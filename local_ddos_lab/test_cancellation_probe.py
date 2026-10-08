import unittest
import contextlib
import io
from unittest.mock import MagicMock, patch

from cancellation_probe import (classify_observation, gateway_snapshot, make_probe_schedule,
                                parse_arguments, send_probe)
from test_event_analysis import lifecycle


def observation_run(cancelled=False, events=None):
    return {'rows': [{'request_id': 'one', 'kind': 'report', 'issued': True, 'business_ok': not cancelled,
                       'deadline_cancelled': cancelled, 'outcome': 'deadline_cancelled' if cancelled else 'ok'}],
            'events': {'run_id': 'one', 'events': lifecycle('one', 'report', 1, 2)
                       if events is None else list(events), 'capacity': 4096},
            'state': {'run_id': 'one'}, 'order_audit_ok': True}


class CancellationProbeTests(unittest.TestCase):
    @patch('cancellation_probe.http.client.HTTPConnection')
    def test_gateway_stats_are_bounded_and_absence_is_not_zero(self, connection):
        self.assertEqual(gateway_snapshot('http://127.0.0.1:8000'), {'applicable': False})
        connection.assert_not_called()
        response = connection.return_value.getresponse.return_value
        response.status = 200
        response.read.return_value = b'{"stats":[]}'
        self.assertTrue(gateway_snapshot('http://127.0.0.1:8080')['captured'])
        self.assertEqual(connection.call_args.args, ('127.0.0.1', 9901))
        response.read.return_value = b'x' * 131073
        self.assertFalse(gateway_snapshot('http://127.0.0.1:8080')['captured'])

    def test_cli_exposes_bounded_workload_and_round_order(self):
        _, args = parse_arguments(['--seconds', '30', '--seed', '123', '--arrival', 'burst',
                                   '--report-rounds', '100', '--mode', 'fixed', '--fixed-limit', '3',
                                   '--round-order', 'cancel-first'])
        self.assertEqual((args.seconds, args.seed, args.arrival, args.report_rounds,
                           args.mode, args.fixed_limit, args.round_order),
                          (30, 123, 'burst', 100, 'fixed', 3, 'cancel-first'))
        for option, value in (('--seconds', '31'), ('--seconds', '2'), ('--report-rounds', '101'),
                              ('--report-rounds', '0'), ('--fixed-limit', '4')):
            with self.subTest(option=option, value=value), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    parse_arguments([option, value])

    def test_bounded_schedule_is_identical_for_both_rounds(self):
        schedule = make_probe_schedule(30, 'report', 'fixed-prefix')
        self.assertEqual(schedule, make_probe_schedule(30, 'report', 'fixed-prefix'))
        self.assertEqual(sum(row['kind'] == 'report' for row in schedule), 60)
        self.assertEqual(sum(row['kind'] == 'orders' for row in schedule), 30)
        self.assertEqual(len({row['request_id'] for row in schedule}), 90)
        self.assertTrue(all(0 <= row['offset_s'] < 30 for row in schedule))

    @patch('cancellation_probe.threading.Timer')
    @patch('cancellation_probe.http.client.HTTPConnection')
    def test_completed_response_does_not_get_labelled_cancelled(self, connection, timer):
        response = connection.return_value.getresponse.return_value
        response.status = 200
        response.read.return_value = b'{"ok":true,"checksum":100}'
        item = make_probe_schedule(3, 'report', 'prefix')[0]
        row = send_probe(item, 0, 'http://127.0.0.1:8080', 50)
        self.assertTrue(row['business_ok'])
        self.assertFalse(row['deadline_cancelled'])
        self.assertTrue(row['completed_before_cancel_deadline'])
        self.assertEqual(connection.call_args.args, ('127.0.0.1', 8080))
        self.assertEqual(connection.return_value.request.call_args.kwargs['headers'],
                          {'X-Lab-Request-ID': item['request_id']})
        timer.return_value.cancel.assert_called_once()

    @patch('cancellation_probe.threading.Timer')
    @patch('cancellation_probe.http.client.HTTPConnection')
    def test_deadline_closes_socket_and_is_not_success(self, connection, timer):
        callbacks = []
        timer.side_effect = lambda seconds, callback: callbacks.append(callback) or MagicMock()
        response = connection.return_value.getresponse.return_value
        response.status = 200

        def deadline_during_read(_):
            callbacks[0]()
            return b'{"ok":true,"checksum":100}'

        response.read.side_effect = deadline_during_read
        item = make_probe_schedule(3, 'report', 'prefix')[0]
        row = send_probe(item, 0, 'http://127.0.0.1:8000', 50)
        self.assertEqual(row['outcome'], 'deadline_cancelled')
        self.assertFalse(row['business_ok'])
        self.assertFalse(row['within_deadline'])
        self.assertFalse(row['completed_before_cancel_deadline'])
        connection.return_value.sock.shutdown.assert_called_once()

    def test_client_cancel_alone_is_not_evidence_of_backend_residual(self):
        result = classify_observation(observation_run(), observation_run(cancelled=True), 'report')
        self.assertEqual(result['status'], 'inconclusive')
        self.assertEqual(result['origin_disconnects'], 0)

    def test_fast_responses_explicitly_do_not_trigger_cancellation(self):
        result = classify_observation(observation_run(), observation_run(), 'report')
        self.assertEqual(result['status'], 'not_observed')
        self.assertIn('not triggered', result['reason'])

    def test_only_matching_disconnect_and_db_finish_prove_observation(self):
        events = lifecycle('one', 'report', 1, 2, disconnected=1.9975)
        events += lifecycle('other', 'report', 1, 2, disconnected=1.97)
        result = classify_observation(observation_run(), observation_run(True, events), 'report')
        self.assertEqual(result['status'], 'inconclusive')
        events = lifecycle('one', 'report', 1, 2, disconnected=1.9975)
        result = classify_observation(observation_run(), observation_run(True, events), 'report')
        self.assertEqual(result['status'], 'observed')
        self.assertEqual(result['max_residual_ms'], 2.5)

    def test_audit_failure_or_drops_make_observation_inconclusive(self):
        for condition in ('audit', 'drops', 'reset'):
            with self.subTest(condition=condition):
                run = observation_run(True)
                if condition == 'audit':
                    run['order_audit_ok'] = False
                elif condition == 'drops':
                    run['rows'][0]['issued'] = False
                else:
                    run['initial_run_id'] = 'different-run'
                result = classify_observation(observation_run(), run, 'report')
                self.assertEqual(result['status'], 'inconclusive')
                self.assertTrue(result['validity_issues'])

    def test_missing_event_timestamp_is_inconclusive_instead_of_crashing(self):
        events = lifecycle('one', 'report', 1, 2, disconnected=1.5)
        del events[1]['elapsed_s']
        result = classify_observation(observation_run(), observation_run(True, events), 'report')
        self.assertEqual(result['status'], 'inconclusive')
        self.assertTrue(result['validity_issues'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
