"""Routing, audit and report checks that do not start a load generator."""
import argparse
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from experiment import call, issue, local_base_url, reconcile_orders, summarize
from summarize_results import audit_result, load_runs, render_report


def request_row(request_id='one', product_id=1, **changes):
    return dict(request_id=request_id, product_id=product_id, kind='orders', label='normal',
                phase='load', issued=True, business_ok=True, within_deadline=True,
                status=200, latency_ms=10, outcome='ok') | changes


def audit_payload(*orders):
    return {
        'committed_order_ids': [order['request_id'] for order in orders],
        'committed_orders': [{'request_id': order['request_id'], 'product_id': order['product_id']}
                             for order in orders],
        'stock_used': len(orders),
        'products': [{'id': i, 'stock': 100000 - sum(order['product_id'] == i for order in orders),
                      'orders_count': sum(order['product_id'] == i for order in orders)}
                     for i in range(1, 21)],
    }


class TargetRoutingTests(unittest.TestCase):
    def test_only_exact_loopback_targets_allowed(self):
        self.assertEqual(local_base_url('http://127.0.0.1:8080/'), 'http://127.0.0.1:8080')
        for target in ('https://127.0.0.1:8080', 'http://localhost:8000', 'http://127.0.0.1:8001',
                       'http://127.0.0.1:8000/path', 'http://127.0.0.1:8000?x=1',
                       'http://127.0.0.1:8000@external.example', 'http://192.168.1.1:8000'):
            with self.subTest(target=target), self.assertRaises(argparse.ArgumentTypeError):
                local_base_url(target)

    @patch('experiment.http.client.HTTPConnection')
    def test_business_uses_proxy_and_management_stays_on_origin(self, connection):
        response = MagicMock(status=200)
        response.read.return_value = b'{"ok":true}'
        response.getheaders.return_value = []
        connection.return_value.getresponse.return_value = response
        call('GET', '/api/products', base_url='http://127.0.0.1:8080')
        self.assertEqual(connection.call_args.args, ('127.0.0.1', 8080))
        self.assertNotIn('X-Lab-Admin', connection.return_value.request.call_args.kwargs['headers'])
        call('GET', '/lab/state', token='secret', base_url='http://127.0.0.1:8080')
        self.assertEqual(connection.call_args.args, ('127.0.0.1', 8000))
        self.assertEqual(connection.return_value.request.call_args.kwargs['headers']['X-Lab-Admin'], 'secret')

    def test_admin_token_cannot_be_sent_to_business_route(self):
        with self.assertRaises(ValueError):
            call('GET', '/api/products', token='secret', base_url='http://127.0.0.1:8080')

    @patch('experiment.call')
    def test_get_probe_passes_opaque_id_without_ground_truth_labels(self, mocked_call):
        mocked_call.return_value = (429, {'reason': 'report_concurrency_budget'}, {})
        row = request_row('abcdef0123456789abcdef01', kind='report', offset_s=0, label='pressure')
        result = issue(row, 0)
        self.assertEqual(mocked_call.call_args.kwargs['request_id'], row['request_id'])
        self.assertNotIn('pressure', str(mocked_call.call_args))
        self.assertEqual(result['rejection_reason'], 'report_concurrency_budget')


class OrderAuditTests(unittest.TestCase):
    def test_valid_order_passes_and_unacknowledged_commit_is_preserved(self):
        acknowledged = request_row()
        timed_out = request_row('two', 2, business_ok=False, within_deadline=False,
                                outcome='client_timeout', status=0)
        audit = audit_payload(acknowledged, timed_out)
        self.assertTrue(reconcile_orders([acknowledged, timed_out], audit))
        self.assertEqual(audit['committed_without_successful_ack'], ['two'])
        self.assertEqual(summarize([acknowledged, timed_out])['normal_orders_load_phase']['completion_rate'], .5)

    def test_acknowledged_missing_order_is_not_counted_as_completed(self):
        rows = [request_row()]
        audit = audit_payload()
        self.assertFalse(reconcile_orders(rows, audit))
        self.assertEqual(audit['acknowledged_missing_in_db'], ['one'])
        self.assertEqual(summarize(rows)['normal_orders_load_phase']['success_within_deadline'], 0)
        self.assertEqual(rows[0]['outcome'], 'audit_failed')

    def test_wrong_product_and_balanced_stock_errors_are_detected(self):
        row = request_row()
        wrong_product = audit_payload(request_row(product_id=2))
        self.assertFalse(reconcile_orders([row], wrong_product))
        self.assertFalse(row['within_deadline'])
        correct = audit_payload(request_row())
        correct['products'][0]['stock'] += 1
        correct['products'][1]['stock'] -= 1
        self.assertFalse(reconcile_orders([request_row()], correct))
        self.assertTrue(correct['stock_matches_orders'])
        self.assertFalse(correct['per_product_stock_matches_orders'])

    def test_legacy_or_unissued_commit_cannot_pass_new_audit(self):
        legacy = {'committed_order_ids': ['one'], 'stock_used': 1}
        self.assertFalse(reconcile_orders([request_row()], legacy))
        self.assertFalse(legacy['detailed_audit_available'])
        dropped = request_row(issued=False, business_ok=False, within_deadline=False,
                              outcome='generator_drop', status=0, latency_ms=None)
        audit = audit_payload(dropped)
        self.assertFalse(reconcile_orders([dropped], audit))
        self.assertEqual(audit['unissued_but_committed_order_ids'], ['one'])

    def test_drops_stay_in_denominator_and_reports_have_completion_rate(self):
        rows = [request_row(), request_row('drop', issued=False, business_ok=False,
                                          within_deadline=False, status=0, latency_ms=None,
                                          outcome='generator_drop'),
                request_row('report', kind='report', latency_ms=1200, within_deadline=False)]
        result = summarize(rows)
        self.assertEqual(result['normal_orders_load_phase']['planned'], 2)
        self.assertEqual(result['normal_orders_load_phase']['completion_rate'], .5)
        self.assertEqual(result['all']['generator_drops'], 1)
        self.assertEqual(result['normal_reports_load_phase']['business_completion_rate'], 1)
        self.assertEqual(result['normal_reports_load_phase']['completion_rate'], 0)


class ReportTests(unittest.TestCase):
    def test_offline_report_preserves_legacy_scope_and_escapes_labels(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            metadata = {'mode': 'off', 'scenario': 'mixed', 'seed': 42,
                        'label': '<script>alert(1)</script>', 'seconds': 6}
            summary = summarize([request_row()])
            del summary['normal_reports_load_phase']
            summary['order_audit_ok'] = True
            for name, payload in [('metadata.json', metadata), ('summary.json', summary),
                                  ('schedule.json', []),
                                  ('order_audit.json', {'stock_matches_orders': True})]:
                (directory / name).write_text(json.dumps(payload), encoding='utf-8')
            (directory / 'requests.csv').write_text('request_id\none\n', encoding='utf-8')
            runs = load_runs(directory)
            document = render_report(runs, directory / 'comparison.html')
            self.assertEqual(audit_result(runs[0])[0], 'warn')
            self.assertIn('舊格式：僅 ID／總庫存', document)
            self.assertIn('&lt;script&gt;', document)
            self.assertNotIn('<script>', document)
            self.assertIn('無樣本', document)
            self.assertIn('requests.csv', document)
            self.assertTrue(runs[0]['schedule_hash_ok'])

    def test_different_workload_or_modified_schedule_is_flagged(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for rounds in (1, 10):
                target = directory / str(rounds)
                target.mkdir()
                metadata = {'report_rounds': rounds, 'scenario': 'mixed', 'seed': 42,
                            'schedule_sha256': 'not-the-recorded-schedule'}
                for name, payload in [('metadata.json', metadata), ('schedule.json', []),
                                      ('summary.json', summarize([request_row()]))]:
                    (target / name).write_text(json.dumps(payload), encoding='utf-8')
            runs = load_runs(directory)
            self.assertNotEqual(runs[0]['condition_id'], runs[1]['condition_id'])
            self.assertFalse(runs[0]['schedule_hash_ok'])
            self.assertEqual(audit_result(runs[0]), ('bad', '缺少稽核'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
