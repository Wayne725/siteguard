import argparse
import http.client
import time
import unittest
from unittest.mock import Mock
from concurrent.futures import ThreadPoolExecutor

from fixture import OwnedFixture, running_fixture
from verify import functional_suite, load_run, local_url, make_load_schedule, request


def rejected_then_retried_post(base_url):
    if request(base_url, 'POST', '/fixture/reset', {})['status'] != 200:
        raise AssertionError('Fixture reset failed')
    with ThreadPoolExecutor(max_workers=24) as pool:
        heavy = [pool.submit(request, base_url, 'GET', '/heavy') for _ in range(24)]
        for _ in range(100):
            if request(base_url, 'GET', '/fixture/state')['json']['outstanding'] == 24:
                break
            time.sleep(.005)
        else:
            raise AssertionError('Real fixture work did not reach its admission capacity')
        rejected = request(base_url, 'POST', '/orders', {'request_id': 'rejected-then-retried'})
        received_while_rejected = request(base_url, 'GET', '/fixture/state')['json']
        heavy_results = [future.result() for future in heavy]
    retried = request(base_url, 'POST', '/orders', {'request_id': 'rejected-then-retried'})
    return rejected, received_while_rejected, retried, request(base_url, 'GET', '/fixture/state')['json'], heavy_results


class LocalBoundsTests(unittest.TestCase):
    def test_stop_drains_active_handler_before_worker_pool_shutdown(self):
        with OwnedFixture(18101) as fixture:
            old_server = fixture.server
            old_server.handle_error = Mock()
            connection = http.client.HTTPConnection('127.0.0.1', 18101, timeout=2)
            try:
                connection.request('GET', '/heavy')
                for _ in range(50):
                    if old_server.fixture_state.snapshot()['outstanding']:
                        break
                    time.sleep(.01)
                else:
                    self.fail('Heavy request did not enter the owned worker pool')
                fixture.stop()
                self.assertEqual(old_server.fixture_state.snapshot()['outstanding'], 0)
                self.assertEqual(old_server.connections, set())
                self.assertTrue(all(not thread.is_alive() for thread in old_server.fixture_state.pool._threads))
                old_server.handle_error.assert_not_called()
            finally:
                connection.close()

    def test_persistent_connection_is_closed_before_origin_restart(self):
        with OwnedFixture(18101) as fixture:
            connection = http.client.HTTPConnection('127.0.0.1', 18101, timeout=2)
            try:
                connection.request('GET', '/health')
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                response.read()
                old_socket = connection.sock
                fixture.stop()
                fixture.start()
                try:
                    old_socket.sendall(b'GET /health HTTP/1.1\r\nHost: 127.0.0.1:18101\r\n\r\n')
                    remaining = old_socket.recv(4096)
                except (BrokenPipeError, ConnectionResetError):
                    remaining = b''
                self.assertEqual(remaining, b'', 'An old keepalive connection still served the stopped origin')
                fresh = request('http://127.0.0.1:18101', 'POST', '/orders', {'request_id': 'after-restart'})
                self.assertEqual(fresh['status'], 200)
                self.assertTrue(fresh['json']['persisted'])
            finally:
                connection.close()

    def test_owned_listener_can_stop_and_recover_without_other_services(self):
        with OwnedFixture(18101) as fixture:
            self.assertEqual(request('http://127.0.0.1:18101', 'GET', '/health')['status'], 200)
            fixture.stop()
            self.assertEqual(request('http://127.0.0.1:18101', 'GET', '/health')['status'], 0)
            fixture.start()
            self.assertEqual(request('http://127.0.0.1:18101', 'GET', '/health')['status'], 200)

    def test_only_dedicated_loopback_ports_are_permitted(self):
        self.assertEqual(local_url('http://127.0.0.1:18088/'), 'http://127.0.0.1:18088')
        for target in ('http://localhost:18088', 'http://127.0.0.1:8000', 'http://127.0.0.1:8080',
                       'https://127.0.0.1:18088', 'http://127.0.0.1:18088/path',
                       'http://127.0.0.1:18088@external.example', 'http://192.168.1.1:18088'):
            with self.subTest(target=target), self.assertRaises(argparse.ArgumentTypeError):
                local_url(target)

    def test_schedule_is_replayable_and_bounded(self):
        schedule = make_load_schedule(10, 42)
        self.assertEqual(schedule, make_load_schedule(10, 42))
        self.assertNotEqual(schedule, make_load_schedule(10, 43))
        self.assertEqual(len(schedule), 200)
        self.assertEqual(sum(row['kind'] == 'orders' for row in schedule), 40)
        self.assertEqual(len({row['request_id'] for row in schedule}), 200)
        self.assertTrue(all(0 <= row['offset_s'] < 10 for row in schedule))
        for seconds in (2, 11):
            with self.assertRaises(ValueError):
                make_load_schedule(seconds)


class OwnedFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.context = running_fixture(18101)
        cls.server = cls.context.__enter__()
        cls.base_url = 'http://127.0.0.1:18101'

    @classmethod
    def tearDownClass(cls):
        cls.context.__exit__(None, None, None)

    def test_http_compatibility_checks_against_real_fixture(self):
        result = functional_suite(self.base_url, self.base_url)
        failures = [check for check in result['checks'] if check['status'] == 'failed']
        self.assertTrue(result['passed'], failures)
        checks = {check['name']: check for check in result['checks']}
        self.assertEqual(checks['multipart_upload_64k']['status'], 'passed')
        self.assertGreater(checks['multipart_upload_64k']['request']['request_body_bytes'], 16384)
        self.assertEqual(checks['sse_first_chunk']['status'], 'passed')
        self.assertEqual(checks['websocket_bidirectional_close']['frames'][-1]['received_opcode'], 8)
        self.assertEqual(checks['http2_prior_knowledge']['status'], 'skipped')
        self.assertEqual(checks['origin_503_recovery']['status'], 'passed')

    def test_load_audit_detects_replayed_post_even_with_idempotent_storage(self):
        schedule = [{'offset_s': .01, 'kind': 'orders', 'request_id': 'intent-one'},
                    {'offset_s': .03, 'kind': 'orders', 'request_id': 'intent-one'}]
        result = load_run(self.base_url, self.base_url, schedule)
        self.assertEqual(result['origin_state']['orders'], {'intent-one': {'order_id': 'intent-one', 'quantity': 1}})
        self.assertEqual(result['duplicate_post_attempts'], {'intent-one': 2})
        self.assertFalse(result['audit_ok'])
        self.assertEqual(result['generator_drops'], 0)

    def test_reset_never_replays_or_creates_orders(self):
        result = request(self.base_url, 'POST', '/fixture/reset', {})
        self.assertEqual(result['status'], 200)
        self.assertEqual(request(self.base_url, 'GET', '/fixture/state')['json']['orders'], {})

    def test_capacity_rejection_is_counted_before_execution_or_commit(self):
        rejected, first_state, retried, final_state, heavy = rejected_then_retried_post(self.base_url)
        self.assertEqual(rejected['status'], 503)
        self.assertEqual(first_state['post_attempts'], {'rejected-then-retried': 1})
        self.assertEqual(first_state['post_executions'], {})
        self.assertEqual(first_state['orders'], {})
        self.assertTrue(all(row['status'] == 200 for row in heavy))
        self.assertEqual(retried['status'], 200)
        self.assertEqual(final_state['post_attempts'], {'rejected-then-retried': 2})
        self.assertEqual(final_state['post_executions'], {'rejected-then-retried': 1})
        self.assertEqual(len(final_state['orders']), 1)


if __name__ == '__main__':
    unittest.main(verbosity=2)
