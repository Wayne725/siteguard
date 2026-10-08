import selectors
import http.client
import shutil
import subprocess
import unittest
from pathlib import Path
from contextlib import contextmanager

from verify import functional_suite, load_run, request
from test_fixture import rejected_then_retried_post


@contextmanager
def owned_node():
    script = Path(__file__).with_name('node_fixture.cjs')
    process = subprocess.Popen(['node', str(script)], stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            ready = selector.select(timeout=5)
            line = process.stdout.readline() if ready else ''
        if 'Owned Node fixture listening on http://127.0.0.1:18101' not in line:
            raise RuntimeError('Owned Node fixture did not bind its dedicated port')
        yield process
    finally:
        process.terminate()
        try:
            _, error = process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            _, error = process.communicate()
        if process.returncode != 0 or error:
            raise RuntimeError(f'Node fixture shutdown was not clean: {error}')


@unittest.skipUnless(shutil.which('node'), 'Node.js is required for the second-stack fixture')
class NodeFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.context = owned_node()
        cls.context.__enter__()
        cls.base_url = 'http://127.0.0.1:18101'

    @classmethod
    def tearDownClass(cls):
        cls.context.__exit__(None, None, None)

    def test_real_node_http_stack_preserves_functional_contract(self):
        result = functional_suite(self.base_url, self.base_url)
        self.assertTrue(result['passed'], [check for check in result['checks'] if check['status'] == 'failed'])
        state = request(self.base_url, 'GET', '/fixture/state')['json']
        self.assertEqual(state['implementation'], 'node')
        self.assertEqual(state['workers'], 4)

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

    def test_real_worker_queue_commits_once_and_detects_duplicate_delivery(self):
        schedule = [{'offset_s': .01, 'kind': 'heavy', 'request_id': 'heavy-one'},
                    {'offset_s': .03, 'kind': 'orders', 'request_id': 'order-one'},
                    {'offset_s': .04, 'kind': 'orders', 'request_id': 'order-one'}]
        result = load_run(self.base_url, self.base_url, schedule)
        self.assertEqual(result['duplicate_post_attempts'], {'order-one': 2})
        self.assertEqual(len(result['origin_state']['orders']), 1)
        self.assertFalse(result['audit_ok'])
        self.assertEqual(result['generator_drops'], 0)
        heavy = next(row for row in result['origin_state']['worker_records'] if row['kind'] == 'heavy')
        self.assertGreaterEqual(heavy['ended_at'] - heavy['started_at'], .35)


@unittest.skipUnless(shutil.which('node'), 'Node.js is required for the second-stack fixture')
class NodeLifecycleTests(unittest.TestCase):
    def test_sigterm_closes_persistent_connections_before_restart(self):
        connection = http.client.HTTPConnection('127.0.0.1', 18101, timeout=2)
        try:
            with owned_node():
                connection.request('GET', '/health')
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                response.read()
                old_socket = connection.sock
            with owned_node():
                try:
                    old_socket.sendall(b'GET /health HTTP/1.1\r\nHost: 127.0.0.1:18101\r\n\r\n')
                    remaining = old_socket.recv(4096)
                except (BrokenPipeError, ConnectionResetError):
                    remaining = b''
                self.assertEqual(remaining, b'')
                fresh = request('http://127.0.0.1:18101', 'POST', '/orders', {'request_id': 'new-node-process'})
                self.assertEqual(fresh['status'], 200)
                self.assertTrue(fresh['json']['persisted'])
        finally:
            connection.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)
