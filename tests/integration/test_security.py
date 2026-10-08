import unittest
from unittest.mock import patch

from fixture import running_fixture
from verify import request
from verify_security import security_suite


class GatewaySecurityVerifierTests(unittest.TestCase):
    def test_unprotected_real_origin_is_a_negative_control(self):
        with running_fixture(18101):
            result = security_suite('http://127.0.0.1:18101')
            checks = {check['name']: check for check in result['checks']}
            self.assertFalse(result['passed'])
            self.assertEqual(checks['incoming_envoy_control_headers_removed']['status'], 'failed')
            self.assertIn('X-Envoy-Arbitrary-Fixture-Control',
                          checks['incoming_envoy_control_headers_removed']['leaked_control_headers'])
            self.assertEqual(checks['untrusted_forwarded_identity_replaced']['status'], 'failed')
            self.assertEqual(checks['upgrade_cannot_bypass_body_limit']['status'], 'skipped')
            state = request('http://127.0.0.1:18101', 'GET', '/fixture/state')['json']
            self.assertEqual(state['post_attempts'], {})
            self.assertEqual(state['orders'], {})

    @patch('verify_security.request')
    def test_profile_bounds_are_checked_before_any_request(self, mocked):
        for options in ({'body_limit_bytes': 0}, {'body_limit_bytes': 131073},
                         {'timeout_seconds': .5}, {'timeout_seconds': 2}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                security_suite('http://127.0.0.1:18088', **options)
        mocked.assert_not_called()

    @patch('verify_security.request')
    def test_upgrade_rejection_does_not_hide_missing_normal_body_limit(self, mocked):
        mocked.side_effect = [
            {'status': 200, 'json': {'forwarded_headers': {}, 'x_test': 'ordinary-header-retained'}},
            {'status': 200, 'json': {'forwarded_headers': {'x-forwarded-proto': 'http'}}},
            {'status': 200}, {'status': 403},
        ]
        result = security_suite('http://127.0.0.1:18088', body_limit_bytes=1024)
        body_check = next(check for check in result['checks'] if check['name'] == 'upgrade_cannot_bypass_body_limit')
        self.assertEqual(body_check['status'], 'failed')
        self.assertEqual(len(body_check['requests']), 2)
        self.assertFalse(result['passed'])

    @patch('verify_security.request')
    def test_timeout_status_alone_does_not_hide_late_response(self, mocked):
        mocked.side_effect = [
            {'status': 200, 'json': {'forwarded_headers': {}, 'x_test': 'ordinary-header-retained'}},
            {'status': 200, 'json': {'forwarded_headers': {'x-forwarded-proto': 'http'}}},
            {'status': 504, 'elapsed_ms': 1500}, {'status': 403, 'elapsed_ms': 10},
            {'status': 504, 'elapsed_ms': 1000},
        ]
        result = security_suite('http://127.0.0.1:18088', timeout_seconds=1)
        timeout_check = next(check for check in result['checks']
                             if check['name'] == 'upgrade_and_control_headers_cannot_bypass_timeout')
        self.assertEqual(timeout_check['status'], 'failed')
        self.assertEqual(len(timeout_check['requests']), 3)


if __name__ == '__main__':
    unittest.main(verbosity=2)
