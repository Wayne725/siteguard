import unittest

from envoy.config.bootstrap.v3.bootstrap_pb2 import Bootstrap
from google.protobuf.json_format import ParseDict

from siteguard.config import example_config, validate_config
from siteguard.renderer import render_envoy
from siteguard.security import RBAC, CANONICAL
from tests.siteguard.test_configuration import register_types


def render(firewall, mode='enforce'):
    raw = example_config()
    raw.update(mode=mode, firewall=firewall, security={
        'block_sensitive_paths': False, 'blocked_methods': [], 'protected_paths': [], 'response_headers': False},
        routes=[{'name': 'ws', 'prefix': '/ws', 'streaming': True}])
    result = render_envoy(validate_config(raw))
    hcm = result['static_resources']['listeners'][0]['filter_chains'][0]['filters'][-1]['typed_config']
    return result, hcm


class FirewallRendererTests(unittest.TestCase):
    def test_ipv4_ipv6_empty_and_combined_policies_parse_official_protobuf(self):
        for mode in ('observe', 'enforce'):
            for firewall in ({}, {'deny_cidrs': ['203.0.113.8', '2001:db8::/32']},
                             {'default_action': 'deny'},
                             {'default_action': 'deny', 'allow_cidrs': ['0.0.0.0/0', '::/0'],
                              'deny_cidrs': ['203.0.113.8', '2001:db8::8']}):
                with self.subTest(mode=mode, firewall=firewall):
                    result, _ = render(firewall, mode)
                    register_types(result)
                    ParseDict(result, Bootstrap())

    def test_firewall_remains_active_without_path_rules_and_cannot_be_overridden_by_routes(self):
        _, hcm = render({'default_action': 'deny', 'allow_cidrs': ['203.0.113.0/24'],
                         'deny_cidrs': ['203.0.113.8']})
        filters = {f['name']: f['typed_config'] for f in hcm['http_filters']}
        self.assertIn(RBAC, filters)
        self.assertNotIn(CANONICAL, filters)
        rules = filters[RBAC]['rules']
        self.assertEqual(rules['action'], 'DENY')
        self.assertEqual(set(rules['policies']), {'firewall_default_deny', 'firewall_denied_source'})
        for route in hcm['route_config']['virtual_hosts'][0]['routes']:
            self.assertNotIn(RBAC, route['typed_per_filter_config'])
        upgrade = next(f for f in hcm['upgrade_configs'][0]['filters'] if f['name'] == RBAC)
        self.assertEqual(upgrade['typed_config']['rules'], rules)

    def test_observe_retains_shadow_rules_without_enforcement(self):
        _, hcm = render({'default_action': 'deny'}, 'observe')
        rbac = next(f['typed_config'] for f in hcm['http_filters'] if f['name'] == RBAC)
        self.assertNotIn('rules', rbac)
        self.assertEqual(rbac['shadow_rules']['policies']['firewall_default_deny']['principals'], [{'any': True}])

    def test_empty_default_allow_adds_no_filters_when_other_security_is_off(self):
        _, hcm = render({})
        self.assertNotIn(RBAC, {f['name'] for f in hcm['http_filters']})
        self.assertNotIn(CANONICAL, {f['name'] for f in hcm['http_filters']})


if __name__ == '__main__':
    unittest.main()
