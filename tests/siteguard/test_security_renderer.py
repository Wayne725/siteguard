import unittest

from google.protobuf.json_format import ParseDict
from envoy.config.bootstrap.v3.bootstrap_pb2 import Bootstrap

from siteguard.config import example_config, validate_config
from siteguard.renderer import render_envoy
from siteguard.security import CANONICAL, INSPECTION, RBAC
from tests.siteguard.test_configuration import register_types


def render_security(mode='enforce', general_security=True, nested=False):
    raw = example_config()
    raw.update(mode=mode, routes=[
        {'name': 'api', 'prefix': '/api', 'response_guard': True, 'max_body_bytes': 4096},
        {'name': 'events', 'prefix': '/events', 'streaming': True},
    ])
    if nested:
        raw['routes'].append({'name': 'private_api', 'prefix': '/api/private',
                              'response_guard': True, 'max_body_bytes': 1024})
    if not general_security:
        raw['security'] = {'block_sensitive_paths': False, 'blocked_methods': [],
                           'protected_paths': [], 'response_headers': False}
    rendered = render_envoy(validate_config(raw))
    hcm = rendered['static_resources']['listeners'][0]['filter_chains'][0]['filters'][-1]['typed_config']
    return rendered, hcm


class SecurityRendererTests(unittest.TestCase):
    def test_guard_variants_parse_official_envoy_protobuf(self):
        for mode in ('observe', 'enforce'):
            for general_security in (False, True):
                for nested in (False, True):
                    with self.subTest(mode=mode, general_security=general_security, nested=nested):
                        rendered, _ = render_security(mode, general_security, nested)
                        register_types(rendered)
                        ParseDict(rendered, Bootstrap())

    def test_guard_retains_alias_protection_when_general_security_is_disabled(self):
        _, hcm = render_security(general_security=False, nested=True)
        filters = {item['name']: item['typed_config'] for item in hcm['http_filters']}
        self.assertIn(CANONICAL, filters)
        self.assertIn(RBAC, filters)
        self.assertEqual(filters[RBAC]['rules']['action'], 'DENY')
        self.assertNotIn('shadow_rules', filters[RBAC])
        upgrade_filters = {item['name'] for item in hcm['upgrade_configs'][0]['filters']}
        self.assertTrue({CANONICAL, RBAC} <= upgrade_filters)

    def test_observe_is_shadow_only_and_never_enables_response_inspection(self):
        _, hcm = render_security('observe', general_security=False, nested=True)
        filters = {item['name']: item['typed_config'] for item in hcm['http_filters']}
        self.assertIn('shadow_rules', filters[RBAC])
        self.assertNotIn('rules', filters[RBAC])
        self.assertEqual(filters[INSPECTION]['processing_mode']['response_body_mode'], 'NONE')
        self.assertEqual(filters[INSPECTION]['processing_mode']['response_header_mode'], 'SKIP')
        for route in hcm['route_config']['virtual_hosts'][0]['routes']:
            self.assertTrue(route['typed_per_filter_config'][INSPECTION]['disabled'])

    def test_only_guard_routes_send_explicit_shared_caps_to_scanner(self):
        _, hcm = render_security(nested=True)
        routes = {route['name']: route for route in hcm['route_config']['virtual_hosts'][0]['routes']}
        for name, expected in (('api', 4096), ('private_api', 1024)):
            with self.subTest(route=name):
                per_filter = routes[name]['typed_per_filter_config']
                inspection = per_filter[INSPECTION]['overrides']
                metadata = {item['key']: item['value'] for item in inspection['grpc_initial_metadata']}
                self.assertEqual(metadata['x-siteguard-max-bytes'], str(expected))
                self.assertEqual(per_filter['envoy.filters.http.buffer']['buffer']['max_request_bytes'], expected)
                self.assertEqual(inspection['processing_mode']['response_body_mode'], 'BUFFERED')
        for name in ('default', 'events'):
            self.assertTrue(routes[name]['typed_per_filter_config'][INSPECTION]['disabled'])


if __name__ == '__main__':
    unittest.main()
