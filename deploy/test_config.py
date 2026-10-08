from pathlib import Path
import unittest

import yaml

from deploy.render_envoy import MODES, build_config
from deploy.validate_config import validate


ROOT = Path(__file__).resolve().parents[1]


def manager(config: dict) -> dict:
    return config['static_resources']['listeners'][0]['filter_chains'][0]['filters'][0]['typed_config']


def match_route(config: dict, path: str) -> dict:
    routes = manager(config)['route_config']['virtual_hosts'][0]['routes']
    for route in routes:
        match = route['match']
        if match.get('path') == path or ('prefix' in match and path.startswith(match['prefix'])):
            return route
    raise AssertionError(f'no route for {path}')


class GatewayConfigTests(unittest.TestCase):
    def test_configs_parse_with_official_protobuf_types(self):
        for mode in MODES:
            with self.subTest(mode=mode):
                validate(ROOT / 'deploy' / 'envoy' / f'{mode}.yaml')

    def test_generated_configs_match_checked_in_files(self):
        for mode in MODES:
            path = ROOT / 'deploy' / 'envoy' / f'{mode}.yaml'
            with self.subTest(mode=mode):
                self.assertEqual(yaml.safe_load(path.read_text()), build_config(mode))

    def test_management_paths_never_route_to_backend(self):
        for mode in MODES:
            config = build_config(mode)
            for path in ('/lab/state', '/lab/reset', '/lab/audit', '/lab/metadata',
                         '/metrics', '/stats', '/config_dump', '/quitquitquit', '/api/lab/reset'):
                with self.subTest(mode=mode, path=path):
                    self.assertEqual(match_route(config, path)['direct_response']['status'], 404)
            self.assertIn('x-lab-admin', manager(config)['route_config']['request_headers_to_remove'])

    def test_api_routes_have_fixed_descriptors_and_no_retries(self):
        for mode in MODES:
            config = build_config(mode)
            for path, kind in (('/api/products', 'products'), ('/api/orders', 'orders'),
                               ('/api/report', 'report')):
                route = match_route(config, path)['route']
                self.assertEqual(route['cluster'], 'app')
                self.assertNotIn('retry_policy', route)
                if mode.startswith('rls'):
                    self.assertEqual(route['rate_limits'][0]['actions'], [{'generic_key': {
                        'descriptor_key': 'kind', 'descriptor_value': kind,
                    }}])
                else:
                    self.assertNotIn('rate_limits', route)

    def test_health_check_bypasses_adaptive_sampling_and_rls(self):
        for mode in MODES:
            config = build_config(mode)
            filters = manager(config)['http_filters']
            self.assertEqual(filters[0]['name'], 'envoy.filters.http.health_check')
            self.assertTrue(filters[0]['typed_config']['pass_through_mode'])
            self.assertNotIn('rate_limits', match_route(config, '/health')['route'])
            self.assertNotIn('rate_limits', match_route(config, '/live')['route'])
            self.assertEqual(filters[0]['typed_config']['headers'][0]['string_match'],
                             {'safe_regex': {'regex': '^/(health|live)$'}})

    def test_ui_and_gateway_mode_are_exposed_without_management_routes(self):
        for mode in MODES:
            config = build_config(mode)
            self.assertEqual(match_route(config, '/ui.js')['route']['cluster'], 'app')
            self.assertEqual(manager(config)['route_config']['response_headers_to_add'], [{
                'header': {'key': 'X-Lab-Gateway-Mode', 'value': mode},
                'append_action': 'OVERWRITE_IF_EXISTS_OR_ADD',
            }])
            self.assertNotIn('rate_limits', match_route(config, '/ui.js')['route'])

    def test_combined_mode_and_fail_closed_are_explicit(self):
        for mode in MODES:
            filters = manager(build_config(mode))['http_filters']
            names = [item['name'] for item in filters]
            self.assertEqual('envoy.filters.http.adaptive_concurrency' in names,
                             mode in ('adaptive', 'rls_adaptive'))
            self.assertEqual('envoy.filters.http.ratelimit' in names, mode.startswith('rls'))
            if mode.startswith('rls'):
                rls = next(item['typed_config'] for item in filters if item['name'].endswith('.ratelimit'))
                self.assertTrue(rls['failure_mode_deny'])
                self.assertEqual(rls['domain'], 'local-ddos-lab')
                self.assertEqual(rls['status_on_error']['code'], 'ServiceUnavailable')
            if mode == 'rls_adaptive':
                self.assertLess(names.index('envoy.filters.http.ratelimit'),
                                names.index('envoy.filters.http.adaptive_concurrency'))

    def test_native_target_uses_loopback_when_requested(self):
        config = build_config('rls', '127.0.0.1', '127.0.0.1', '127.0.0.1', '127.0.0.1')
        self.assertEqual(config['admin']['address']['socket_address']['address'], '127.0.0.1')
        for item in config['static_resources']['clusters']:
            address = item['load_assignment']['endpoints'][0]['lb_endpoints'][0]['endpoint']['address']
            self.assertEqual(address['socket_address']['address'], '127.0.0.1')

    def test_compose_limits_and_ports(self):
        compose = yaml.safe_load((ROOT / 'compose.yaml').read_text())
        services = compose['services']
        self.assertRegex(services['postgres']['image'], r'^postgres:17-alpine@sha256:[0-9a-f]{64}$')
        self.assertNotIn('ports', services['postgres'])
        self.assertNotIn('ports', services['rls'])
        self.assertTrue(compose['networks']['lab']['internal'])
        self.assertFalse(compose['networks']['edge'].get('internal', False))
        self.assertEqual(services['postgres']['networks'], ['lab'])
        self.assertEqual(services['rls']['networks'], ['lab'])
        for name in ('app', 'envoy'):
            self.assertIn('edge', services[name]['networks'])
        for name, service in services.items():
            with self.subTest(service=name):
                self.assertGreater(service['cpus'], 0)
                self.assertTrue(service['mem_limit'])
                self.assertTrue(service['healthcheck'])
                for port in service.get('ports', []):
                    self.assertTrue(port.startswith('127.0.0.1:'))


if __name__ == '__main__':
    unittest.main()
