import copy
import importlib
import tempfile
import unittest
from pathlib import Path

from google.protobuf.json_format import ParseDict
from envoy.config.bootstrap.v3.bootstrap_pb2 import Bootstrap

from siteguard.config import ConfigError, example_config, load_config, validate_config
from siteguard.renderer import render_envoy


def register_types(value):
    if isinstance(value, dict):
        if '@type' in value:
            qualified = value['@type'].split('/')[-1]
            namespace, name = qualified.rsplit('.', 1)
            special = {'HttpConnectionManager': 'http_connection_manager', 'HttpProtocolOptions': 'http_protocol_options',
                       'ConnectionLimit': 'connection_limit', 'RateLimit': 'rate_limit',
                       'FixedHeapConfig': 'fixed_heap', 'StdoutAccessLog': 'stream',
                       'BufferPerRoute': 'buffer', 'LuaPerRoute': 'lua',
                       'ExternalProcessor': 'ext_proc', 'ExtProcPerRoute': 'ext_proc',
                       'UpstreamTlsContext': 'tls', 'DownstreamTlsContext': 'tls',
                       'HeaderMutation': 'header_mutation', 'XffConfig': 'xff'}
            importlib.import_module(f'{namespace}.{special.get(name, name.lower())}_pb2')
        for item in value.values():
            register_types(item)
    elif isinstance(value, list):
        for item in value:
            register_types(item)


class ConfigurationTests(unittest.TestCase):
    def test_default_and_feature_variants_parse_official_protobuf(self):
        raw = example_config()
        for mode, protocol, scheme in [('observe', 'http1', 'http'), ('enforce', 'http2', 'http'),
                                       ('enforce', 'auto', 'https')]:
            with self.subTest(mode=mode, protocol=protocol):
                raw.update(mode=mode, trusted_proxy_cidrs=['10.42.0.0/24'], routes=[
                    {'name': 'heavy', 'prefix': '/heavy', 'max_concurrent': 2, 'rate_per_second': 4, 'burst': 4},
                    {'name': 'stream', 'prefix': '/stream', 'streaming': True},
                ])
                raw['upstream'] = {'url': f'{scheme}://example.com', 'protocol': protocol}
                rendered = render_envoy(validate_config(raw))
                register_types(rendered)
                ParseDict(rendered, Bootstrap())

    def test_typos_invalid_numbers_and_insecure_url_fail_before_docker(self):
        mutations = [
            lambda c: c.update(mdoe='enforce'),
            lambda c: c['policy'].update(max_concurrent=True),
            lambda c: c['policy'].update(queue_size=-1),
            lambda c: c['policy'].update(request_timeout_seconds=float('nan')),
            lambda c: c['upstream'].update(url='https://name:secret@example.com'),
            lambda c: c['upstream'].update(url='http://example.com/path'),
            lambda c: c['upstream'].update(url='http://example.com:70000'),
            lambda c: c['upstream'].update(protocol='auto'),
            lambda c: c.update(trusted_proxy_cidrs=['0.0.0.0/0']),
            lambda c: c.update(trusted_proxy_hops=1),
        ]
        for mutation in mutations:
            config = example_config()
            mutation(config)
            with self.subTest(config=config), self.assertRaises(ConfigError):
                validate_config(config)

    def test_reservations_cannot_consume_default_pool_or_alias_paths(self):
        for routes in ([{'name': 'default', 'prefix': '/x'}],
                       [{'name': 'all', 'prefix': '/x', 'max_concurrent': 64}],
                       [{'name': 'encoded', 'prefix': '/x%2Fy'}],
                       [{'name': 'a', 'prefix': '/same'}, {'name': 'b', 'prefix': '/same/'}]):
            with self.subTest(routes=routes), self.assertRaises(ConfigError):
                validate_config({**example_config(), 'routes': routes})

    def test_rules_sort_by_specificity_without_mutating_input(self):
        raw = {**example_config(), 'routes': [{'name': 'api', 'prefix': '/api/'},
                                             {'name': 'report', 'prefix': '/api/report'}]}
        before = copy.deepcopy(raw)
        result = validate_config(raw)
        self.assertEqual(raw, before)
        self.assertEqual([r['name'] for r in result['routes']], ['report', 'api'])

    def test_tls_paths_relative_to_configuration_and_never_inline_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'certificate.pem').write_text('public-cert')
            (root / 'key.pem').write_text('private-key-content')
            (root / 'siteguard.yaml').write_text('version: 1\nlistener:\n  tls:\n    certificate: certificate.pem\n    private_key: key.pem\n')
            config = load_config(root / 'siteguard.yaml')
            rendered = render_envoy(config)
            register_types(rendered)
            ParseDict(rendered, Bootstrap())
            self.assertEqual(config['listener']['tls']['private_key'], str((root / 'key.pem').resolve()))
            self.assertNotIn('private-key-content', str(rendered))

    def test_observe_keeps_would_limit_signals_without_enforcement(self):
        rendered = render_envoy(validate_config(example_config()))
        hcm = rendered['static_resources']['listeners'][0]['filter_chains'][0]['filters'][-1]['typed_config']
        rate = next(f['typed_config'] for f in hcm['http_filters'] if f['name'].endswith('.ratelimit'))
        self.assertEqual(rate['filter_enabled']['default_value']['numerator'], 100)
        self.assertEqual(rate['filter_enforced']['default_value']['numerator'], 0)
        self.assertFalse(rate['failure_mode_deny'])

    def test_duplicate_yaml_policy_fields_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'siteguard.yaml'
            path.write_text('mode: enforce\nmode: observe\n')
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_private_admin_streaming_and_logs_do_not_expose_sensitive_data(self):
        raw = {**example_config(), 'mode': 'enforce', 'routes': [
            {'name': 'events', 'prefix': '/events', 'streaming': True}]}
        rendered = render_envoy(validate_config(raw))
        self.assertEqual(rendered['admin']['address']['socket_address']['address'], '127.0.0.1')
        hcm = rendered['static_resources']['listeners'][0]['filter_chains'][0]['filters'][-1]['typed_config']
        routes = hcm['route_config']['virtual_hosts'][0]['routes']
        stream = next(r for r in routes if r['name'] == 'events')
        self.assertEqual(stream['route']['timeout'], '0s')
        self.assertTrue(stream['typed_per_filter_config']['envoy.filters.http.buffer']['disabled'])
        self.assertTrue(stream['route']['upgrade_configs'][0]['enabled'])
        default = next(r for r in routes if r['name'] == 'default')
        self.assertFalse(default['route']['upgrade_configs'][0]['enabled'])
        self.assertEqual(default['route']['max_stream_duration']['max_stream_duration'], '30s')
        self.assertNotIn('%REQ(:PATH)%', str(hcm['access_log']))
        self.assertNotIn('AUTHORIZATION', str(hcm['access_log']).upper())
        self.assertNotIn('retry_policy', str(rendered))


if __name__ == '__main__':
    unittest.main()
