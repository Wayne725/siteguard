import copy
import unittest

from siteguard.config import ConfigError, example_config, validate_config


class SecurityConfigurationTests(unittest.TestCase):
    def validate_security(self, security):
        return validate_config({**example_config(), 'security': security})['security']

    def protected(self, prefix='/admin', cidrs=None):
        return {'prefix': prefix, 'allowed_cidrs': ['203.0.113.10/32'] if cidrs is None else cidrs}

    def validate_route(self, route, mode='enforce', **policy):
        raw = example_config()
        raw.update(mode=mode, routes=[{'name': 'private_api', 'prefix': '/api/private', **route}])
        raw['policy'].update(policy)
        return validate_config(raw)['routes'][0]

    def test_legacy_config_gets_security_defaults_without_shared_mutable_values(self):
        expected = {'block_sensitive_paths': True, 'blocked_methods': ['TRACE', 'TRACK', 'CONNECT'],
                    'response_headers': True, 'protected_paths': []}
        raw = example_config()
        del raw['security']
        first = validate_config(raw)
        self.assertEqual(first['security'], expected)
        first['security']['blocked_methods'].clear()
        first['security']['protected_paths'].append(self.protected())
        self.assertEqual(validate_config(raw)['security'], expected)
        sample = example_config()
        sample['security']['blocked_methods'].clear()
        self.assertEqual(example_config()['security'], expected)

    def test_partial_security_defaults_allow_explicit_disabling(self):
        result = self.validate_security({'response_headers': False})
        self.assertFalse(result['response_headers'])
        self.assertTrue(result['block_sensitive_paths'])
        self.assertEqual(result['blocked_methods'], ['TRACE', 'TRACK', 'CONNECT'])
        result = self.validate_security({'block_sensitive_paths': False, 'blocked_methods': []})
        self.assertFalse(result['block_sensitive_paths'])
        self.assertEqual(result['blocked_methods'], [])

    def test_unknown_fields_and_non_objects_fail_at_each_security_level(self):
        for value in (None, [], True, {'response_header': True}, {'block_sensitive_path': True},
                      {'protected_paths': [{'prefix': '/admin', 'allow_cidrs': ['203.0.113.10/32']}]},
                      {'protected_paths': [{**self.protected(), 'override': True}]}):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                self.validate_security(value)
        with self.assertRaises(ConfigError):
            self.validate_route({'response_guards': True, 'max_body_bytes': 1024})
        with self.assertRaises(ConfigError):
            self.validate_route({'response_guard': True, 'max_body_bytes': 1024, 'max_response_bytes': 1024})

    def test_security_and_route_flags_require_real_booleans(self):
        for value in (0, 1, 'true', 'false', None, [], {}):
            for key in ('response_headers', 'block_sensitive_paths'):
                with self.subTest(key=key, value=value), self.assertRaises(ConfigError):
                    self.validate_security({key: value})
            with self.subTest(key='response_guard', value=value), self.assertRaises(ConfigError):
                self.validate_route({'response_guard': value})

    def test_methods_accept_uppercase_rfc_tokens_and_sixteen_entry_boundary(self):
        methods = ['TRACE', 'M-SEARCH', "!#$%&'*+.^_`|~", *[f'CUSTOM{i}' for i in range(13)]]
        self.assertEqual(len(methods), 16)
        self.assertEqual(self.validate_security({'blocked_methods': methods})['blocked_methods'], methods)

    def test_methods_reject_empty_tokens_lowercase_duplicates_and_non_lists(self):
        invalid = ['TRACE', None, {}, (), ['TRACE'] * 2, [f'M{i}' for i in range(17)]]
        invalid.extend([[value] for value in ('', 'trace', 'Trace', 'GET ', 'GET\n', 'G ET', 'GET/POST',
                                             'G:ET', 'G(ET)', 'ＧＥＴ', '\x00', None, True, 1)])
        for methods in invalid:
            with self.subTest(methods=methods), self.assertRaises(ConfigError):
                self.validate_security({'blocked_methods': methods})

    def test_protected_paths_reject_ambiguous_or_non_ascii_prefixes(self):
        invalid = ('', 'admin', '/admin%2F', '/admin%252f', '/admin?q=1', '/admin#part', '/admin;v=1',
                   '/admin\\child', '/admin child', '/admin\t', '/admin\n', '/admin\x7f',
                   '/後台', '//admin', '/admin//child', '/admin//', '/./admin', '/admin/../child',
                   '/admin/.', '/admin/..', '/admin.', '/admin./child', '/admin.../',
                   '/' + 'a' * 8192, None, True, 123)
        for prefix in invalid:
            with self.subTest(prefix=prefix), self.assertRaises(ConfigError):
                self.validate_security({'protected_paths': [self.protected(prefix)]})

    def test_root_and_overlapping_paths_keep_separate_cidr_rules(self):
        rules = [self.protected('/', ['203.0.113.0/24']),
                 self.protected('/admin/', ['203.0.113.10/32']),
                 self.protected('/admin/private', ['2001:0DB8:0000::/48'])]
        result = self.validate_security({'protected_paths': rules})['protected_paths']
        self.assertEqual(result, [self.protected('/', ['203.0.113.0/24']),
                                  self.protected('/admin', ['203.0.113.10/32']),
                                  self.protected('/admin/private', ['2001:db8::/48'])])
        self.assertEqual(rules[1]['prefix'], '/admin/')

    def test_duplicate_paths_are_rejected_after_trailing_slash_normalization(self):
        for prefixes in (('/admin', '/admin/'), ('/', '/')):
            with self.subTest(prefixes=prefixes), self.assertRaises(ConfigError):
                self.validate_security({'protected_paths': [self.protected(prefix) for prefix in prefixes]})

    def test_protected_path_entries_require_allowed_cidrs_and_bounded_lists(self):
        for paths in (None, {}, 'admin', [None], [[]], [{}], [{'prefix': '/admin'}],
                      [{'allowed_cidrs': ['203.0.113.10/32']}],
                      [self.protected(f'/admin{i}') for i in range(33)]):
            with self.subTest(paths=paths), self.assertRaises(ConfigError):
                self.validate_security({'protected_paths': paths})
        valid = [self.protected(f'/admin{i}') for i in range(32)]
        self.assertEqual(len(self.validate_security({'protected_paths': valid})['protected_paths']), 32)

    def test_allowed_cidrs_require_exact_non_global_networks_and_unique_entries(self):
        invalid = [None, [], {}, '203.0.113.10/32', ['203.0.113.10'], ['203.0.113.1/24'],
                   ['2001:db8::1/48'], ['0.0.0.0/0'], ['::/0'], ['203.0.113.10/33'],
                   ['2001:db8::/129'], ['203.0.113.10/32 '], ['fe80::%en0/64'], [True], [0],
                   ['203.0.113.10/32'] * 2, ['2001:db8::/48', '2001:0DB8:0000::/48'],
                   [f'203.0.113.{i}/32' for i in range(33)]]
        for cidrs in invalid:
            with self.subTest(cidrs=cidrs), self.assertRaises(ConfigError):
                self.validate_security({'protected_paths': [{'prefix': '/admin', 'allowed_cidrs': cidrs}]})
        valid = [f'203.0.113.{i}/32' for i in range(32)]
        result = self.validate_security({'protected_paths': [self.protected(cidrs=valid)]})
        self.assertEqual(result['protected_paths'][0]['allowed_cidrs'], valid)

    def test_response_guard_requires_explicit_small_cap_even_if_policy_has_one(self):
        for mode in ('observe', 'enforce'):
            with self.subTest(mode=mode), self.assertRaisesRegex(ConfigError, '明確設定.*請求與回應'):
                self.validate_route({'response_guard': True}, mode=mode, max_body_bytes=1024)
        for value in (0, 65537, 1024 ** 3, True, 1024.0, '1024', None):
            with self.subTest(value=value), self.assertRaisesRegex(ConfigError, '共用硬緩衝上限'):
                self.validate_route({'response_guard': True, 'max_body_bytes': value})

    def test_response_guard_accepts_shared_cap_boundaries_in_both_modes(self):
        for mode in ('observe', 'enforce'):
            for limit in (1, 65536):
                with self.subTest(mode=mode, limit=limit):
                    result = self.validate_route({'response_guard': True, 'max_body_bytes': limit}, mode)
                    self.assertTrue(result['response_guard'])
                    self.assertFalse(result['streaming'])
                    self.assertEqual(result['max_body_bytes'], limit)

    def test_response_guard_requires_canonical_safe_ascii_prefix(self):
        invalid = ('/api.', '/api./private', '/api/private.../', '/api;version=1',
                   '/api/私密', '/api/%70rivate', '/api/./private', '/api/../private',
                   '/api//private', '/api\\private', '/api/private?q=1', '/api/private#part',
                   '/api/private\x7f', '/api/private name', '/' + 'a' * 8192)
        for mode in ('observe', 'enforce'):
            for prefix in invalid:
                with self.subTest(mode=mode, prefix=prefix), self.assertRaises(ConfigError):
                    self.validate_route({'prefix': prefix, 'response_guard': True,
                                         'max_body_bytes': 1024}, mode)

    def test_canonical_prefixes_keep_valid_case_internal_dots_and_trailing_slash(self):
        for prefix in ('/Admin', '/api/v1.0', '/.well-known', '/api/private/', '/' + 'a' * 8191):
            expected = prefix.rstrip('/')
            with self.subTest(prefix=prefix):
                protected = self.validate_security({'protected_paths': [self.protected(prefix)]})
                self.assertEqual(protected['protected_paths'][0]['prefix'], expected)
                guarded = self.validate_route({'prefix': prefix, 'response_guard': True, 'max_body_bytes': 1024})
                self.assertEqual(guarded['prefix'], expected)

    def test_ordinary_routes_keep_existing_prefix_compatibility(self):
        for prefix in ('/api.', '/api;version=1', '/api/私密'):
            with self.subTest(prefix=prefix):
                route = self.validate_route({'prefix': prefix})
                self.assertEqual(route['prefix'], prefix)
                self.assertFalse(route['response_guard'])

    def test_response_guard_and_streaming_are_mutually_exclusive(self):
        for mode in ('observe', 'enforce'):
            for cap in ({}, {'max_body_bytes': 1024}):
                with self.subTest(mode=mode, cap=cap), self.assertRaisesRegex(ConfigError, '不可與 streaming'):
                    self.validate_route({'streaming': True, 'response_guard': True, **cap}, mode)
        self.assertFalse(self.validate_route({'streaming': True})['response_guard'])
        self.assertFalse(self.validate_route({'max_body_bytes': 65537})['response_guard'])
        self.assertFalse(self.validate_route({'response_guard': False})['response_guard'])

    def test_validation_and_returned_values_do_not_mutate_caller_input(self):
        raw = example_config()
        raw['security']['protected_paths'] = [self.protected('/admin/', ['2001:0DB8:0000::/48'])]
        raw['routes'] = [{'name': 'private_api', 'prefix': '/api/private/',
                          'response_guard': True, 'max_body_bytes': 4096}]
        before = copy.deepcopy(raw)
        result = validate_config(raw)
        self.assertEqual(raw, before)
        result['security']['protected_paths'][0]['allowed_cidrs'].clear()
        result['security']['blocked_methods'].clear()
        result['routes'][0]['max_body_bytes'] = 1
        self.assertEqual(raw, before)
        raw['routes'][0]['max_body_bytes'] = 65537
        before_failure = copy.deepcopy(raw)
        with self.assertRaises(ConfigError):
            validate_config(raw)
        self.assertEqual(raw, before_failure)


if __name__ == '__main__':
    unittest.main()
