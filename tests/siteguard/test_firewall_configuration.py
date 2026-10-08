import copy
import unittest

from siteguard.config import ConfigError, example_config, validate_config


class FirewallConfigurationTests(unittest.TestCase):
    def validate(self, firewall, mode='observe'):
        return validate_config({**example_config(), 'mode': mode, 'firewall': firewall})['firewall']

    def test_legacy_config_defaults_to_allow_without_sharing_mutable_lists(self):
        raw = example_config()
        del raw['firewall']
        expected = {'default_action': 'allow', 'allow_cidrs': [], 'deny_cidrs': []}
        first = validate_config(raw)['firewall']
        self.assertEqual(first, expected)
        first['allow_cidrs'].append('192.0.2.1/32')
        first['deny_cidrs'].append('192.0.2.2/32')
        self.assertEqual(validate_config(raw)['firewall'], expected)
        sample = example_config()
        sample['firewall']['deny_cidrs'].append('::/0')
        self.assertEqual(example_config()['firewall'], expected)
        self.assertNotIn('firewall', raw)

    def test_partial_config_and_intentional_deny_all_are_valid_in_both_modes(self):
        for mode in ('observe', 'enforce'):
            with self.subTest(mode=mode):
                self.assertEqual(self.validate({}, mode),
                                 {'default_action': 'allow', 'allow_cidrs': [], 'deny_cidrs': []})
                self.assertEqual(self.validate({'default_action': 'deny'}, mode),
                                 {'default_action': 'deny', 'allow_cidrs': [], 'deny_cidrs': []})
                self.assertEqual(self.validate({'deny_cidrs': ['192.0.2.1']}, mode),
                                 {'default_action': 'allow', 'allow_cidrs': [], 'deny_cidrs': ['192.0.2.1/32']})

    def test_bare_ip_and_exact_networks_normalize_without_collapsing_overlap(self):
        result = self.validate({
            'default_action': 'deny',
            'allow_cidrs': ['192.0.2.8', '2001:0DB8:0000::1', '192.0.2.0/24', '2001:db8::/48'],
            'deny_cidrs': ['192.0.2.8/32', '2001:db8::1/128'],
        })
        self.assertEqual(result['allow_cidrs'],
                         ['192.0.2.8/32', '2001:db8::1/128', '192.0.2.0/24', '2001:db8::/48'])
        self.assertEqual(result['deny_cidrs'], ['192.0.2.8/32', '2001:db8::1/128'])

    def test_explicit_global_networks_are_allowed_and_not_removed_from_deny_list(self):
        result = self.validate({'default_action': 'deny', 'allow_cidrs': ['0.0.0.0/0', '::/0'],
                                'deny_cidrs': ['0.0.0.0/0', '::/0']})
        self.assertEqual(result['allow_cidrs'], ['0.0.0.0/0', '::/0'])
        self.assertEqual(result['deny_cidrs'], ['0.0.0.0/0', '::/0'])
        self.assertEqual(self.validate({'deny_cidrs': ['0.0.0.0/0']})['deny_cidrs'], ['0.0.0.0/0'])

    def test_mapped_ipv6_normalizes_to_ipv4_while_native_ipv6_networks_remain(self):
        values = ['::ffff:203.0.113.8', '::ffff:198.51.100.0/120', '::ffff:0:0/96',
                  '2001:db8::/32', '::/0', '::fffe:0:0/95']
        expected = ['203.0.113.8/32', '198.51.100.0/24', '0.0.0.0/0',
                    '2001:db8::/32', '::/0', '::fffe:0:0/95']
        for key in ('allow_cidrs', 'deny_cidrs'):
            with self.subTest(key=key):
                result = self.validate({'default_action': 'deny', key: values})
                self.assertEqual(result[key], expected)

    def test_mapped_ipv6_and_equivalent_ipv4_are_detected_as_duplicates(self):
        equivalent = (['::ffff:203.0.113.8', '203.0.113.8'],
                      ['203.0.113.0/24', '::ffff:203.0.113.0/120'],
                      ['::ffff:0:0/96', '0.0.0.0/0'],
                      ['::ffff:cb00:7108/128', '203.0.113.8/32'])
        for key in ('allow_cidrs', 'deny_cidrs'):
            for values in equivalent:
                with self.subTest(key=key, values=values), self.assertRaisesRegex(ConfigError, '正規化後重複'):
                    self.validate({'default_action': 'deny', key: values})

    def test_allow_list_with_default_allow_is_rejected_as_ineffective(self):
        for mode in ('observe', 'enforce'):
            for settings in ({'allow_cidrs': ['192.0.2.1']},
                             {'default_action': 'allow', 'allow_cidrs': ['::/0'],
                              'deny_cidrs': ['2001:db8::/48']}):
                with self.subTest(mode=mode, settings=settings), self.assertRaisesRegex(ConfigError, '沒有放行作用'):
                    self.validate(settings, mode)

    def test_objects_fields_and_actions_are_strict(self):
        invalid = [None, [], False, 'allow', {'default': 'deny'}, {'allowed_cidrs': []},
                   {'deny_cidr': []}, {'default_action': None}, {'default_action': True},
                   {'default_action': 'ALLOW'}, {'default_action': 'drop'}, {'default_action': 'allow '},
                   {1: 'deny'}]
        for settings in invalid:
            with self.subTest(settings=settings), self.assertRaises(ConfigError):
                self.validate(settings)

    def test_ip_lists_require_lists_and_enforce_the_256_entry_boundary(self):
        entries = [f'192.0.2.{index}' for index in range(256)]
        for key in ('allow_cidrs', 'deny_cidrs'):
            result = self.validate({'default_action': 'deny', key: entries})
            self.assertEqual(len(result[key]), 256)
            self.assertEqual(result[key][-1], '192.0.2.255/32')
            for value in (None, '192.0.2.1', {}, (), True, entries + ['198.51.100.1']):
                with self.subTest(key=key, value_type=type(value)), self.assertRaises(ConfigError):
                    self.validate({'default_action': 'deny', key: value})

    def test_addresses_reject_hostnames_zones_host_bits_and_non_string_values(self):
        values = ('example.com', 'example.com/24', '', '192.0.2.1/24', '2001:db8::1/48',
                  'fe80::1%en0', 'fe80::%en0/64', '192.0.2.1/33', '2001:db8::/129',
                  '192.0.2.1 ', ' 192.0.2.1', '192.0.2.1\n', '192.0.2.1\x00',
                  '192.0.2.0/255.255.255.0', '192.0.2.0/２４', '192.0.2.0/-1',
                  '192.0.2.0/24/32', '[2001:db8::1]', '192.0.2.1:443', True, False, 0, None, [], {})
        for key in ('allow_cidrs', 'deny_cidrs'):
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ConfigError):
                    self.validate({'default_action': 'deny', key: [value]})

    def test_normalized_duplicates_are_rejected_within_each_list(self):
        duplicates = (['192.0.2.1', '192.0.2.1/32'],
                      ['2001:db8::1', '2001:0DB8:0000::1/128'],
                      ['2001:db8::/48', '2001:0DB8:0000::/48'],
                      ['0.0.0.0/0', '0.0.0.0/0'])
        for key in ('allow_cidrs', 'deny_cidrs'):
            for values in duplicates:
                with self.subTest(key=key, values=values), self.assertRaisesRegex(ConfigError, '正規化後重複'):
                    self.validate({'default_action': 'deny', key: values})

    def test_validation_and_results_do_not_mutate_input_on_success_or_failure(self):
        raw = example_config()
        raw['firewall'] = {'default_action': 'deny', 'allow_cidrs': ['2001:0DB8::1'],
                           'deny_cidrs': ['192.0.2.8']}
        before = copy.deepcopy(raw)
        result = validate_config(raw)
        self.assertEqual(raw, before)
        result['firewall']['allow_cidrs'].clear()
        result['firewall']['deny_cidrs'].append('::/0')
        self.assertEqual(raw, before)
        raw['firewall']['deny_cidrs'].append('192.0.2.8/32')
        invalid_before = copy.deepcopy(raw)
        with self.assertRaises(ConfigError):
            validate_config(raw)
        self.assertEqual(raw, invalid_before)


if __name__ == '__main__':
    unittest.main()
