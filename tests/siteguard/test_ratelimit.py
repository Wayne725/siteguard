from concurrent.futures import ThreadPoolExecutor
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from siteguard.ratelimit import DOMAIN, Policy, RateLimitService, load_policy, render_policy


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def config(**overrides):
    value = {
        'version': 1, 'mode': 'enforce',
        'policy': {'rate_per_second': 100, 'burst': 100,
                   'per_ip_rate': 1, 'per_ip_burst': 2},
        'route_names': ['default', 'reports'],
        'routes': {'reports': {'rate_per_second': 1, 'burst': 1}},
        'max_clients': 2, 'idle_ttl_seconds': 10,
    }
    value.update(overrides)
    return value


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()

    def test_render_has_only_policy_and_explicit_route_rates(self):
        raw = {'mode': 'observe', 'policy': {
            'rate_per_second': 20, 'burst': 40, 'per_ip_rate': 2, 'per_ip_burst': 4,
            'max_concurrent': 30, 'secret': 'must-not-copy'},
            'routes': [{'name': 'reports', 'rate_per_second': 1, 'burst': 2},
                       {'name': 'stream', 'streaming': True}]}
        rendered = render_policy(raw)
        self.assertEqual(rendered['routes'], {'reports': {'rate_per_second': 1, 'burst': 2}})
        self.assertEqual(rendered['route_names'], ['default', 'reports', 'stream'])
        self.assertEqual(rendered['max_clients'], 10000)
        self.assertNotIn('secret', json.dumps(rendered))
        self.assertEqual(Policy(rendered, self.clock).mode, 'observe')

    def test_render_module_imports_without_server_or_yaml_dependencies(self):
        result = subprocess.run([sys.executable, '-S', '-c',
                                 'from siteguard.ratelimit import render_policy'],
                                cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_route_rejection_does_not_spend_site_or_client_credit(self):
        policy = Policy(config(), self.clock)
        self.assertTrue(policy.check('192.0.2.1', 'reports').allowed)
        rejected = policy.check('192.0.2.2', 'reports')
        self.assertEqual(rejected.limited_scopes, ('route',))
        self.assertEqual(policy.site.tokens, 99)
        self.assertNotIn('192.0.2.2', policy.clients)
        self.assertTrue(policy.check('192.0.2.2').allowed)
        self.assertTrue(policy.check('192.0.2.2').allowed)
        self.assertFalse(policy.check('192.0.2.2').allowed)
        self.assertEqual(policy.site.tokens, 97)

    def test_site_rejection_does_not_spend_route_credit(self):
        settings = config()
        settings['policy'].update(rate_per_second=1, burst=1)
        policy = Policy(settings, self.clock)
        self.assertTrue(policy.check('192.0.2.1').allowed)
        self.assertEqual(policy.check('192.0.2.2', 'reports').limited_scopes, ('site',))
        self.assertEqual(policy.routes['reports'].tokens, 1)
        self.clock.now = 1
        self.assertTrue(policy.check('192.0.2.2', 'reports').allowed)

    def test_full_cache_uses_shared_overflow_without_lru_token_reset(self):
        settings = config(max_clients=1)
        settings['policy']['per_ip_burst'] = 1
        policy = Policy(settings, self.clock)
        self.assertTrue(policy.check('192.0.2.1').allowed)
        overflow = policy.check('192.0.2.2')
        self.assertTrue(overflow.allowed)
        self.assertTrue(overflow.overflow)
        for index in range(3, 100):
            decision = policy.check(f'192.0.2.{index}')
            self.assertFalse(decision.allowed)
            self.assertTrue(decision.overflow)
        self.assertEqual(list(policy.clients), ['192.0.2.1'])
        self.assertFalse(policy.check('192.0.2.1').allowed)

    def test_expiry_waits_for_full_natural_refill(self):
        settings = config(max_clients=1, idle_ttl_seconds=.001)
        settings['policy']['per_ip_rate'] = .1
        policy = Policy(settings, self.clock)
        self.assertTrue(policy.check('192.0.2.1').allowed)
        self.assertTrue(policy.check('192.0.2.1').allowed)
        self.clock.now = 1
        self.assertTrue(policy.check('192.0.2.2').overflow)
        self.assertIn('192.0.2.1', policy.clients)
        self.clock.now = 20
        self.assertTrue(policy.check('192.0.2.3').allowed)
        self.assertEqual(list(policy.clients), ['192.0.2.3'])

    def test_free_cache_slot_does_not_erase_recent_overflow_debt(self):
        settings = config(max_clients=1, idle_ttl_seconds=10)
        settings['policy']['per_ip_burst'] = 1
        policy = Policy(settings, self.clock)
        policy.check('192.0.2.1')
        self.clock.now = 9.9
        self.assertTrue(policy.check('192.0.2.2').allowed)
        self.clock.now = 10
        decision = policy.check('192.0.2.2')
        self.assertTrue(decision.overflow)
        self.assertFalse(decision.allowed)
        self.assertEqual(len(policy.clients), 0)
        self.clock.now = 11
        self.assertTrue(policy.check('192.0.2.2').allowed)
        self.assertEqual(list(policy.clients), ['192.0.2.2'])

    def test_ipv6_equivalent_and_mapped_addresses_share_credit(self):
        policy = Policy(config(), self.clock)
        self.assertTrue(policy.check('2001:db8::1').allowed)
        self.assertTrue(policy.check('2001:0db8:0:0:0:0:0:1').allowed)
        self.assertFalse(policy.check('2001:db8::1').allowed)
        self.assertTrue(policy.check('192.0.2.1').allowed)
        self.assertTrue(policy.check('::ffff:192.0.2.1').allowed)
        self.assertFalse(policy.check('192.0.2.1').allowed)
        self.assertEqual(len(policy.clients), 2)

    def test_unknown_route_or_malformed_address_cannot_create_state(self):
        policy = Policy(config(), self.clock)
        for address, route in [('unknown', 'default'), ('192.0.2.1', 'missing'),
                               ('fe80::1%random-zone', 'default'), ('1' * 5000, 'default')]:
            self.assertEqual(policy.check(address, route).reason, 'invalid_request')
        self.assertEqual(len(policy.clients), 0)
        self.assertEqual(policy.site.tokens, 100)

    def test_parallel_checks_cannot_overspend_global_bucket(self):
        settings = config(max_clients=1000)
        settings['policy'].update(rate_per_second=50, burst=50)
        policy = Policy(settings, self.clock)
        with ThreadPoolExecutor(max_workers=16) as pool:
            decisions = list(pool.map(lambda i: policy.check(f'2001:db8::{i:x}'), range(1, 201)))
        self.assertEqual(sum(decision.allowed for decision in decisions), 50)
        self.assertEqual(policy.site.tokens, 0)
        self.assertEqual(len(policy.clients), 50)

    def test_clock_reversal_cannot_mint_tokens(self):
        policy = Policy(config(), self.clock)
        policy.check('192.0.2.1')
        policy.check('192.0.2.1')
        self.clock.now = -100
        self.assertFalse(policy.check('192.0.2.1').allowed)
        self.clock.now = 1
        self.assertTrue(policy.check('192.0.2.1').allowed)
        self.assertFalse(policy.check('192.0.2.1').allowed)

    def test_metrics_do_not_contain_client_addresses(self):
        policy = Policy(config(), self.clock)
        policy.check('198.51.100.201', 'reports')
        snapshot = policy.snapshot()
        self.assertEqual(snapshot['counters']['allowed'], 1)
        self.assertNotIn('198.51.100.201', json.dumps(snapshot))

    def test_invalid_policy_cannot_disable_bounds(self):
        for updates in ({'max_clients': 0}, {'max_clients': True},
                        {'max_clients': 100001}, {'idle_ttl_seconds': float('inf')},
                        {'route_names': ['default', 'default']}, {'mode': 'bypass'}):
            with self.subTest(updates=updates), self.assertRaises(ValueError):
                Policy(config(**updates), self.clock)
        settings = config()
        settings['policy']['per_ip_rate'] = float('nan')
        with self.assertRaises(ValueError):
            Policy(settings, self.clock)

    def test_file_size_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'policy.json'
            path.write_text(json.dumps(config()))
            self.assertEqual(load_policy(path)['version'], 1)
            path.write_bytes(b' ' * 65537)
            with self.assertRaises(ValueError):
                load_policy(path)


class Context:
    def __init__(self, cancelled=False, remaining=1):
        self.is_cancelled = cancelled
        self.remaining = remaining

    def cancelled(self):
        return self.is_cancelled

    def time_remaining(self):
        return self.remaining


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        from envoy.service.ratelimit.v3 import rls_pb2
        self.pb = rls_pb2
        self.policy = Policy(config(), Clock())
        self.service = RateLimitService(self.policy)

    def request(self):
        request = self.pb.RateLimitRequest(domain=DOMAIN)
        descriptor = request.descriptors.add()
        for key, value in (('scope', 'site'), ('remote_address', '192.0.2.1'), ('route', 'default')):
            descriptor.entries.add(key=key, value=value)
        return request

    async def test_observe_reports_over_limit_instead_of_forcing_ok(self):
        service = RateLimitService(Policy(config(mode='observe'), Clock()))
        responses = [await service.ShouldRateLimit(self.request(), Context()) for _ in range(3)]
        self.assertEqual([r.overall_code for r in responses], [self.pb.RateLimitResponse.OK,
                         self.pb.RateLimitResponse.OK, self.pb.RateLimitResponse.OVER_LIMIT])
        self.assertEqual(responses[-1].statuses[0].code, self.pb.RateLimitResponse.OVER_LIMIT)
        self.assertEqual(responses[-1].dynamic_metadata['reason'], 'rate_limited')

    async def test_malformed_descriptors_and_overrides_create_no_credit(self):
        original = self.request()
        requests = []
        for change in ('domain', 'duplicate', 'extra_descriptor', 'empty', 'hits', 'override',
                       'descriptor_hits', 'scope', 'oversized'):
            request = copy.deepcopy(original)
            if change == 'domain':
                request.domain = 'another-service'
            elif change == 'duplicate':
                request.descriptors[0].entries[1].key = 'scope'
            elif change == 'extra_descriptor':
                request.descriptors.add().CopyFrom(request.descriptors[0])
            elif change == 'empty':
                request.ClearField('descriptors')
            elif change == 'hits':
                request.hits_addend = 2
            elif change == 'override':
                request.descriptors[0].limit.requests_per_unit = 100000
            elif change == 'descriptor_hits':
                request.descriptors[0].hits_addend.value = 0
            elif change == 'scope':
                request.descriptors[0].entries[0].value = 'other'
            elif change == 'oversized':
                request.descriptors[0].entries[1].value = 'x' * 5000
            requests.append(request)
        for request in requests:
            response = await self.service.ShouldRateLimit(request, Context())
            self.assertEqual(response.overall_code, self.pb.RateLimitResponse.OVER_LIMIT)
            self.assertEqual(response.dynamic_metadata['reason'], 'invalid_request')
        self.assertEqual(len(self.policy.clients), 0)
        self.assertEqual(self.policy.site.tokens, 100)

    async def test_cancelled_and_expired_calls_do_not_allocate_or_consume(self):
        for context in (Context(cancelled=True), Context(remaining=0), Context(remaining=-1)):
            response = await self.service.ShouldRateLimit(self.request(), context)
            self.assertEqual(response.overall_code, self.pb.RateLimitResponse.OVER_LIMIT)
            self.assertEqual(response.dynamic_metadata['reason'], 'cancelled')
        self.assertEqual(len(self.policy.clients), 0)
        self.assertEqual(self.policy.site.tokens, 100)
        self.assertTrue(self.policy.check('192.0.2.1').allowed)

    async def test_remote_address_action_matches_regardless_of_entry_order(self):
        request = self.request()
        entries = list(request.descriptors[0].entries)
        request.descriptors[0].ClearField('entries')
        request.descriptors[0].entries.extend(reversed(entries))
        response = await self.service.ShouldRateLimit(request, Context(remaining=None))
        self.assertEqual(response.overall_code, self.pb.RateLimitResponse.OK)


if __name__ == '__main__':
    unittest.main()
