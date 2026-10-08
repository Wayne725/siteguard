import unittest

from rls.policy import AdmissionPolicy, Config


class FakeClock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def step(self, seconds=1):
        self.now += seconds


def snapshot(run_id='run-a', running=0, outstanding=0, active=0, received=0, disconnected=0):
    return {'run_id': run_id, 'db_workers': 4,
            'running': {'report': running}, 'outstanding': {'report': outstanding},
            'active_after_disconnect': {'report': active},
            'totals': {'products_received': received, 'products_disconnected': disconnected}}


class RatePolicyTests(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()

    def policy(self, mode='fixed'):
        return AdmissionPolicy(Config(mode=mode), self.clock)

    def tick(self, policy, **values):
        self.clock.step()
        policy.observe(snapshot(**values))
        policy.advance()

    def test_bucket_refills_at_rate_and_caps_burst(self):
        policy = self.policy()
        self.assertTrue(policy.decide(['report'], 2).allowed)
        self.assertFalse(policy.decide(['report']).allowed)
        self.clock.step(.49)
        self.assertFalse(policy.decide(['report']).allowed)
        self.clock.step(.01)
        self.assertTrue(policy.decide(['report']).allowed)
        self.clock.step(10)
        self.assertTrue(policy.decide(['report'], 2).allowed)
        self.assertFalse(policy.decide(['report']).allowed)

    def test_multi_descriptor_admission_is_atomic(self):
        policy = self.policy()
        policy.decide(['report'], 2)
        before = policy.buckets['orders'].tokens
        self.assertFalse(policy.decide(['orders', 'report']).allowed)
        self.assertEqual(policy.buckets['orders'].tokens, before)
        self.assertTrue(policy.decide(['orders'], 8).allowed)
        self.assertFalse(policy.decide(['orders']).allowed)

    def test_duplicate_descriptors_charge_the_same_bucket_atomically(self):
        policy = self.policy()
        self.assertFalse(policy.decide(['report', 'report', 'report']).allowed)
        self.assertEqual(policy.buckets['report'].tokens, 2)
        self.assertTrue(policy.decide(['report', 'report']).allowed)
        self.assertEqual(policy.buckets['report'].tokens, 0)

    def test_pressure_shrinks_only_report_rate_to_floor(self):
        policy = self.policy('feedback')
        policy.observe(snapshot())
        self.tick(policy, running=3, outstanding=4, received=1)
        self.assertEqual(policy.report_rate, 1)
        self.tick(policy, running=4, outstanding=5, received=2)
        self.assertEqual(policy.report_rate, .5)
        self.tick(policy, running=4, outstanding=6, received=3)
        self.assertEqual(policy.report_rate, .5)
        self.assertEqual(policy.buckets['orders'].rate, 8)
        self.assertEqual(policy.buckets['products'].rate, 12)

    def test_retained_work_with_high_utilization_is_pressure(self):
        policy = self.policy('feedback')
        policy.observe(snapshot())
        self.tick(policy, running=3, outstanding=3, active=1)
        self.assertEqual(policy.report_rate, 1)

    def test_retained_work_with_low_utilization_does_not_reduce_rate(self):
        policy = self.policy('feedback')
        policy.observe(snapshot())
        self.tick(policy, running=1, outstanding=1, active=1)
        self.assertEqual(policy.report_rate, 2)

    def test_cheap_cancellations_alone_do_not_reduce_rate(self):
        policy = self.policy('feedback')
        policy.observe(snapshot())
        for received in range(1, 6):
            self.tick(policy, received=received, disconnected=received)
        self.assertEqual(policy.report_rate, 2)

    def test_busy_without_queue_or_residual_work_is_not_pressure(self):
        policy = self.policy('feedback')
        policy.observe(snapshot())
        self.tick(policy, running=4, outstanding=4, received=10)
        self.assertEqual(policy.report_rate, 2)

    def test_recovery_requires_three_demand_windows(self):
        policy = self.policy('feedback')
        policy.observe(snapshot())
        self.tick(policy, running=4, outstanding=5, received=1)
        for received in (2, 3):
            self.tick(policy, received=received)
            self.assertEqual(policy.report_rate, 1)
        self.tick(policy, received=4)
        self.assertEqual(policy.report_rate, 1.25)

    def test_no_received_samples_do_not_increase_rate(self):
        policy = self.policy('feedback')
        policy.observe(snapshot())
        self.tick(policy, running=4, outstanding=5, received=1)
        for _ in range(6):
            self.tick(policy, received=1)
        self.assertEqual(policy.report_rate, 1)

    def test_run_id_resets_buckets_rate_and_recovery(self):
        policy = self.policy('feedback')
        policy.observe(snapshot())
        self.tick(policy, running=4, outstanding=5)
        policy.decide(['report'], 2)
        self.assertEqual(policy.report_rate, 1)
        policy.observe(snapshot(run_id='run-b'))
        self.assertEqual(policy.report_rate, 2)
        self.assertEqual(policy.healthy_windows, 0)
        self.assertTrue(policy.decide(['report'], 2).allowed)

    def test_stale_snapshot_falls_back_to_fixed_base(self):
        policy = self.policy('feedback')
        policy.observe(snapshot())
        self.tick(policy, running=4, outstanding=5)
        self.assertEqual(policy.report_rate, 1)
        self.clock.step(2.01)
        policy.advance()
        self.assertEqual(policy.report_rate, 2)
        self.assertEqual(policy.feedback_state, 'fixed_stale')

    def test_no_initial_snapshot_uses_fixed_settings(self):
        policy = self.policy('feedback')
        self.clock.step(3)
        policy.advance()
        self.assertEqual(policy.report_rate, 2)
        self.assertTrue(policy.decide(['report'], 2).allowed)
        self.assertFalse(policy.decide(['report']).allowed)

    def test_invalid_snapshot_does_not_refresh_freshness(self):
        policy = self.policy('feedback')
        policy.observe(snapshot())
        self.clock.step(3)
        for invalid in ({}, snapshot(running=-1), {'run_id': 'a', 'db_workers': 0},
                        snapshot(running=5, outstanding=5), snapshot(running=1, active=2),
                        snapshot(running=2, outstanding=1)):
            with self.assertRaises(ValueError):
                policy.observe(invalid)
        self.assertEqual(policy.snapshot_at, 0)
        policy.advance()
        self.assertEqual(policy.feedback_state, 'fixed_stale')

    def test_bypass_still_rejects_invalid_inputs(self):
        policy = self.policy('bypass')
        for kinds, hits in (([], 1), (['admin'], 1), (['report'], 0), (['orders'], 101)):
            self.assertFalse(policy.decide(kinds, hits).allowed)
        self.assertTrue(policy.decide(['report'], 100).allowed)
        self.assertEqual(policy.buckets['report'].tokens, 2)

    def test_env_config_bounds_and_finite_values(self):
        for env in ({'RLS_MODE': 'unknown'}, {'RLS_REPORT_RATE': '0'},
                    {'RLS_ORDERS_RATE': 'nan'}, {'RLS_REPORT_BURST': '.5'},
                    {'RLS_PRODUCTS_RATE': '51'}, {'RLS_REPORT_BURST': '101'}):
            with self.subTest(env=env), self.assertRaises(ValueError):
                Config.from_env(env)
        config = Config.from_env({'RLS_MODE': 'feedback', 'RLS_REPORT_RATE': '.5'})
        self.assertEqual(config.rates['report'], .5)
        self.assertEqual(config.bursts['report'], 1)


if __name__ == '__main__':
    unittest.main()
