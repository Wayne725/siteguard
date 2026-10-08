import hashlib
import json
import math
import unittest
from collections import Counter

from cancellation_probe import MAX_INFLIGHT, make_probe_schedule
from experiment import MAX_CLIENT_INFLIGHT, make_schedule
from workload import ARRIVALS


class WorkloadTests(unittest.TestCase):
    def check_variants(self, factory, inflight_cap):
        periodic = factory('periodic')
        identity = lambda row: (row['request_id'], row['label'], row['phase'], row['kind'], row['product_id'])
        counts = Counter((row['label'], row['phase'], row['kind']) for row in periodic)
        windows = Counter(math.floor(row['offset_s'] / .5) for row in periodic)
        for arrival in ARRIVALS:
            with self.subTest(arrival=arrival):
                schedule = factory(arrival)
                self.assertEqual(schedule, factory(arrival))
                self.assertEqual({identity(row) for row in schedule}, {identity(row) for row in periodic})
                self.assertEqual(Counter((row['label'], row['phase'], row['kind']) for row in schedule), counts)
                self.assertEqual(Counter(math.floor(row['offset_s'] / .5) for row in schedule), windows)
                self.assertLessEqual(max(windows.values()), inflight_cap)
                self.assertTrue(all(0 <= row['offset_s'] < 30 for row in schedule))
                self.assertTrue(all(len(row['request_id']) == 24 and
                                    all(character in '0123456789abcdef' for character in row['request_id'])
                                    for row in schedule))
                if arrival != 'periodic':
                    self.assertNotEqual([row['offset_s'] for row in schedule],
                                        [row['offset_s'] for row in periodic])

    def test_regular_arrivals_preserve_phase_kind_identity_and_window_counts(self):
        for scenario in ('normal', 'surge', 'mixed', 'critical'):
            self.check_variants(lambda arrival: make_schedule(scenario, 30, 42, arrival), MAX_CLIENT_INFLIGHT)

    def test_probe_arrivals_preserve_counts_with_bounded_bursts(self):
        self.check_variants(lambda arrival: make_probe_schedule(30, 'report', 42, arrival), MAX_INFLIGHT)
        schedule = make_probe_schedule(3, 'report', 42, 'burst')
        report, order = schedule[:2]
        self.assertEqual((report['kind'], order['kind']), ('report', 'orders'))
        self.assertLess(order['offset_s'] - report['offset_s'], .02)

    def test_periodic_keeps_original_probe_offsets(self):
        schedule = make_probe_schedule(3, 'report', 42)
        self.assertEqual([row['offset_s'] for row in schedule],
                          [.05, .25, .55, 1.05, 1.25, 1.55, 2.05, 2.25, 2.55])

    def test_schedule_hash_depends_on_workload_not_output_uuid_or_strategy(self):
        schedules = [make_probe_schedule(3, 'report', 42, 'jittered') for _ in range(6)]
        hashes = {hashlib.sha256(json.dumps(schedule, indent=2).encode()).hexdigest() for schedule in schedules}
        self.assertEqual(len(hashes), 1)
        self.assertNotEqual(schedules[0], make_probe_schedule(3, 'report', 43, 'jittered'))

    def test_arrivals_do_not_cross_fractional_phase_boundaries(self):
        for arrival in ARRIVALS:
            for row in make_schedule('surge', 6, 42, arrival):
                lower, upper = {'warmup': (0, 1.2), 'load': (1.2, 4.8), 'recovery': (4.8, 6)}[row['phase']]
                self.assertGreaterEqual(row['offset_s'], lower)
                if arrival == 'periodic':
                    self.assertLessEqual(row['offset_s'], upper)
                else:
                    self.assertLess(row['offset_s'], upper)


if __name__ == '__main__':
    unittest.main(verbosity=2)
