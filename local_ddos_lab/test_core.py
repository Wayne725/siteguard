"""Small unit tests, runnable without starting the server."""
import tempfile
import unittest
from pathlib import Path

import database
from experiment import make_schedule, summarize
from policy import Controller, percentile


class CoreTests(unittest.TestCase):
    def test_controller_reduces_and_recovers(self):
        c = Controller()
        self.assertEqual(c.update(100, 0, 4), 'reduce')
        self.assertEqual(c.limit, 1)
        c.update(1, 0, 4)
        self.assertEqual(c.update(1, 0, 4), 'increase')
        self.assertEqual(c.limit, 2)

    def test_no_samples_do_not_imply_recovery(self):
        c = Controller(limit=1)
        for _ in range(5):
            c.update(None, 0, 5)
        self.assertEqual(c.limit, 1)

    def test_limits_hold(self):
        c = Controller()
        for _ in range(20):
            c.update(100, 1, 2)
        self.assertEqual(c.limit, 1)
        for _ in range(20):
            c.update(0, 0, 2)
        self.assertEqual(c.limit, 3)

    def test_schedule_deterministic_and_labels_not_in_id(self):
        a = make_schedule('mixed', 10, 42)
        self.assertEqual(a, make_schedule('mixed', 10, 42))
        self.assertTrue(any(x['label'] == 'pressure' for x in a))
        self.assertTrue(all(len(x['request_id']) == 24 for x in a))
        self.assertLessEqual(len(make_schedule('surge', 10, 42)), 120)

    def test_percentile_empty(self):
        self.assertIsNone(percentile([], .95))
        self.assertEqual(percentile([1, 2, 3], .95), 3)

    def test_real_order_commit_and_idempotency(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'db.sqlite'
            database.initialize(path)
            a = database.execute(path, 'orders', 'test-order', 1, 1)
            b = database.execute(path, 'orders', 'test-order', 1, 1)
            self.assertTrue(a['persisted'] and b['persisted'])
            audit = database.audit(path)
            self.assertEqual(audit['stock_used'], 1)
            self.assertEqual(len(audit['committed_order_ids']), 1)
            r = database.execute(path, 'report', '', 1, 1)
            self.assertGreater(r['checksum'], 0)
            database.reset(path)
            self.assertEqual(database.audit(path)['stock_used'], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
