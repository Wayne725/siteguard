import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import database
from cancellation import Cancellation, WorkCancelled


class TransactionChecks:
    def test_duplicate_orders_decrement_stock_once(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.backend.execute(
                self.target, 'orders', 'same-key', 3, 1), range(4)))
        self.assertTrue(all(row['persisted'] for row in results))
        audit = self.backend.audit(self.target)
        self.assertEqual(audit['committed_orders'], [{'request_id': 'same-key', 'product_id': 3}])
        self.assertEqual(audit['stock_used'], 1)
        self.assertEqual(audit['products'][2]['stock'], 99999)

    def test_reusing_key_for_different_product_rolls_back(self):
        self.backend.execute(self.target, 'orders', 'same-key', 1, 1)
        with self.assertRaises(self.backend.ERRORS):
            self.backend.execute(self.target, 'orders', 'same-key', 2, 1)
        audit = self.backend.audit(self.target)
        self.assertEqual(audit['stock_used'], 1)
        self.assertEqual(audit['products'][1]['stock'], 100000)

    def test_invalid_product_creates_no_order(self):
        with self.assertRaises(self.backend.ERRORS):
            self.backend.execute(self.target, 'orders', 'bad-product', 999, 1)
        self.assertEqual(self.backend.audit(self.target)['committed_order_ids'], [])

    def test_cancelled_before_start_creates_no_order(self):
        cancellation = Cancellation()
        cancellation.cancel()
        with self.assertRaises(WorkCancelled):
            self.backend.execute(self.target, 'orders', 'cancelled', 1, 1, cancellation)
        self.assertEqual(self.backend.audit(self.target)['stock_used'], 0)

    def test_real_report_has_expected_checksum(self):
        result = self.backend.execute(self.target, 'report', '', 1, 2)
        self.assertEqual(result['checksum'], 40_040_000)


class SQLiteTests(TransactionChecks, unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.backend = database
        self.target = Path(self.temp_dir.name) / 'test.sqlite'
        self.backend.initialize(self.target)


@unittest.skipUnless(os.environ.get('RUN_LAB_POSTGRES_TESTS') == '1',
                     'requires the isolated Compose lab and explicit test flag')
class PostgreSQLTests(TransactionChecks, unittest.TestCase):
    def setUp(self):
        import postgres_database
        self.backend = postgres_database
        self.target = os.environ['APP_DATABASE_URL']
        self.backend.initialize(self.target)
        self.backend.reset(self.target)
        self.addCleanup(self.backend.reset, self.target)


if __name__ == '__main__':
    unittest.main(verbosity=2)
