"""Small, real SQLite workload. No sleep-based backend workload."""
from __future__ import annotations

import sqlite3
import time
from contextlib import closing
from pathlib import Path
from typing import Any

from cancellation import Cancellation

ROWS = 40_000
BACKEND = 'sqlite'
ERRORS = (sqlite3.Error, ValueError)


def connect(path: Path) -> sqlite3.Connection:
    con = sqlite3.connect(path, timeout=0.25)
    con.execute('PRAGMA busy_timeout=250')
    return con


def readiness(path: Path) -> bool:
    # mode=ro makes a missing database a failure, rather than creating an empty one.
    with closing(sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True,
                                timeout=.25)) as con:
        return con.execute('SELECT id FROM products LIMIT 1').fetchone() is not None


def initialize(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(connect(path)) as con, con:
        con.execute('PRAGMA journal_mode=WAL')
        con.executescript('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL,
            stock INTEGER NOT NULL, price INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL,
            amount INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS orders (
            request_id TEXT PRIMARY KEY, product_id INTEGER NOT NULL,
            created REAL NOT NULL);
        ''')
        con.executemany('INSERT OR IGNORE INTO products VALUES (?, ?, ?, ?)',
                        ((i, f'Product {i}', 100000, 100+i) for i in range(1, 21)))
        if con.execute('SELECT COUNT(*) FROM sales').fetchone()[0] != ROWS:
            con.execute('DELETE FROM sales')
            con.executemany('INSERT INTO sales VALUES (?, ?, ?)',
                            ((i, i % 20 + 1, (i * 37) % 1000 + 1)
                             for i in range(1, ROWS+1)))


def reset(path: Path) -> None:
    with closing(connect(path)) as con, con:
        con.execute('DELETE FROM orders')
        con.execute('UPDATE products SET stock=100000')


def audit(path: Path) -> dict[str, Any]:
    with closing(connect(path)) as con, con:
        orders = [{'request_id': r[0], 'product_id': r[1]} for r in
                  con.execute('SELECT request_id,product_id FROM orders ORDER BY request_id')]
        products = [{'id': r[0], 'stock': r[1], 'orders_count': r[2]} for r in con.execute('''
            SELECT p.id,p.stock,COUNT(o.request_id) FROM products p
            LEFT JOIN orders o ON p.id=o.product_id GROUP BY p.id,p.stock ORDER BY p.id''')]
        stock_used = con.execute('SELECT SUM(100000-stock) FROM products').fetchone()[0]
    return {'committed_order_ids': [o['request_id'] for o in orders], 'stock_used': stock_used,
            'committed_orders': orders, 'products': products}


def execute(path: Path, kind: str, request_id: str, product_id: int,
            report_rounds: int, cancellation: Cancellation | None = None) -> dict[str, Any]:
    """Each worker owns its connection. Enforce a bounded SQL execution time."""
    start = time.monotonic()
    con = connect(path)
    cancellation = cancellation or Cancellation()
    con.set_progress_handler(lambda: int(time.monotonic()-start > 1.5
                                        or cancellation.requested.is_set()), 2000)
    try:
        cancellation.bind(con.interrupt)
        if kind == 'products':
            rows = con.execute('SELECT id,name,price FROM products ORDER BY id').fetchall()
            return {'ok': True, 'products': rows}
        if kind == 'orders':
            # Unique request_id makes retries idempotent within this demo.
            con.execute('BEGIN IMMEDIATE')
            existing = con.execute('SELECT product_id FROM orders WHERE request_id=?',
                                   (request_id,)).fetchone()
            if existing is None:
                cur = con.execute('UPDATE products SET stock=stock-1 WHERE id=? AND stock>0',
                                  (product_id,))
                if cur.rowcount != 1:
                    raise ValueError('product unavailable')
                con.execute('INSERT INTO orders VALUES (?, ?, ?)',
                            (request_id, product_id, time.time()))
            elif existing[0] != product_id:
                raise ValueError('idempotency key belongs to another product')
            cancellation.check()
            con.commit()
            persisted = con.execute('SELECT 1 FROM orders WHERE request_id=?',
                                    (request_id,)).fetchone() is not None
            return {'ok': persisted, 'order_id': request_id, 'persisted': persisted}
        if kind == 'report':
            # Repeated bounded aggregates deliberately create a heavier test workload.
            # This is synthetic business data, not a production report benchmark.
            checksum = 0
            for offset in range(report_rounds):
                rows = con.execute('''SELECT (product_id+?) % 17 AS bucket, SUM(amount)
                                      FROM sales GROUP BY bucket''', (offset,)).fetchall()
                checksum += sum(row[1] for row in rows)
            return {'ok': True, 'checksum': checksum, 'rounds': report_rounds}
        raise ValueError('unknown work kind')
    finally:
        cancellation.unbind()
        con.close()
