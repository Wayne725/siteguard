"""Equivalent synthetic workload in an isolated PostgreSQL schema."""
import time

import psycopg

from cancellation import Cancellation

ROWS = 40_000
BACKEND = 'postgresql'
ERRORS = (psycopg.Error, ValueError)


def connect(dsn):
    return psycopg.connect(str(dsn), connect_timeout=3,
                          options='-c search_path=ddos_lab -c statement_timeout=1500 -c lock_timeout=250')


def readiness(dsn):
    with psycopg.connect(str(dsn), connect_timeout=1,
                         options='-c search_path=ddos_lab -c statement_timeout=250 -c lock_timeout=250') as con:
        return con.execute('SELECT id FROM products LIMIT 1').fetchone() is not None


def initialize(dsn):
    with connect(dsn) as con:
        con.execute('CREATE SCHEMA IF NOT EXISTS ddos_lab')
        con.execute('''CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL,
            stock INTEGER NOT NULL CHECK(stock>=0), price INTEGER NOT NULL)''')
        con.execute('''CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL, amount INTEGER NOT NULL)''')
        con.execute('''CREATE TABLE IF NOT EXISTS orders (
            request_id TEXT PRIMARY KEY, product_id INTEGER NOT NULL REFERENCES products(id),
            created DOUBLE PRECISION NOT NULL)''')
        con.execute('''INSERT INTO products SELECT i, 'Product '||i, 100000, 100+i
                       FROM generate_series(1,20) i ON CONFLICT DO NOTHING''')
        if con.execute('SELECT COUNT(*) FROM sales').fetchone()[0] != ROWS:
            con.execute('DELETE FROM sales')
            con.execute('''INSERT INTO sales SELECT i, i %% 20 + 1, (i*37) %% 1000 + 1
                           FROM generate_series(1,%s) i''', (ROWS,))


def reset(dsn):
    with connect(dsn) as con:
        con.execute('DELETE FROM orders')
        con.execute('UPDATE products SET stock=100000')


def audit(dsn):
    with connect(dsn) as con:
        orders = [{'request_id': r[0], 'product_id': r[1]} for r in
                  con.execute('SELECT request_id,product_id FROM orders ORDER BY request_id')]
        products = [{'id': r[0], 'stock': r[1], 'orders_count': r[2]} for r in con.execute('''
            SELECT p.id,p.stock,COUNT(o.request_id) FROM products p
            LEFT JOIN orders o ON p.id=o.product_id GROUP BY p.id,p.stock ORDER BY p.id''')]
    return {'committed_order_ids': [o['request_id'] for o in orders],
            'committed_orders': orders, 'products': products,
            'stock_used': sum(100000-p['stock'] for p in products)}


def execute(dsn, kind, request_id, product_id, report_rounds, cancellation=None):
    cancellation = cancellation or Cancellation()
    started = time.monotonic()
    with connect(dsn) as con:
        try:
            cancellation.bind(con.cancel)
            if kind == 'products':
                return {'ok': True, 'products': con.execute(
                    'SELECT id,name,price FROM products ORDER BY id').fetchall()}
            if kind == 'orders':
                inserted = con.execute('''INSERT INTO orders VALUES (%s,%s,%s)
                    ON CONFLICT(request_id) DO NOTHING RETURNING request_id''',
                    (request_id, product_id, time.time())).fetchone()
                if inserted:
                    result = con.execute('''UPDATE products SET stock=stock-1
                        WHERE id=%s AND stock>0''', (product_id,))
                    if result.rowcount != 1:
                        raise ValueError('product unavailable')
                elif con.execute('SELECT product_id FROM orders WHERE request_id=%s',
                                 (request_id,)).fetchone()[0] != product_id:
                    raise ValueError('idempotency key belongs to another product')
                cancellation.check()
                con.commit()
                return {'ok': True, 'order_id': request_id, 'persisted': True}
            if kind == 'report':
                checksum = 0
                for offset in range(report_rounds):
                    cancellation.check()
                    remaining = 1.5 - (time.monotonic()-started)
                    if remaining <= 0:
                        raise ValueError('SQL execution deadline exceeded')
                    con.execute("SELECT set_config('statement_timeout', %s, true)",
                                (str(max(1, int(remaining*1000))),))
                    rows = con.execute('''SELECT (product_id+%s) %% 17 AS bucket, SUM(amount)
                        FROM sales GROUP BY bucket''', (offset,)).fetchall()
                    checksum += sum(row[1] for row in rows)
                return {'ok': True, 'checksum': checksum, 'rounds': report_rounds}
            raise ValueError('unknown work kind')
        finally:
            cancellation.unbind()
