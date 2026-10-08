"""Bounded runner for the local origin (:8000) or Envoy (:8080) only.

Requests are scheduled independently of response speed. If the generator cannot
keep up, it records a drop instead of silently reducing load or sending a burst.
Ground-truth labels remain client-side and are never sent to the defense.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import http.client
import json
import os
import platform
import random
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from policy import percentile
from event_analysis import analyze_events
from workload import ARRIVALS, ARRIVAL_WINDOW_S, retime_schedule

ROOT = Path(__file__).resolve().parent
HOST = '127.0.0.1'
ADMIN_BASE_URL = 'http://127.0.0.1:8000'
ALLOWED_BASE_URLS = {ADMIN_BASE_URL: 8000, 'http://127.0.0.1:8080': 8080}
LAB_ID = 'local-resource-defense-lab-v1'
MAX_CLIENT_INFLIGHT = 16
CLIENT_TIMEOUT = 3.5
SLO_MS = 1000.0  # proposed lab criterion, NOT an industry standard
RESET_SETTLE_S = 1


def local_base_url(value: str) -> str:
    normalized = value[:-1] if value.endswith('/') else value
    if normalized not in ALLOWED_BASE_URLS:
        raise argparse.ArgumentTypeError(
            'Only http://127.0.0.1:8000 or http://127.0.0.1:8080 is allowed.')
    return normalized


def call(method: str, path: str, payload: dict | None = None,
         token: str | None = None, base_url: str = ADMIN_BASE_URL,
         request_id: str | None = None) -> tuple[int, dict, dict]:
    """http.client does not follow redirects or use environment proxies."""
    if path not in ('/health', '/api/products', '/api/orders', '/api/report',
                    '/lab/reset', '/lab/state', '/lab/audit', '/lab/metadata', '/lab/events'):
        raise ValueError('path not in lab allowlist')
    base_url = local_base_url(base_url)
    if path.startswith('/lab/'):
        base_url = ADMIN_BASE_URL
    elif token is not None:
        raise ValueError('Admin token may only be sent to origin management paths.')
    con = http.client.HTTPConnection(HOST, ALLOWED_BASE_URLS[base_url], timeout=CLIENT_TIMEOUT)
    headers = {'Content-Type': 'application/json'}
    if token:
        headers['X-Lab-Admin'] = token
    if request_id is not None:
        if path not in ('/api/products', '/api/report'):
            raise ValueError('Request ID header is only used for GET business probes.')
        headers['X-Lab-Request-ID'] = request_id
    try:
        con.request(method, path, body=json.dumps(payload).encode() if payload else None,
                    headers=headers)
        res = con.getresponse()
        response_limit = 2 * 1024 * 1024 if path == '/lab/events' else 131072
        raw = res.read(response_limit + 1)
        if len(raw) > response_limit:
            raise ValueError('unexpected response size')
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = {'unexpected_response': raw[:100].decode(errors='replace')}
        return res.status, data, {k.lower(): v for k, v in res.getheaders()}
    finally:
        con.close()


def phase(t: float, seconds: int) -> str:
    return 'warmup' if t < seconds*.2 else ('load' if t < seconds*.8 else 'recovery')


def make_schedule(scenario: str, seconds: int, seed: int, arrival: str = 'periodic') -> list[dict]:
    rng = random.Random(seed)
    rows: list[dict] = []

    def add(rate: float, start: float, end: float, label: str, forced: str | None):
        t = start + .05
        while t < end:
            kind = forced or rng.choices(['products', 'orders', 'report'], [.6, .3, .1])[0]
            rows.append({'offset_s': round(t, 6), 'label': label, 'kind': kind,
                         'phase': phase(t, seconds), 'product_id': rng.randint(1, 20)})
            t += 1/rate

    add(4, 0, seconds, 'normal', None)
    if scenario == 'surge':
        add(8, seconds*.2, seconds*.8, 'normal', None)
    elif scenario == 'mixed':
        add(6, seconds*.2, seconds*.8, 'pressure', 'report')
    elif scenario == 'critical':
        add(6, seconds*.2, seconds*.8, 'pressure', 'orders')
    rows.sort(key=lambda x: x['offset_s'])
    for i, row in enumerate(rows):
        # The ID does not encode normal/pressure and has the same form for both.
        row['request_id'] = hashlib.sha256(f'{seed}:{scenario}:{i}'.encode()).hexdigest()[:24]
    return retime_schedule(rows, seconds, seed, arrival)


def issue(item: dict, start: float, base_url: str = ADMIN_BASE_URL) -> dict:
    scheduled = start + item['offset_s']
    sent = time.monotonic()
    row = dict(item, issued=True, status=0, outcome='client_error', business_ok=False,
               within_deadline=False, queue_ms=None, work_ms=None,
               generator_lag_ms=round((sent-scheduled)*1000, 3), latency_ms=None)
    path = '/api/' + item['kind']
    payload = ({'request_id': item['request_id'], 'product_id': item['product_id']}
               if item['kind'] == 'orders' else None)
    try:
        status, body, headers = call('POST' if payload else 'GET', path, payload,
                                     base_url=base_url,
                                     request_id=item['request_id'] if payload is None else None)
        correct = body.get('ok') is True
        if item['kind'] == 'orders':
            correct = correct and body.get('persisted') is True and body.get('order_id') == item['request_id']
        if item['kind'] == 'products':
            correct = correct and len(body.get('products', [])) == 20
        if item['kind'] == 'report':
            correct = correct and body.get('checksum', 0) > 0
        row.update(status=status, business_ok=(status == 200 and correct),
                   outcome=('ok' if status == 200 and correct else
                            'rejected' if status == 429 else
                            'server_error' if status >= 500 else 'invalid_response'),
                   queue_ms=headers.get('x-lab-queue-ms'), work_ms=headers.get('x-lab-work-ms'),
                   rejection_reason=body.get('reason') if status != 200 else None)
    except (socket.timeout, TimeoutError):
        row['outcome'] = 'client_timeout'
    except (OSError, http.client.HTTPException, ValueError) as exc:
        row['error'] = str(exc)
    row['latency_ms'] = round((time.monotonic()-scheduled)*1000, 3)
    row['within_deadline'] = row['business_ok'] and row['latency_ms'] <= SLO_MS
    return row


def summarize(rows: list[dict]) -> dict:
    def group(items: list[dict]) -> dict:
        good = [x for x in items if x['business_ok']]
        return {'planned': len(items), 'issued': sum(x['issued'] for x in items),
                'generator_drops': sum(not x['issued'] for x in items),
                'business_successes': len(good),
                'business_completion_rate': len(good)/len(items) if items else None,
                'success_within_deadline': sum(x['within_deadline'] for x in items),
                'completion_rate': (sum(x['within_deadline'] for x in items)/len(items)
                                    if items else None),
                'http_429': sum(x['status'] == 429 for x in items),
                'http_5xx': sum(x['status'] >= 500 for x in items),
                'client_timeouts': sum(x['outcome'] == 'client_timeout' for x in items),
                'successful_latency_p95_ms': percentile([x['latency_ms'] for x in good], .95)}
    return {'deadline_ms': SLO_MS, 'all': group(rows),
            'normal_load_phase': group([x for x in rows if x['label'] == 'normal' and x['phase'] == 'load']),
            'normal_orders_load_phase': group([x for x in rows if x['label'] == 'normal' and
                                               x['phase'] == 'load' and x['kind'] == 'orders']),
            'normal_reports_load_phase': group([x for x in rows if x['label'] == 'normal' and
                                                x['phase'] == 'load' and x['kind'] == 'report']),
            'by_label_phase_kind': {
                f'{label}/{p}/{kind}': group([x for x in rows if x['label'] == label and
                                            x['phase'] == p and x['kind'] == kind])
                for label in ('normal', 'pressure') for p in ('warmup', 'load', 'recovery')
                for kind in ('products', 'orders', 'report')},
            'warnings': ['Any generator drops invalidate comparisons at the intended arrival rate.',
                         'Successful-only p95 excludes rejected/failed requests; interpret with completion rate.',
                         'These are single-host resource-contention experiments, not Internet DDoS measurements.']}


def reconcile_orders(rows: list[dict], audit: dict) -> bool:
    orders = [row for row in rows if row['kind'] == 'orders']
    acknowledged = {row['request_id'] for row in orders if row['business_ok']}
    planned = {row['request_id'] for row in orders}
    issued = {row['request_id'] for row in orders if row['issued']}
    committed = set(audit['committed_order_ids'])
    audit['acknowledged_missing_in_db'] = sorted(acknowledged - committed)
    audit['committed_without_successful_ack'] = sorted(committed - acknowledged)
    audit['unexpected_committed_order_ids'] = sorted(committed - planned)
    audit['unissued_but_committed_order_ids'] = sorted((planned - issued) & committed)
    audit['stock_matches_orders'] = audit['stock_used'] == len(committed)
    detailed = {order['request_id']: order['product_id']
                for order in audit.get('committed_orders', [])}
    products = audit.get('products', [])
    audit['detailed_audit_available'] = 'committed_orders' in audit and 'products' in audit
    audit['order_details_match_ids'] = (audit['detailed_audit_available']
                                        and set(detailed) == committed)
    audit['mismatched_product_order_ids'] = sorted(
        row['request_id'] for row in orders if row['request_id'] in committed
        and detailed.get(row['request_id']) != row['product_id'])
    audit['per_product_stock_matches_orders'] = (
        audit['detailed_audit_available'] and {p['id'] for p in products} == set(range(1, 21))
        and all(100000 - p['stock'] == p['orders_count'] and p['stock'] >= 0 for p in products)
        and sum(p['orders_count'] for p in products) == len(committed))
    audit['scope'] = 'order IDs, expected products, aggregate and per-product stock usage'
    for row in orders:
        row['db_committed'] = row['request_id'] in committed
        row['audit_product_matches'] = detailed.get(row['request_id']) == row['product_id']
        if row['business_ok'] and not (row['db_committed'] and row['audit_product_matches']):
            row.update(business_ok=False, within_deadline=False, outcome='audit_failed')
    return (not audit['acknowledged_missing_in_db']
            and not audit['unexpected_committed_order_ids']
            and not audit['unissued_but_committed_order_ids']
            and not audit['mismatched_product_order_ids']
            and audit['order_details_match_ids'] and audit['stock_matches_orders']
            and audit['per_product_stock_matches_orders'])


def monitor(token: str, stop: threading.Event, snapshots: list) -> None:
    while not stop.is_set():
        try:
            status, body, _ = call('GET', '/lab/state', token=token)
            snapshots.append({'status': status, **body})
        except Exception as exc:
            snapshots.append({'monitor_error': str(exc)})
        stop.wait(1)


def run_one(args: argparse.Namespace, mode: str, seed: int, token: str, out: Path) -> dict:
    status, body, _ = call('POST', '/lab/reset',
                           {'mode': mode, 'report_rounds': args.report_rounds,
                            'fixed_limit': args.fixed_limit}, token)
    if status != 200:
        raise RuntimeError(f'Reset failed: {status} {body}')
    time.sleep(RESET_SETTLE_S)
    out.mkdir(parents=True, exist_ok=False)
    initial_run_id = body['run_id']
    schedule = make_schedule(args.scenario, args.seconds, seed, args.arrival)
    schedule_json = json.dumps(schedule, indent=2)
    (out/'schedule.json').write_text(schedule_json, encoding='utf-8')
    metadata = call('GET', '/lab/metadata', token=token)[1]
    metadata.update({'python': sys.version, 'platform': platform.platform(), 'mode': mode,
                     'scenario': args.scenario, 'seconds': args.seconds, 'seed': seed,
                     'arrival': args.arrival, 'arrival_window_s': ARRIVAL_WINDOW_S,
                     'report_rounds': args.report_rounds, 'fixed_limit': args.fixed_limit,
                     'base_url': args.base_url, 'admin_base_url': ADMIN_BASE_URL,
                     'transport_path': 'origin' if args.base_url == ADMIN_BASE_URL else 'envoy',
                     'label': args.label,
                     'reset_settle_s': RESET_SETTLE_S,
                     'schedule_sha256': hashlib.sha256(schedule_json.encode()).hexdigest(),
                     'client_max_inflight': MAX_CLIENT_INFLIGHT,
                     'client_timeout_s': CLIENT_TIMEOUT, 'source_sha256': {
                         f: hashlib.sha256((ROOT/f).read_bytes()).hexdigest()
                         for f in ('server.py', 'database.py', 'postgres_database.py', 'cancellation.py',
                                   'policy.py', 'experiment.py', 'workload.py', 'event_analysis.py')}})
    (out/'metadata.json').write_text(json.dumps(metadata, indent=2), encoding='utf-8')
    rows, snapshots = [], []
    stop = threading.Event()
    observer = threading.Thread(target=monitor, args=(token, stop, snapshots), daemon=True)
    observer.start()
    try:
        with ThreadPoolExecutor(max_workers=MAX_CLIENT_INFLIGHT) as pool:
            pending = set()
            start = time.monotonic()
            for item in schedule:
                delay = start + item['offset_s'] - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                done = {f for f in pending if f.done()}
                rows.extend(f.result() for f in done)
                pending -= done
                lag = time.monotonic() - (start + item['offset_s'])
                if len(pending) >= MAX_CLIENT_INFLIGHT or lag > .1:
                    rows.append(dict(item, issued=False, status=0, outcome='generator_drop',
                                     business_ok=False, within_deadline=False, latency_ms=None,
                                     generator_lag_ms=round(lag*1000, 3), queue_ms=None, work_ms=None))
                else:
                    pending.add(pool.submit(issue, item, start, args.base_url))
            rows.extend(f.result() for f in pending)
        # Drain before audit/reset. No hidden requests from previous runs.
        for _ in range(30):
            state_status, final_state, _ = call('GET', '/lab/state', token=token)
            if state_status != 200:
                raise RuntimeError(f'Drain check failed: {state_status}')
            if not sum(final_state.get('outstanding', {}).values()):
                break
            time.sleep(.2)
        else:
            raise RuntimeError('Server did not drain; stop and inspect before another run.')
        events_status, events, _ = call('GET', '/lab/events', token=token)
        if events_status != 200:
            raise RuntimeError(f'Event collection failed: {events_status}')
        audit_status, audit, _ = call('GET', '/lab/audit', token=token)
        if audit_status != 200:
            raise RuntimeError(f'Audit failed: {audit}')
    finally:
        stop.set()
        observer.join(timeout=4)
    rows.sort(key=lambda x: x['offset_s'])
    audit_ok = reconcile_orders(rows, audit)
    summary = summarize(rows)
    summary['order_audit_ok'] = audit_ok
    summary['parameters'] = {'mode': mode, 'scenario': args.scenario, 'seed': seed,
                             'base_url': args.base_url, 'label': args.label, 'arrival': args.arrival}
    evidence = analyze_events(rows, events, final_state, initial_run_id)
    with (out/'requests.csv').open('w', newline='', encoding='utf-8-sig') as f:
        writer = csv.DictWriter(f, fieldnames=sorted(set().union(*(x.keys() for x in rows))))
        writer.writeheader()
        writer.writerows(rows)
    for name, data in [('summary.json', summary), ('order_audit.json', audit),
                       ('events.json', events), ('evidence.json', evidence), ('final_state.json', final_state)]:
        (out/name).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    (out/'state.jsonl').write_text('\n'.join(json.dumps(x) for x in snapshots)+'\n', encoding='utf-8')
    normal = summary['normal_orders_load_phase']
    print(f'{mode:8} | normal orders during load: {normal["success_within_deadline"]}/'
          f'{normal["planned"]} | generator drops: {summary["all"]["generator_drops"]} | {out}')
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', choices=['normal', 'surge', 'mixed', 'critical'], default='normal')
    parser.add_argument('--mode', choices=['off', 'fixed', 'adaptive', 'all'], default='off')
    parser.add_argument('--seconds', type=int, default=30)
    parser.add_argument('--repeats', type=int, default=1)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--arrival', choices=ARRIVALS, default='periodic')
    parser.add_argument('--report-rounds', type=int, default=40)
    parser.add_argument('--fixed-limit', type=int, default=2)
    parser.add_argument('--base-url', type=local_base_url, default=ADMIN_BASE_URL,
                        help='Local origin :8000 or Envoy :8080; management always uses :8000.')
    parser.add_argument('--label', default='', help='Human-readable run label, stored in metadata.')
    args = parser.parse_args()
    if not (6 <= args.seconds <= 120 and 1 <= args.repeats <= 5 and
            1 <= args.report_rounds <= 100 and 1 <= args.fixed_limit <= 3):
        parser.error('Safety limits: seconds=6..120, repeats=1..5, report-rounds=1..100, fixed-limit=1..3')
    token_file = Path(os.environ.get('APP_RUNTIME_DIR', str(ROOT / 'runtime'))) / 'admin.token'
    if not token_file.exists():
        parser.error('Start the bundled server first: python server.py')
    token = token_file.read_text(encoding='utf-8').strip()
    try:
        status, body, _ = call('GET', '/health', base_url=args.base_url)
        if status != 200 or body.get('lab_id') != LAB_ID:
            raise RuntimeError(f'{args.base_url} is not the bundled lab. Refusing to run.')
        # Admin handshake verifies that this server belongs to this local project.
        if call('GET', '/lab/metadata', token=token)[0] != 200:
            raise RuntimeError('Admin handshake failed; check local server/runtime directory.')
        batch = ROOT/'results'/f'{time.strftime("%Y%m%d-%H%M%S")}-{time.time_ns()%1000000:06}'
        results = []
        for repeat in range(args.repeats):
            seed = args.seed+repeat
            modes = ['off', 'fixed', 'adaptive'] if args.mode == 'all' else [args.mode]
            random.Random(seed).shuffle(modes)
            for mode in modes:
                results.append(run_one(args, mode, seed, token,
                                       batch/f'{args.scenario}-{mode}-seed{seed}'))
        (batch/'batch_summary.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
        print('Raw records and audit saved. These results are not proof of general DDoS protection.')
    except KeyboardInterrupt:
        print('\nStopped. Allow bounded in-flight work to finish before restarting.', file=sys.stderr)
        raise SystemExit(130)
    except (OSError, RuntimeError, http.client.HTTPException) as exc:
        parser.exit(1, f'Experiment stopped: {exc}\n')


if __name__ == '__main__':
    main()
