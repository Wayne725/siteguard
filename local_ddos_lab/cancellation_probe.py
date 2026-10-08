"""Bounded local cancellation observation: 2 probes/s plus 1 normal order/s."""
from __future__ import annotations

import argparse
import csv
import hashlib
import http.client
import json
import os
import platform
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from experiment import (ADMIN_BASE_URL, ALLOWED_BASE_URLS, CLIENT_TIMEOUT, HOST, LAB_ID,
                        ROOT, SLO_MS, RESET_SETTLE_S, call, issue, local_base_url, reconcile_orders, summarize)
from event_analysis import analyze_events
from workload import ARRIVALS, ARRIVAL_WINDOW_S, retime_schedule

MAX_INFLIGHT = 12
REPORT_ROUNDS = 40


def make_probe_schedule(seconds: int, kind: str, seed: int = 42,
                        arrival: str = 'periodic') -> list[dict]:
    rows = [dict(offset_s=round(.05 + i / 2, 6), kind=kind, label='probe', phase='load',
                 product_id=1) for i in range(seconds * 2)]
    rows.extend(dict(offset_s=round(.25 + i, 6), kind='orders', label='normal', phase='load',
                     product_id=i % 20 + 1) for i in range(seconds))
    rows.sort(key=lambda row: row['offset_s'])
    for index, row in enumerate(rows):
        row['request_id'] = hashlib.sha256(f'{seed}:probe:{kind}:{index}'.encode()).hexdigest()[:24]
    return retime_schedule(rows, seconds, seed, arrival, phased=False)


def send_probe(item: dict, start: float, base_url: str, cancel_after_ms: int | None) -> dict:
    base_url = local_base_url(base_url)
    scheduled = start + item['offset_s']
    sent = time.monotonic()
    row = dict(item, issued=True, status=0, outcome='client_error', business_ok=False,
               within_deadline=False, generator_lag_ms=round((sent - scheduled) * 1000, 3),
               latency_ms=None, deadline_cancelled=False, cancel_after_ms=cancel_after_ms,
               completed_before_cancel_deadline=False)
    connection = http.client.HTTPConnection(HOST, ALLOWED_BASE_URLS[base_url], timeout=CLIENT_TIMEOUT)
    timer = None
    cancelled = threading.Event()
    finished = threading.Event()
    lock = threading.Lock()
    try:
        connection.connect()
        connected_socket = connection.sock

        def close_at_deadline():
            with lock:
                if finished.is_set():
                    return
                cancelled.set()
                try:
                    connected_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        if cancel_after_ms is not None:
            timer = threading.Timer(cancel_after_ms / 1000, close_at_deadline)
            timer.daemon = True
            timer.start()
        connection.request('GET', f'/api/{item["kind"]}',
                           headers={'X-Lab-Request-ID': item['request_id']})
        response = connection.getresponse()
        raw = response.read(131073)
        if len(raw) > 131072:
            raise ValueError('unexpected response size')
        body = json.loads(raw)
        correct = body.get('ok') is True and (body.get('checksum', 0) > 0 if item['kind'] == 'report'
                                             else len(body.get('products', [])) == 20)
        row.update(status=response.status, business_ok=response.status == 200 and correct,
                   outcome='ok' if response.status == 200 and correct else 'http_or_business_error',
                   rejection_reason=body.get('reason') if response.status != 200 else None)
    except (socket.timeout, TimeoutError):
        row['outcome'] = 'client_timeout'
    except (OSError, http.client.HTTPException, ValueError) as exc:
        row['error'] = str(exc)
    finally:
        with lock:
            finished.set()
            if timer is not None:
                timer.cancel()
            row['deadline_cancelled'] = cancelled.is_set()
        if timer is not None:
            timer.join(timeout=1)
        connection.close()
    if row['deadline_cancelled']:
        row.update(outcome='deadline_cancelled', business_ok=False)
    row['latency_ms'] = round((time.monotonic() - scheduled) * 1000, 3)
    row['within_deadline'] = row['business_ok'] and row['latency_ms'] <= SLO_MS
    row['completed_before_cancel_deadline'] = (
        cancel_after_ms is not None and row['business_ok'] and not row['deadline_cancelled'])
    return row


def admin(path: str, token: str, payload: dict | None = None) -> dict:
    status, body, _ = call('POST' if payload is not None else 'GET', path, payload, token)
    if status != 200:
        raise RuntimeError(f'{path} failed: {status} {body}')
    return body


def wait_for_drain(token: str) -> dict:
    consecutive_idle = 0
    for _ in range(80):
        state = admin('/lab/state', token)
        counts = [count for field in ('outstanding', 'running', 'active_after_disconnect')
                  for count in state.get(field, {}).values()]
        if any(count < 0 for count in counts):
            raise RuntimeError(f'Negative resource counter; stop and inspect: {state}')
        consecutive_idle = consecutive_idle + 1 if all(count == 0 for count in counts) else 0
        if consecutive_idle >= 3:
            return state
        time.sleep(.1)
    raise RuntimeError('Backend did not fully drain; no audit or next reset was attempted.')


def observe(token: str, stop: threading.Event, snapshots: list) -> None:
    while not stop.is_set():
        try:
            snapshots.append(admin('/lab/state', token))
        except (OSError, RuntimeError, http.client.HTTPException) as exc:
            snapshots.append({'monitor_error': str(exc)})
        stop.wait(.1)


def classify_observation(wait_run: dict, cancel_run: dict, kind: str) -> dict:
    rows = [row for row in cancel_run['rows'] if row['kind'] == kind]
    issued_ids = {row['request_id'] for row in rows if row['issued']}
    events = [event for event in cancel_run['events']['events']
              if event.get('kind') == kind and event.get('request_id') in issued_ids]
    disconnected = {event['request_id'] for event in events if event.get('event') == 'http_disconnect_observed'}
    deadline_cancellations = sum(row.get('deadline_cancelled', False) for row in rows)
    faults = []
    for name, run in (('wait', wait_run), ('cancel', cancel_run)):
        evidence = run.get('evidence') or analyze_events(
            run['rows'], run['events'], run['state'], run.get('initial_run_id'))
        faults.extend(f'{name}: {issue}' for issue in evidence['validity_issues'])
        if not run['order_audit_ok']:
            faults.append(f'{name}: order audit failed')
        if any(not row['issued'] for row in run['rows']):
            faults.append(f'{name}: generator drops')
        if any(row['outcome'] in ('client_error', 'client_timeout') for row in run['rows']):
            faults.append(f'{name}: unexpected client error or timeout')
    residuals = []
    if not faults:
        starts = {event['request_id']: event['elapsed_s'] for event in events
                  if event['event'] == 'db_work_started'}
        disconnect_times = {event['request_id']: event['elapsed_s'] for event in events
                            if event['event'] == 'http_disconnect_observed'}
        residuals = [round((event['elapsed_s'] - max(starts[event['request_id']],
                            disconnect_times[event['request_id']])) * 1000, 3)
                     for event in events if event['event'] == 'db_work_finished'
                     and event['request_id'] in disconnected and event['request_id'] in starts
                     and event['elapsed_s'] > max(starts[event['request_id']],
                                                 disconnect_times[event['request_id']])]
    if faults:
        status, reason = 'inconclusive', 'Observation validity checks failed; inspect raw records.'
    elif not deadline_cancellations:
        if rows and all(row['business_ok'] for row in rows):
            status, reason = 'not_observed', 'All probes completed before cancellation; cancellation was not triggered.'
        else:
            status, reason = 'inconclusive', 'No deadline cancellation and not all probes completed successfully.'
    elif not disconnected:
        status, reason = 'inconclusive', 'Client closed requests, but origin did not observe disconnects.'
    elif residuals:
        status, reason = 'observed', 'Origin observed disconnects followed by recorded DB worker cleanup time.'
    else:
        status, reason = 'not_observed', 'Disconnects were observed without positive post-disconnect DB work time.'
    return {'status': status, 'reason': reason, 'validity_issues': faults,
            'deadline_cancellations': deadline_cancellations, 'origin_disconnects': len(disconnected),
            'db_finishes_after_disconnect': len(residuals), 'residual_ms': residuals,
            'max_residual_ms': max(residuals) if residuals else None,
            'limitations': [
                'Observed cleanup time alone is not evidence of a bug, attack or control-policy weakness.',
                'This single wait/cancel pair does not establish causality or algorithm superiority.',
                'Probe lifecycle association uses exact opaque client request IDs within the same server run.',
                'DB execution overlap alone does not establish saturation or harm to normal orders.',
                'Proxy buffering or cancellation behavior can prevent an origin disconnect observation.']}


def write_json(path: Path, payload) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')


def gateway_snapshot(base_url: str) -> dict:
    if base_url == ADMIN_BASE_URL:
        return {'applicable': False}
    connection = http.client.HTTPConnection(HOST, 9901, timeout=1)
    try:
        connection.request('GET', '/stats?format=json&filter=adaptive_concurrency')
        response = connection.getresponse()
        raw = response.read(131073)
        if response.status != 200 or len(raw) > 131072:
            raise ValueError('Gateway statistics unavailable or oversized')
        return {'applicable': True, 'captured': True, 'monotonic_s': time.monotonic(),
                'stats': json.loads(raw)}
    except (OSError, ValueError, http.client.HTTPException) as exc:
        return {'applicable': True, 'captured': False, 'error_type': type(exc).__name__}
    finally:
        connection.close()


def run_round(args: argparse.Namespace, variant: str, schedule: list[dict], token: str, out: Path) -> dict:
    wait_for_drain(token)
    reset_config = {'mode': args.mode, 'report_rounds': args.report_rounds, 'fixed_limit': args.fixed_limit}
    admin('/lab/reset', token, reset_config)
    time.sleep(RESET_SETTLE_S)
    for kind in ('products', args.kind):
        status, _, _ = call('GET', f'/api/{kind}', base_url=args.base_url)
        if status != 200:
            raise RuntimeError(f'Warmup failed: {status}')
    wait_for_drain(token)
    initial = admin('/lab/reset', token, reset_config)
    time.sleep(RESET_SETTLE_S)
    out.mkdir()
    write_json(out / 'gateway_stats_start.json', gateway_snapshot(args.base_url))
    rows, snapshots = [], []
    stop = threading.Event()
    monitor = threading.Thread(target=observe, args=(token, stop, snapshots), daemon=True)
    monitor.start()
    try:
        with ThreadPoolExecutor(max_workers=MAX_INFLIGHT) as pool:
            pending = set()
            start = time.monotonic()
            for item in schedule:
                delay = start + item['offset_s'] - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                done = {future for future in pending if future.done()}
                rows.extend(future.result() for future in done)
                pending -= done
                lag = time.monotonic() - start - item['offset_s']
                if len(pending) >= MAX_INFLIGHT or lag > .1:
                    rows.append(dict(item, issued=False, status=0, business_ok=False,
                                     within_deadline=False, outcome='generator_drop', latency_ms=None,
                                     generator_lag_ms=round(lag * 1000, 3)))
                elif item['kind'] == 'orders':
                    pending.add(pool.submit(issue, item, start, args.base_url))
                else:
                    pending.add(pool.submit(send_probe, item, start, args.base_url,
                                           args.cancel_after_ms if variant == 'cancel' else None))
            rows.extend(future.result() for future in pending)
        state = wait_for_drain(token)
        events = admin('/lab/events', token)
        audit = admin('/lab/audit', token)
    finally:
        stop.set()
        monitor.join(timeout=4)
        write_json(out / 'gateway_stats_end.json', gateway_snapshot(args.base_url))
    rows.sort(key=lambda row: row['offset_s'])
    audit_ok = reconcile_orders(rows, audit)
    metrics = summarize(rows)
    metrics.update(experiment_type='cancellation_probe', order_audit_ok=audit_ok, variant=variant)
    evidence = analyze_events(rows, events, state, initial['run_id'])
    write_json(out / 'metrics.json', metrics)
    write_json(out / 'evidence.json', evidence)
    write_json(out / 'events.json', events)
    write_json(out / 'order_audit.json', audit)
    write_json(out / 'final_state.json', state)
    (out / 'state.jsonl').write_text('\n'.join(json.dumps(row) for row in snapshots) + '\n', encoding='utf-8')
    with (out / 'requests.csv').open('w', newline='', encoding='utf-8-sig') as stream:
        writer = csv.DictWriter(stream, fieldnames=sorted(set().union(*(row.keys() for row in rows))))
        writer.writeheader()
        writer.writerows(rows)
    print(f'{variant}: normal orders {metrics["normal_orders_load_phase"]["success_within_deadline"]}/'
          f'{metrics["normal_orders_load_phase"]["planned"]}, audit={audit_ok}')
    return {'rows': rows, 'events': events, 'state': state, 'initial_run_id': initial['run_id'],
            'order_audit_ok': audit_ok, 'metrics': metrics, 'evidence': evidence}


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', type=local_base_url, default=ADMIN_BASE_URL)
    parser.add_argument('--seconds', type=int, default=10)
    parser.add_argument('--cancel-after-ms', type=int, default=50)
    parser.add_argument('--kind', choices=('report', 'products'), default='report')
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--arrival', choices=ARRIVALS, default='periodic')
    parser.add_argument('--report-rounds', type=int, default=REPORT_ROUNDS)
    parser.add_argument('--mode', choices=('off', 'fixed', 'adaptive'), default='off')
    parser.add_argument('--fixed-limit', type=int, default=2)
    parser.add_argument('--round-order', choices=('wait-first', 'cancel-first'), default='wait-first')
    parser.add_argument('--label', default='')
    args = parser.parse_args(argv)
    if not (3 <= args.seconds <= 30 and 20 <= args.cancel_after_ms <= 1000
            and 1 <= args.report_rounds <= 100 and 1 <= args.fixed_limit <= 3):
        parser.error('Bounds: seconds=3..30; cancel-after-ms=20..1000; '
                     'report-rounds=1..100; fixed-limit=1..3. Request counts are fixed.')
    return parser, args


def main() -> None:
    parser, args = parse_arguments()
    token_file = Path(os.environ.get('APP_RUNTIME_DIR', str(ROOT / 'runtime'))) / 'admin.token'
    if not token_file.exists():
        parser.error('Start the bundled server first: python server.py')
    token = token_file.read_text(encoding='utf-8').strip()
    try:
        status, health, _ = call('GET', '/health', base_url=args.base_url)
        if status != 200 or health.get('lab_id') != LAB_ID:
            raise RuntimeError('Target is not the bundled local lab.')
        metadata = admin('/lab/metadata', token)
        admin('/lab/events', token)
        prefix = uuid.uuid4().hex
        schedule = make_probe_schedule(args.seconds, args.kind, args.seed, args.arrival)
        out = ROOT / 'results' / f'cancellation-{time.strftime("%Y%m%d-%H%M%S")}-{prefix[:8]}'
        out.mkdir(parents=True)
        schedule_json = json.dumps(schedule, indent=2)
        (out / 'schedule.json').write_text(schedule_json, encoding='utf-8')
        metadata.update(experiment_type='cancellation_probe', base_url=args.base_url,
                        admin_base_url=ADMIN_BASE_URL, label=args.label, kind=args.kind,
                        seconds=args.seconds, cancel_after_ms=args.cancel_after_ms,
                        seed=args.seed, arrival=args.arrival, arrival_window_s=ARRIVAL_WINDOW_S,
                        probe_rate_per_s=2, normal_order_rate_per_s=1, max_inflight=MAX_INFLIGHT,
                        report_rounds=args.report_rounds, mode=args.mode, fixed_limit=args.fixed_limit,
                        variants=['wait', 'cancel'] if args.round_order == 'wait-first' else ['cancel', 'wait'],
                        round_order=args.round_order,
                        gateway_state_shared_between_rounds=args.base_url != ADMIN_BASE_URL,
                        warmup_requests=['products', args.kind],
                        warmup_notice='Two cache-warming requests do not establish completed Envoy minRTT estimation.',
                        reset_settle_s=RESET_SETTLE_S,
                        schedule_sha256=hashlib.sha256(schedule_json.encode()).hexdigest(),
                        platform=platform.platform(), timer_starts='after TCP connect, before HTTP request',
                        source_sha256={name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                       for name in ('server.py', 'database.py', 'postgres_database.py',
                                                    'cancellation.py', 'experiment.py', 'cancellation_probe.py',
                                                    'workload.py', 'event_analysis.py')})
        write_json(out / 'metadata.json', metadata)
        runs = {variant: run_round(args, variant, schedule, token, out / variant)
                for variant in metadata['variants']}
        wait_run, cancel_run = runs['wait'], runs['cancel']
        result = classify_observation(wait_run, cancel_run, args.kind)
        result.update(experiment_type='cancellation_probe', label=args.label,
                      normal_orders={name: run['metrics']['normal_orders_load_phase']
                                     for name, run in (('wait', wait_run), ('cancel', cancel_run))})
        write_json(out / 'summary.json', result)
        print(f'{result["status"]}: {result["reason"]}\n{out}')
    except KeyboardInterrupt:
        parser.exit(130, 'Stopped. Wait for the backend to drain before another run.\n')
    except (OSError, RuntimeError, ValueError, http.client.HTTPException) as exc:
        parser.exit(1, f'Probe stopped: {exc}\n')


if __name__ == '__main__':
    main()
