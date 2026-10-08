"""Bounded loopback verification of a real origin and a separately managed gateway."""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import random
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext
from pathlib import Path
from urllib.parse import quote, urlsplit

from fixture import BODY_LIMIT, HOST, PORTS, RANGE_BODY, SSE_DELAY_SECONDS, OwnedFixture, frame, read_frame

GATEWAY_PORT = 18088
ALLOWED_PORTS = (*PORTS, GATEWAY_PORT)
MAX_INFLIGHT = 32
TIMEOUT = 3.5
ORDER_DEADLINE_MS = 300


def local_url(value):
    parsed = urlsplit(value)
    if (parsed.scheme != 'http' or parsed.hostname != HOST or parsed.port not in ALLOWED_PORTS
            or parsed.username or parsed.password or parsed.path not in ('', '/')
            or parsed.query or parsed.fragment or parsed.netloc != f'{HOST}:{parsed.port}'):
        raise argparse.ArgumentTypeError('Only http://127.0.0.1:{18088,18100,18101} is permitted.')
    return f'http://{HOST}:{parsed.port}'


def request(base_url, method, path, body=None, headers=None):
    port = urlsplit(local_url(base_url)).port
    if not path.startswith('/') or path.startswith('//'):
        raise ValueError('Only origin-relative paths are permitted')
    raw_body = json.dumps(body).encode() if isinstance(body, dict) else (body or b'')
    if len(raw_body) > BODY_LIMIT:
        raise ValueError('Verification body exceeds the fixture limit')
    sent_headers = dict(headers or {})
    if isinstance(body, dict):
        sent_headers.setdefault('Content-Type', 'application/json')
    started = time.monotonic()
    record = {'method': method, 'path': path, 'request_headers': sent_headers,
              'request_body_bytes': len(raw_body), 'request_body_sha256': hashlib.sha256(raw_body).hexdigest(),
              'status': 0, 'response_headers': {}, 'body': '', 'error': None}
    connection = http.client.HTTPConnection(HOST, port, timeout=TIMEOUT)
    try:
        connection.request(method, path, body=raw_body or None, headers=sent_headers)
        response = connection.getresponse()
        data = response.read(BODY_LIMIT + 1)
        if len(data) > BODY_LIMIT:
            raise ValueError('Response exceeds bounded verifier size')
        record.update(status=response.status, response_headers=dict(response.getheaders()),
                      body=data.decode('utf-8', errors='replace'), response_body_hex=data.hex(),
                      response_body_bytes=len(data), response_body_sha256=hashlib.sha256(data).hexdigest())
        try:
            record['json'] = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            pass
    except (OSError, http.client.HTTPException, ValueError) as exc:
        record['error'] = f'{type(exc).__name__}: {exc}'
    finally:
        connection.close()
    record['elapsed_ms'] = round((time.monotonic() - started) * 1000, 3)
    return record


def header(record, name):
    return next((value for key, value in record['response_headers'].items() if key.lower() == name.lower()), None)


def sse_check(base_url):
    connection = http.client.HTTPConnection(HOST, urlsplit(local_url(base_url)).port, timeout=TIMEOUT)
    started = time.monotonic()
    try:
        connection.request('GET', '/events', headers={'Accept': 'text/event-stream'})
        response = connection.getresponse()
        first = bytearray()
        while len(first) < 4096 and not first.endswith(b'\n\n'):
            value = response.read(1)
            if not value:
                break
            first.extend(value)
        first_ms = (time.monotonic() - started) * 1000
        remaining = response.read(4096)
        total_ms = (time.monotonic() - started) * 1000
        passed = (response.status == 200 and b'event: first' in first and b'event: second' in remaining
                  and first_ms < SSE_DELAY_SECONDS * 750 and total_ms >= SSE_DELAY_SECONDS * 900)
        return {'name': 'sse_first_chunk', 'status': 'passed' if passed else 'failed',
                'http_status': response.status, 'first_chunk_ms': round(first_ms, 3),
                'complete_ms': round(total_ms, 3), 'server_delay_ms': SSE_DELAY_SECONDS * 1000,
                'first_chunk': first.decode(errors='replace'), 'remaining': remaining.decode(errors='replace')}
    finally:
        connection.close()


def websocket_check(base_url):
    port = urlsplit(local_url(base_url)).port
    key = base64.b64encode(b'siteguard-test16').decode()
    expected_accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
    started = time.monotonic()
    with socket.create_connection((HOST, port), timeout=TIMEOUT) as connection:
        connection.sendall((f'GET /ws HTTP/1.1\r\nHost: {HOST}:{port}\r\nUpgrade: websocket\r\n'
                            f'Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n'
                            'Sec-WebSocket-Version: 13\r\n\r\n').encode())
        stream = connection.makefile('rb')
        response = bytearray()
        while not response.endswith(b'\r\n\r\n') and len(response) < 8192:
            value = stream.read(1)
            if not value:
                break
            response.extend(value)
        handshake = response.decode('latin-1')
        if not handshake.startswith('HTTP/1.1 101') or expected_accept.lower() not in handshake.lower():
            return {'name': 'websocket_bidirectional_close', 'status': 'failed', 'handshake': handshake}
        checks = []
        for opcode, payload in ((1, '雙向 echo'.encode()), (2, b'\x00\xffbinary'), (9, b'ping'),
                                (8, struct.pack('!H', 1000) + b'normal close')):
            connection.sendall(frame(opcode, payload, mask=b'\x01\x02\x03\x04'))
            returned_opcode, returned_payload = read_frame(stream)
            checks.append({'sent_opcode': opcode, 'received_opcode': returned_opcode,
                           'bytes': len(payload), 'matches': returned_payload == payload
                           and returned_opcode == (10 if opcode == 9 else opcode)})
        stream.close()
        return {'name': 'websocket_bidirectional_close', 'status': 'passed' if all(row['matches'] for row in checks)
                else 'failed', 'handshake': handshake, 'frames': checks,
                'elapsed_ms': round((time.monotonic() - started) * 1000, 3)}


def http2_check(base_url):
    try:
        import h2.config
        import h2.connection
        import h2.events
        import h2.exceptions
    except ImportError:
        return {'name': 'http2_prior_knowledge', 'status': 'skipped',
                'reason': 'Optional h2 development dependency is unavailable; no HTTP/2 claim is made.'}
    port = urlsplit(local_url(base_url)).port
    if port in PORTS:
        return {'name': 'http2_prior_knowledge', 'status': 'skipped',
                'reason': 'The fixture origin speaks HTTP/1.1; this check targets the gateway listener.'}
    connection = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=True, header_encoding='utf-8'))
    result_headers, body = {}, bytearray()
    started = time.monotonic()
    with socket.create_connection((HOST, port), timeout=TIMEOUT) as transport:
        connection.initiate_connection()
        connection.send_headers(1, [(':method', 'GET'), (':scheme', 'http'), (':authority', f'{HOST}:{port}'),
                                    (':path', '/echo?protocol=h2')], end_stream=True)
        transport.sendall(connection.data_to_send())
        for _ in range(32):
            incoming = transport.recv(65536)
            if not incoming:
                break
            try:
                events = connection.receive_data(incoming)
            except h2.exceptions.ProtocolError as exc:
                return {'name': 'http2_prior_knowledge', 'status': 'failed', 'reason': str(exc)}
            for event in events:
                if isinstance(event, h2.events.ResponseReceived):
                    result_headers.update(event.headers)
                elif isinstance(event, h2.events.DataReceived):
                    body.extend(event.data)
                    connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    passed = result_headers.get(':status') == '200' and json.loads(body)['query'] == {'protocol': ['h2']}
                    return {'name': 'http2_prior_knowledge', 'status': 'passed' if passed else 'failed',
                            'headers': result_headers, 'body': body.decode(),
                            'elapsed_ms': round((time.monotonic() - started) * 1000, 3)}
            outgoing = connection.data_to_send()
            if outgoing:
                transport.sendall(outgoing)
            if len(body) > BODY_LIMIT:
                break
    return {'name': 'http2_prior_knowledge', 'status': 'failed', 'reason': 'No bounded complete HTTP/2 response'}


def connection_recovery_check(gateway_url, owned_fixture):
    if not isinstance(owned_fixture, OwnedFixture) or owned_fixture.server is None:
        raise ValueError('TCP outage testing requires the fixture owned by this verifier')
    gateway_url = local_url(gateway_url)
    if urlsplit(gateway_url).port != GATEWAY_PORT:
        raise ValueError('TCP outage testing targets the dedicated gateway port 18088')
    owned_fixture.stop()
    try:
        failed = request(gateway_url, 'GET', '/health')
    finally:
        owned_fixture.start()
    recovery_attempts = []
    for _ in range(20):
        recovered = request(gateway_url, 'GET', '/health')
        recovery_attempts.append(recovered)
        if recovered['status'] == 200:
            break
        time.sleep(.1)
    passed = (failed['status'] in (502, 503, 504) and recovered['status'] == 200
              and recovered.get('json', {}).get('fixture') == 'siteguard-loopback-v1')
    return {'name': 'origin_connection_refusal_recovery', 'status': 'passed' if passed else 'failed',
            'unavailable_request': failed, 'recovery_attempts': recovery_attempts}


def functional_suite(base_url, fixture_url):
    base_url, fixture_url = local_url(base_url), local_url(fixture_url)
    if urlsplit(fixture_url).port not in PORTS:
        raise ValueError('Fixture control must address a fixture port directly')
    checks = []

    def check(name, method, path, expected, body=None, headers=None):
        record = request(base_url, method, path, body, headers)
        try:
            passed = bool(expected(record))
        except (KeyError, TypeError, ValueError):
            passed = False
        checks.append({'name': name, 'status': 'passed' if passed else 'failed', 'request': record})

    check('html_utf8', 'GET', '/', lambda row: row['status'] == 200 and '正常頁面' in row['body'])
    check('head_semantics', 'HEAD', '/', lambda row: row['status'] == 200 and not row['body']
          and int(header(row, 'Content-Length')) > 0)
    check('query_unicode_cookies_auth', 'GET', quote('/中文/頁面') + '?q=%E6%B8%AC%E8%A9%A6&q=two&empty=',
          lambda row: row['status'] == 200 and row['json']['path'] == '/中文/頁面'
          and row['json']['query'] == {'q': ['測試', 'two'], 'empty': ['']}
          and row['json']['authorization'] == 'Bearer fixture-test-only'
          and row['json']['cookie'] == 'session=fixture; preference=zh'
          and 'fixture_cookie=ok' in header(row, 'Set-Cookie'),
          headers={'Authorization': 'Bearer fixture-test-only', 'Cookie': 'session=fixture; preference=zh'})
    check('form_post', 'POST', '/echo', lambda row: row['status'] == 200
          and row['json']['body'] == 'name=%E6%B8%AC%E8%A9%A6&value=one%2Btwo'
          and row['json']['content_type'] == 'application/x-www-form-urlencoded',
          b'name=%E6%B8%AC%E8%A9%A6&value=one%2Btwo', {'Content-Type': 'application/x-www-form-urlencoded'})
    check('json_post', 'POST', '/echo', lambda row: row['status'] == 200
          and json.loads(row['json']['body']) == {'message': '中文', 'quantity': 2},
          {'message': '中文', 'quantity': 2})
    check('redirect_location', 'GET', '/redirect', lambda row: row['status'] == 302
          and header(row, 'Location') == '/destination?from=redirect')
    check('cache_headers', 'GET', '/cache', lambda row: row['status'] == 200
          and header(row, 'ETag') == '"fixture-v1"' and header(row, 'Cache-Control') == 'public, max-age=60')
    check('conditional_304', 'GET', '/cache', lambda row: row['status'] == 304 and not row['body'],
          headers={'If-None-Match': '"fixture-v1"'})
    check('range_206', 'GET', '/range', lambda row: row['status'] == 206
          and row['response_body_hex'] == RANGE_BODY[100:200].hex()
          and header(row, 'Content-Range') == f'bytes 100-199/{len(RANGE_BODY)}',
          headers={'Range': 'bytes=100-199'})
    upload = bytes(range(256)) * 256
    boundary = 'siteguard-boundary-0123456789'
    multipart = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="fixture.bin"\r\n'
                 'Content-Type: application/octet-stream\r\n\r\n').encode() + upload + f'\r\n--{boundary}--\r\n'.encode()
    check('multipart_upload_64k', 'POST', '/upload', lambda row: row['status'] == 200
          and row['json']['parts'] == [{'name': 'file', 'filename': 'fixture.bin', 'size': len(upload),
                                       'sha256': hashlib.sha256(upload).hexdigest()}],
          multipart, {'Content-Type': f'multipart/form-data; boundary={boundary}'})
    check('not_found_404', 'GET', '/missing', lambda row: row['status'] == 404)
    for verifier in (sse_check, websocket_check, http2_check):
        try:
            checks.append(verifier(base_url))
        except (OSError, EOFError, ValueError, http.client.HTTPException) as exc:
            checks.append({'name': verifier.__name__, 'status': 'failed', 'error': str(exc)})
    try:
        control = request(fixture_url, 'POST', '/fixture/availability', {'available': False})
        if control['status'] != 200:
            raise RuntimeError('Cannot control owned fixture availability')
        check('origin_503_passthrough', 'GET', '/health', lambda row: row['status'] == 503)
    finally:
        request(fixture_url, 'POST', '/fixture/availability', {'available': True})
    check('origin_503_recovery', 'GET', '/health', lambda row: row['status'] == 200
          and row['json'].get('fixture') == 'siteguard-loopback-v1')
    return {'schema_version': 1, 'suite': 'http_compatibility', 'base_url': base_url,
            'passed': all(check['status'] in ('passed', 'skipped') for check in checks), 'checks': checks,
            'limitations': ['Fixture coverage is a finite compatibility sample, not proof of support for most websites.',
                            'Origin outage checks cover a returned HTTP 503; connection refusal is a separate check.',
                            'The HTTP/2 check uses cleartext prior knowledge; TLS/ALPN is not exercised.',
                            'WebSocket test covers unfragmented text/binary, ping/pong and a normal close.']}


def make_load_schedule(seconds=6, seed=42):
    if not 3 <= seconds <= 10:
        raise ValueError('Each load batch must last 3..10 seconds')
    rng = random.Random(seed)
    schedule = []
    for index in range(seconds * 16):
        schedule.append({'offset_s': round(.01 + index / 16, 6), 'kind': 'heavy'})
    for index in range(seconds * 4):
        schedule.append({'offset_s': round(.03 + index / 4 + rng.uniform(0, .015), 6), 'kind': 'orders'})
    schedule.sort(key=lambda row: row['offset_s'])
    for index, row in enumerate(schedule):
        row['request_id'] = hashlib.sha256(f'siteguard:{seed}:{index}'.encode()).hexdigest()[:24]
    return schedule


def drain_fixture(fixture_url):
    for _ in range(40):
        state = request(fixture_url, 'GET', '/fixture/state')
        if state['status'] == 200 and state['json']['outstanding'] == 0:
            return state['json']
        time.sleep(.1)
    raise RuntimeError('Owned fixture did not drain within four seconds')


def load_run(base_url, fixture_url, schedule):
    base_url, fixture_url = local_url(base_url), local_url(fixture_url)
    if urlsplit(fixture_url).port not in PORTS:
        raise ValueError('Fixture control must address a fixture port directly')
    if len(schedule) > 200 or any(row['offset_s'] < 0 or row['offset_s'] >= 10 for row in schedule):
        raise ValueError('Schedule exceeds the fixed local batch bounds')
    drain_fixture(fixture_url)
    if request(fixture_url, 'POST', '/fixture/reset', {})['status'] != 200:
        raise RuntimeError('Fixture reset failed')
    started = time.monotonic()

    def issue(item):
        path = '/orders' if item['kind'] == 'orders' else '/heavy'
        record = request(base_url, 'POST' if item['kind'] == 'orders' else 'GET', path,
                         {'request_id': item['request_id']} if item['kind'] == 'orders' else None,
                         {'X-Request-ID': item['request_id']})
        record.update(item, issued=True, scheduled_latency_ms=round(
            (time.monotonic() - started - item['offset_s']) * 1000, 3))
        return record

    records, pending = [], set()
    with ThreadPoolExecutor(max_workers=MAX_INFLIGHT) as pool:
        for item in schedule:
            delay = started + item['offset_s'] - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            done = {future for future in pending if future.done()}
            records.extend(future.result() for future in done)
            pending -= done
            lag = time.monotonic() - started - item['offset_s']
            if len(pending) >= MAX_INFLIGHT or lag > .1:
                records.append(dict(item, issued=False, status=0, error='generator_drop',
                                    scheduled_latency_ms=None))
            else:
                pending.add(pool.submit(issue, item))
        records.extend(future.result() for future in pending)
    records.sort(key=lambda row: row['offset_s'])
    state = drain_fixture(fixture_url)
    planned = [row for row in records if row['kind'] == 'orders']
    successful = [row for row in planned if row.get('json', {}).get('order_id') == row['request_id']
                  and row['status'] == 200 and row['json'].get('ok') is True
                  and row['json'].get('persisted') is True]
    on_time = [row for row in successful if row['scheduled_latency_ms'] <= ORDER_DEADLINE_MS]
    duplicates = {key: count for key, count in state['post_attempts'].items() if count > 1}
    expected_ids = {row['request_id'] for row in planned if row['issued']}
    unexpected_ids = set(state['orders']) - expected_ids
    unexpected_attempts = set(state['post_attempts']) - expected_ids
    missing_commits = {row['request_id'] for row in successful} - set(state['orders'])
    return {'schema_version': 1, 'suite': 'bounded_overload', 'base_url': base_url,
            'schedule_sha256': hashlib.sha256(json.dumps(schedule, sort_keys=True).encode()).hexdigest(),
            'max_inflight': MAX_INFLIGHT, 'order_deadline_ms': ORDER_DEADLINE_MS,
            'planned_orders': len(planned), 'successful_orders': len(successful),
            'acknowledged_orders': len(successful), 'committed_orders': len(state['orders']),
            'received_post_attempts': sum(state['post_attempts'].values()),
            'executed_post_attempts': sum(state['post_executions'].values()),
            'on_time_orders': len(on_time), 'order_completion_rate': len(on_time) / len(planned) if planned else None,
            'generator_drops': sum(not row['issued'] for row in records),
            'duplicate_post_attempts': duplicates, 'unexpected_order_ids': sorted(unexpected_ids),
            'missing_committed_orders': sorted(missing_commits),
            'unexpected_post_attempt_ids': sorted(unexpected_attempts),
            'audit_ok': not (duplicates or unexpected_ids or missing_commits or unexpected_attempts),
            'requests': records, 'origin_state': state}


def load_comparison(gateway_url, fixture_url, seconds=6, seed=42, gateway_first=False):
    gateway_url, fixture_url = local_url(gateway_url), local_url(fixture_url)
    if urlsplit(gateway_url).port != GATEWAY_PORT:
        raise ValueError('The protected comparison must address the dedicated gateway port 18088')
    schedule = make_load_schedule(seconds, seed)
    runs = {}
    order = ('gateway', 'direct') if gateway_first else ('direct', 'gateway')
    for name in order:
        runs[name] = load_run(gateway_url if name == 'gateway' else fixture_url, fixture_url, schedule)
    direct, gateway = runs['direct'], runs['gateway']
    valid = (all(run['audit_ok'] and not run['generator_drops'] for run in runs.values())
             and direct['schedule_sha256'] == gateway['schedule_sha256'])
    gain = 100 * (gateway['order_completion_rate'] - direct['order_completion_rate'])
    return {'schema_version': 1, 'suite': 'bounded_overload_comparison', 'seed': seed, 'seconds': seconds,
            'run_order': list(order), 'schedule': schedule, 'runs': runs,
            'valid_comparison': valid, 'order_gain_percentage_points': round(gain, 3),
            'business_benefit_observed': valid and gain > 0,
            'limitations': ['One paired synthetic workload is not proof of general protection effectiveness.',
                            'The heavy endpoint consumes CPU on a shared four-worker fixture pool.',
                            'Rejected and generator-dropped requests remain in planned-request denominators.',
                            'The 300 ms order deadline is a fixture criterion, not a universal service SLO.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', type=local_url, default=f'http://{HOST}:{GATEWAY_PORT}')
    parser.add_argument('--fixture-url', type=local_url, default=f'http://{HOST}:18100')
    parser.add_argument('--suite', choices=('functional', 'load', 'all'), default='functional')
    parser.add_argument('--seconds', type=int, default=6)
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--gateway-first', action='store_true')
    parser.add_argument('--own-fixture', action='store_true',
                        help='Start/stop only the dedicated fixture owned by this invocation; enables TCP outage checks.')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not 3 <= args.seconds <= 10:
        parser.error('seconds must be 3..10; inflight and request rates are fixed')
    result = {'schema_version': 1, 'base_url': args.base_url, 'fixture_url': args.fixture_url}
    fixture_port = urlsplit(args.fixture_url).port
    if fixture_port not in PORTS:
        parser.error('fixture-url must use port 18100 or 18101')
    with OwnedFixture(fixture_port) if args.own_fixture else nullcontext() as owned_fixture:
        if args.suite in ('functional', 'all'):
            result['functional'] = functional_suite(args.base_url, args.fixture_url)
            if owned_fixture and urlsplit(args.base_url).port == GATEWAY_PORT:
                check = connection_recovery_check(args.base_url, owned_fixture)
                result['functional']['checks'].append(check)
                result['functional']['passed'] &= check['status'] == 'passed'
        if args.suite in ('load', 'all'):
            result['load'] = load_comparison(args.base_url, args.fixture_url, args.seconds, args.seed, args.gateway_first)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(args.output)
    if 'functional' in result and not result['functional']['passed']:
        raise SystemExit(1)
    if 'load' in result and not result['load']['valid_comparison']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
