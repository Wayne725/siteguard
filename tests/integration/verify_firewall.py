"""Bounded loopback checks for firewall enforcement, allowlists, and shadow mode."""
from __future__ import annotations

import argparse
import base64
import http.client
import json
import socket
import time
from contextlib import nullcontext
from pathlib import Path

from security_fixture import FAKE_TOKEN, MARKER, OwnedFixture
from verify_incident_prevention import MAX_WIRE_BYTES, MemorySocket, REQUEST_TIMEOUT, origin_state

GATEWAY = ('127.0.0.1', 18090)
ORIGIN = ('127.0.0.1', 18102)
PHASES = ('deny', 'allow', 'observe', 'deny-all')
FIRST_EVENT = b'data: {"marker":"first"}\n\n'
LAST_EVENT = b'data: {"marker":"last"}\n\n'
UPGRADE_HEADERS = {'Connection': 'close, Upgrade', 'Upgrade': 'websocket',
                   'Sec-WebSocket-Key': base64.b64encode(b'firewall-test-16').decode(),
                   'Sec-WebSocket-Version': '13'}


def partial_body(raw):
    head, separator, body = raw.partition(b'\r\n\r\n')
    if not separator:
        return b''
    header_lines = head.lower().split(b'\r\n')[1:]
    chunked = any(line.split(b':', 1)[0] == b'transfer-encoding' and b'chunked' in line
                  for line in header_lines)
    if not chunked:
        return bytes(body)
    pieces = []
    cursor = 0
    while cursor < len(body):
        end_line = body.find(b'\r\n', cursor)
        if end_line < 0:
            break
        try:
            length = int(body[cursor:end_line].split(b';', 1)[0], 16)
        except ValueError:
            break
        if length <= 0:
            break
        start = end_line + 2
        pieces.append(body[start:start + length])
        cursor = start + length
        if len(body) < cursor + 2 or body[cursor:cursor + 2] != b'\r\n':
            break
        cursor += 2
    return b''.join(pieces)


def firewall_request(endpoint, method, path, headers=None, body=b''):
    if endpoint not in (GATEWAY, ORIGIN) or method not in ('GET', 'POST', 'HEAD', 'OPTIONS'):
        raise ValueError('Only fixed methods on dedicated local security endpoints are permitted')
    if not path.startswith('/') and not (method == 'OPTIONS' and path == '*'):
        raise ValueError('Only origin-form targets and OPTIONS * are permitted')
    request_headers = {'Host': f'{endpoint[0]}:{endpoint[1]}', 'Connection': 'close', **(headers or {})}
    if method == 'POST':
        request_headers.update({'Content-Length': str(len(body)), 'Content-Type': 'application/json'})
    payload = (f'{method} {path} HTTP/1.1\r\n'
               + ''.join(f'{name}: {value}\r\n' for name, value in request_headers.items()) + '\r\n').encode() + body
    record = {'method': method, 'path': path, 'request_headers': request_headers,
              'request_body_base64': base64.b64encode(body).decode(), 'status': None, 'headers': [],
              'complete': False, 'error': None, 'first_event_ms': None, 'last_event_ms': None}
    started = time.monotonic()
    raw = bytearray()
    eof = False
    try:
        with socket.create_connection(endpoint, timeout=REQUEST_TIMEOUT) as connection:
            connection.sendall(payload)
            while len(raw) <= MAX_WIRE_BYTES:
                remaining = REQUEST_TIMEOUT - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError('Per-request three-second deadline exceeded')
                connection.settimeout(remaining)
                data = connection.recv(min(8192, MAX_WIRE_BYTES + 1 - len(raw)))
                if not data:
                    eof = True
                    break
                raw.extend(data)
                if path == '/events':
                    decoded = partial_body(raw)
                    for name, marker in (('first_event_ms', FIRST_EVENT), ('last_event_ms', LAST_EVENT)):
                        if record[name] is None and marker in decoded:
                            record[name] = round((time.monotonic() - started) * 1000, 3)
            if len(raw) > MAX_WIRE_BYTES:
                raise ValueError('Response exceeds the bounded wire capture limit')
    except (OSError, ValueError) as error:
        record['error'] = f'{type(error).__name__}: {error}'
    record.update({'elapsed_ms': round((time.monotonic() - started) * 1000, 3),
                   'wire_bytes': len(raw), 'wire_base64': base64.b64encode(raw).decode(),
                   'wire_text': raw.decode('utf-8', errors='replace')})
    try:
        response = http.client.HTTPResponse(MemorySocket(bytes(raw)), method=method)
        response.begin()
        record['status'] = response.status
        record['headers'] = response.getheaders()
        decoded = response.read()
        record['body_bytes'] = len(decoded)
        record['body_text'] = decoded.decode('utf-8', errors='replace')
        record['complete'] = eof and record['error'] is None
        try:
            record['json'] = json.loads(decoded)
        except (ValueError, UnicodeDecodeError):
            pass
    except (http.client.HTTPException, OSError, EOFError, ValueError) as error:
        record['parse_error'] = f'{type(error).__name__}: {error}'
    record['unexpected_fake_secret'] = FAKE_TOKEN.encode() in raw or b'-----BEGIN PRIVATE KEY-----' in raw
    return record


def collect_case(origin, gateway, name, method, path, denied, headers=None, body=b''):
    before = origin_state(origin)
    response = firewall_request(gateway, method, path, headers, body)
    after = origin_state(origin)
    delta = after['total_calls'] - before['total_calls']
    calls = after['calls'][-delta:] if delta > 0 else []
    expected_calls = [] if denied else [{'method': method, 'path': path}]
    asterisk_rejection = denied and method == 'OPTIONS' and path == '*'
    accepted_statuses = (403, 404) if asterisk_rejection else (403,) if denied else (200,)
    checks = {'response_complete': response['complete'],
              'exact_origin_calls': delta == (0 if denied else 1) and calls == expected_calls,
              'expected_status': response['status'] in accepted_statuses,
              'no_secret': not response['unexpected_fake_secret']}
    if not denied:
        if method == 'HEAD':
            checks['head_has_no_body'] = response.get('body_bytes') == 0
            checks['origin_marker_header'] = dict((key.lower(), value) for key, value in response['headers']).get(
                'x-fixture-marker') == MARKER
        elif path == '/events':
            received_headers = {key.lower(): value for key, value in response['headers']}
            checks['sse_content_type'] = received_headers.get('content-type', '').startswith('text/event-stream')
            first, last = response['first_event_ms'], response['last_event_ms']
            checks['first_event_precedes_last'] = first is not None and last is not None and first + 50 <= last
            checks['first_event_within_deadline'] = first is not None and first < 1500
            checks['both_fixture_events_received'] = (FIRST_EVENT.decode() in response.get('body_text', '')
                                                      and LAST_EVENT.decode() in response.get('body_text', ''))
        else:
            checks['origin_marker_body'] = response.get('json', {}).get('marker') == MARKER
    return {'name': name, 'passed': all(checks.values()), 'checks': checks,
            'expected': ('no_origin_request_rejection' if asterisk_rejection else
                         '403_without_origin_call' if denied else '200_with_exactly_one_origin_call'),
            'origin_calls_delta': delta, 'origin_calls': calls,
            'origin_before_total': before['total_calls'], 'origin_after_total': after['total_calls'],
            'response': response}


def run_phase(phase, origin=ORIGIN, gateway=GATEWAY):
    if phase not in PHASES or origin != ORIGIN or gateway not in (ORIGIN, GATEWAY):
        raise ValueError('Only predefined phases and dedicated loopback endpoints are permitted')
    denied = phase in ('deny', 'deny-all')
    cases = []

    def check(name, method, path, headers=None):
        cases.append(collect_case(origin, gateway, name, method, path, denied, headers,
                                  body=b'{"fixture":"safe"}' if method == 'POST' else b''))

    for method in ('GET', 'HEAD', 'POST', 'OPTIONS'):
        check(f'normal_{method.lower()}', method, '/')
    check('sse_stream', 'GET', '/events')
    if denied:
        check('websocket_upgrade', 'GET', '/ws', UPGRADE_HEADERS)
        for index, headers in enumerate(({'X-Forwarded-For': '203.0.113.10'},
                                         {'X-Real-IP': '203.0.113.10'},
                                         {'Forwarded': 'for=203.0.113.10'})):
            check(f'forged_client_identity_{index + 1}', 'GET', '/', headers)
    if phase == 'deny-all':
        check('options_asterisk', 'OPTIONS', '*')
    return {'schema_version': 1, 'suite': 'firewall', 'phase': phase,
            'passed': bool(cases) and all(case['passed'] for case in cases), 'cases': cases,
            'executed_cases': len(cases), 'failed_cases': [case['name'] for case in cases if not case['passed']],
            'origin': f'http://{origin[0]}:{origin[1]}', 'gateway': f'http://{gateway[0]}:{gateway[1]}',
            'bounds': {'concurrency': 1, 'per_request_seconds': REQUEST_TIMEOUT,
                       'maximum_gateway_requests': 10, 'max_wire_bytes': MAX_WIRE_BYTES},
            'prerequisites': ['The selected firewall profile is already running on 18090.',
                              'Deny profiles reject the real downstream socket address; 203.0.113.10 is only a forged header value.',
                              'Allow permits the actual socket address; observe shadows a policy that would deny it.',
                              '/events is a streaming route; no concurrent traffic reaches the dedicated origin.',
                              'Admission limits permit all requests so unrelated rate limiting cannot mimic firewall decisions.'],
            'interpretation': ['Deny requires complete HTTP 403 and zero origin calls, including Upgrade.',
                               'OPTIONS * accepts complete 403 or 404 with zero origin calls; this proves non-forwarding, not a specific RBAC decision.',
                               'Allow and observe require HTTP 200, exact origin calls, and actual fixture markers.',
                               'The fixture emits SSE events 100 ms apart; the first must arrive at least 50 ms before the last.',
                               'Fake forwarded headers cannot demonstrate a real source address change.'],
            'limitations': ['Finite local protocol evidence, not a broad firewall or website compatibility certification.',
                            'No Docker changes, external requests, credentials, or load generation.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', choices=PHASES, required=True)
    parser.add_argument('--own-fixture', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    report = {'schema_version': 1, 'phase': args.phase, 'passed': False}
    try:
        with OwnedFixture() if args.own_fixture else nullcontext():
            report = run_phase(args.phase)
    except (OSError, RuntimeError, ValueError) as error:
        report['error'] = f'{type(error).__name__}: {error}'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
    print(json.dumps({'phase': args.phase, 'passed': report['passed'],
                      'executed_cases': report.get('executed_cases', 0),
                      'failed_cases': report.get('failed_cases', []), 'output': str(args.output)}, ensure_ascii=False))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
