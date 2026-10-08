"""Finite real-socket security checks for the dedicated local 18090 gateway."""
from __future__ import annotations

import argparse
import base64
import gzip
import http.client
import io
import json
import socket
import time
from contextlib import nullcontext
from pathlib import Path
from urllib.parse import urlsplit

from security_fixture import CLEAN_HEADERS, FAKE_PRIVATE_KEY, FAKE_TOKEN, FIXTURE_ID, MARKER, OwnedFixture

ORIGIN = 'http://127.0.0.1:18102'
GATEWAY = 'http://127.0.0.1:18090'
MAX_WIRE_BYTES = 128 * 1024
REQUEST_TIMEOUT = 3
BLOCKED_PATHS = ('/.env', '/.git/config', '/%2eenv', '/%252eenv', '/%61dmin',
                 '/public/../admin', '/admin;foo', '/admin%2fexport', '/admin', '/public/%2e%2e%20/admin')
GUARD_ALIASES = ('/%61pi/token', '/api;v=1/token', '/API/token')
SECRET_PATHS = ('/api/private-key', '/api/token', '/api/split-secret', '/api/oversize',
                '/api/gzip', '/api/binary', '/api/cookie-private', '/api/partial206',
                '/api/trailers', '/api/chunked-oversize')


def local_endpoint(value, required_port):
    parsed = urlsplit(value)
    if (parsed.scheme != 'http' or parsed.hostname not in ('127.0.0.1', 'localhost')
            or parsed.port != required_port or parsed.username or parsed.password
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
        raise ValueError(f'Only http://127.0.0.1:{required_port} is allowed')
    return '127.0.0.1', required_port


class MemorySocket:
    def __init__(self, raw):
        self.raw = raw

    def makefile(self, *_):
        return io.BytesIO(self.raw)


def wire_request(endpoint, method, path, headers=None, body=b''):
    host, port = endpoint
    if host != '127.0.0.1' or port not in (18090, 18102):
        raise ValueError('Only the dedicated local security fixture and gateway are allowed')
    if method not in ('GET', 'POST', 'PUT', 'OPTIONS', 'HEAD', 'TRACE') or not path.startswith('/'):
        raise ValueError('Unsupported finite test request')
    request_headers = {'Host': f'{host}:{port}', 'Connection': 'close', **(headers or {})}
    if body or method in ('POST', 'PUT'):
        request_headers['Content-Length'] = str(len(body))
    head = f'{method} {path} HTTP/1.1\r\n' + ''.join(f'{key}: {value}\r\n' for key, value in request_headers.items())
    payload = (head + '\r\n').encode('ascii') + body
    raw = bytearray()
    started = time.monotonic()
    record = {'method': method, 'path': path, 'request_headers': request_headers,
              'request_body_base64': base64.b64encode(body).decode(), 'status': None,
              'complete': False, 'error': None, 'first_byte_ms': None}
    eof = False
    try:
        with socket.create_connection(endpoint, timeout=REQUEST_TIMEOUT) as connection:
            connection.sendall(payload)
            while len(raw) <= MAX_WIRE_BYTES:
                remaining = REQUEST_TIMEOUT - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError('Per-request three-second deadline exceeded')
                connection.settimeout(remaining)
                chunk = connection.recv(min(8192, MAX_WIRE_BYTES + 1 - len(raw)))
                if not chunk:
                    eof = True
                    break
                if record['first_byte_ms'] is None:
                    record['first_byte_ms'] = round((time.monotonic() - started) * 1000, 3)
                raw.extend(chunk)
            if len(raw) > MAX_WIRE_BYTES:
                record['error'] = 'Response exceeded the bounded wire capture limit'
    except (OSError, TimeoutError) as error:
        record['error'] = f'{type(error).__name__}: {error}'
    record['elapsed_ms'] = round((time.monotonic() - started) * 1000, 3)
    record['wire_bytes'] = len(raw)
    record['wire_base64'] = base64.b64encode(raw).decode()
    record['wire_text'] = raw.decode('utf-8', errors='replace')
    record['headers'] = []
    decoded = b''
    try:
        response = http.client.HTTPResponse(MemorySocket(bytes(raw)), method=method)
        response.begin()
        record['status'] = response.status
        record['headers'] = response.getheaders()
        decoded = response.read()
        record['complete'] = eof and record['error'] is None and len(decoded) <= MAX_WIRE_BYTES
        if response.getheader('Content-Encoding', '').lower() == 'gzip':
            with gzip.GzipFile(fileobj=io.BytesIO(decoded)) as stream:
                decoded = stream.read(MAX_WIRE_BYTES + 1)
            if len(decoded) > MAX_WIRE_BYTES:
                raise ValueError('Decoded response exceeds capture limit')
        record['body_text'] = decoded.decode('utf-8', errors='replace')
        record['body_bytes'] = len(decoded)
        try:
            record['json'] = json.loads(decoded)
        except (ValueError, UnicodeDecodeError):
            pass
    except (http.client.HTTPException, OSError, EOFError, ValueError) as error:
        record['parse_error'] = f'{type(error).__name__}: {error}'
        record['complete'] = False
    probes = {'fake_token': FAKE_TOKEN.encode(), 'private_key_marker': b'-----BEGIN PRIVATE KEY-----',
              'fake_private_key_payload': FAKE_PRIVATE_KEY.splitlines()[1].encode()}
    record['leaked_fake_markers'] = [name for name, marker in probes.items() if marker in raw or marker in decoded]
    return record


def origin_state(origin):
    result = wire_request(origin, 'GET', '/fixture/state')
    state = result.get('json', {})
    if not result['complete'] or result['status'] != 200 or state.get('fixture') != FIXTURE_ID:
        raise RuntimeError(f'Independent security fixture is unavailable: {result.get("error") or result["status"]}')
    return state


def run_case(origin, gateway, name, method, path, expected, headers=None, body=b'', expected_status=None,
             expected_origin_path=None):
    before = origin_state(origin)
    response = wire_request(gateway, method, path, headers, body)
    after = origin_state(origin)
    delta = after['total_calls'] - before['total_calls']
    expected_calls = 0 if expected == 'request_blocked' else 1
    observed_calls = after['calls'][-max(delta, 0):] if delta > 0 else []
    actual_origin_match = delta == expected_calls
    if expected_calls:
        actual_origin_match = actual_origin_match and observed_calls == [
            {'method': method, 'path': expected_origin_path or path}]
    if expected == 'request_blocked':
        response_match = response['status'] in (400, 403, 404, 405)
    elif expected == 'response_blocked':
        response_match = response['status'] is not None and 400 <= response['status'] <= 599
    else:
        response_match = response['status'] == 200
        if method != 'HEAD':
            response_match = response_match and response.get('json', {}).get('marker') == MARKER
        if path == '/api/clean':
            expected_headers = {**CLEAN_HEADERS, 'referrer-policy': 'no-referrer'}
            actual_headers = {key.lower(): value for key, value in response['headers']}
            response['required_clean_headers'] = expected_headers
            response['clean_headers_preserved'] = all(actual_headers.get(key) == value
                                                       for key, value in expected_headers.items())
            response_match = response_match and response['clean_headers_preserved']
        if method == 'HEAD':
            response_match = response_match and response.get('body_bytes') == 0
    if expected_status is not None:
        response_match = response_match and response['status'] == expected_status
    no_leak = not response['leaked_fake_markers'] if expected in ('response_blocked', 'request_blocked') else True
    passed = response['complete'] and response_match and actual_origin_match and no_leak
    return {'name': name, 'passed': passed, 'expected': expected, 'expected_status': expected_status,
            'expected_origin_calls': expected_calls, 'expected_origin_path': expected_origin_path or path,
            'origin_calls_delta': delta, 'origin_calls': observed_calls,
            'origin_before': {'total_calls': before['total_calls'], 'dropped_calls': before['dropped_calls']},
            'origin_after': {'total_calls': after['total_calls'], 'dropped_calls': after['dropped_calls']},
            'response': response}


def verify(origin_url=ORIGIN, gateway_url=GATEWAY, suite='all', admin_expect='deny'):
    origin = local_endpoint(origin_url, 18102)
    gateway = local_endpoint(gateway_url, 18090)
    cases = []

    def check(name, method, path, expected, **kwargs):
        cases.append(run_case(origin, gateway, name, method, path, expected, **kwargs))

    if suite in ('request', 'all'):
        for index, path in enumerate(BLOCKED_PATHS):
            check(f'sensitive_path_{index + 1}', 'GET', path, 'request_blocked')
        for index, path in enumerate(GUARD_ALIASES):
            if path == '/%61pi/token':
                check(f'guard_alias_{index + 1}', 'GET', path, 'response_blocked',
                      expected_origin_path='/api/token')
            else:
                check(f'guard_alias_{index + 1}', 'GET', path, 'request_blocked', expected_status=403)
        check('trace_blocked', 'TRACE', '/trace-target', 'request_blocked')
        check('spoofed_allowlisted_ip_does_not_grant_admin', 'GET', '/admin', 'request_blocked',
              headers={'X-Forwarded-For': '203.0.113.10', 'X-Real-IP': '203.0.113.10',
                       'Forwarded': 'for=203.0.113.10'})
        for index, path in enumerate(('/.well-known/acme-challenge/token', '/environment', '/administrator')):
            check(f'ordinary_path_{index + 1}', 'GET', path, 'allowed')
        for method in ('GET', 'POST', 'PUT', 'OPTIONS', 'HEAD'):
            check(f'ordinary_method_{method.lower()}', method, '/method-check', 'allowed',
                  body=b'{"fixture":"safe"}' if method in ('POST', 'PUT') else b'',
                  headers={'Content-Type': 'application/json'})
    if suite in ('response', 'all'):
        check('clean_api_response', 'GET', '/api/clean', 'allowed')
        check('clean_head_api_response', 'HEAD', '/api/clean', 'allowed')
        for path in SECRET_PATHS:
            check(path.rsplit('/', 1)[-1], 'GET', path, 'response_blocked',
                  headers={'TE': 'trailers', 'Connection': 'close, TE'} if path == '/api/trailers' else None)
        check('head_cookie_private', 'HEAD', '/api/cookie-private', 'response_blocked')
    if suite == 'allowlist':
        expected = 'allowed' if admin_expect == 'allow' else 'request_blocked'
        check('protected_path_actual_client_identity', 'GET', '/admin', expected)
        check('spoofed_forwarded_headers_do_not_change_identity', 'GET', '/admin', expected,
              headers={'X-Forwarded-For': '203.0.113.10', 'X-Real-IP': '203.0.113.10',
                       'Forwarded': 'for=203.0.113.10'})
    return {'schema_version': 1, 'suite': suite, 'origin': origin_url, 'gateway': gateway_url,
            'passed': bool(cases) and all(case['passed'] for case in cases), 'cases': cases,
            'executed_cases': len(cases), 'failed_cases': [case['name'] for case in cases if not case['passed']],
            'data_notice': 'Every secret value in this fixture and capture is deliberately fake.',
            'bounds': {'concurrency': 1, 'per_request_seconds': REQUEST_TIMEOUT,
                       'max_wire_bytes': MAX_WIRE_BYTES, 'maximum_gateway_requests': 36},
            'required_profile': {'mode': 'enforce', 'sensitive_paths_blocked': True,
                                 'protected_admin_allowlist': '203.0.113.10/32' if admin_expect == 'deny'
                                 else 'The actual gateway downstream socket client address CIDR',
                                 'dlp_route_prefix': '/api', 'dlp_max_response_bytes': 65536,
                                 'dlp_streaming': False, 'trusted_proxy_cidrs': [],
                                 'rate_limits': 'High enough not to reject this small sequential suite'},
            'limitations': ['No live credentials, external destinations, load, or Docker operations.',
                            'No observe-mode claim; this verifier requires the stated enforce profile.',
                            'Origin deltas require no concurrent traffic to this dedicated fixture.',
                            'This finite matrix does not establish coverage of every encoding or secret type.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--origin', default=ORIGIN)
    parser.add_argument('--gateway', default=GATEWAY)
    parser.add_argument('--suite', choices=('request', 'response', 'all', 'allowlist'), default='all')
    parser.add_argument('--admin-expect', choices=('allow', 'deny'), default='deny')
    parser.add_argument('--own-fixture', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    local_endpoint(args.origin, 18102)
    local_endpoint(args.gateway, 18090)
    report = {'schema_version': 1, 'passed': False, 'suite': args.suite}
    try:
        with OwnedFixture() if args.own_fixture else nullcontext():
            report = verify(args.origin, args.gateway, args.suite, args.admin_expect)
    except (OSError, RuntimeError, ValueError) as error:
        report['error'] = f'{type(error).__name__}: {error}'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + '\n')
    print(json.dumps({'passed': report['passed'], 'executed_cases': report.get('executed_cases', 0),
                      'failed_cases': report.get('failed_cases', []), 'output': str(args.output)}, ensure_ascii=False))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
