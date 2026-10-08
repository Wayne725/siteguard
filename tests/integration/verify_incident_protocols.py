"""Finite local HTTP/2, response-header, and security failure-mode checks."""
from __future__ import annotations

import argparse
import base64
import json
import socket
import time
from contextlib import nullcontext
from pathlib import Path

from security_fixture import FAKE_PRIVATE_KEY, FAKE_TOKEN, MARKER, OwnedFixture
from verify_incident_prevention import MAX_WIRE_BYTES, REQUEST_TIMEOUT, origin_state, wire_request

GATEWAY = ('127.0.0.1', 18090)
ORIGIN = ('127.0.0.1', 18102)
PHASES = ('enforce', 'observe', 'scanner-down', 'canonical-broken')


def h2_request(endpoint, path):
    if endpoint not in (GATEWAY, ORIGIN):
        raise ValueError('HTTP/2 requests require a dedicated local security endpoint')
    started = time.monotonic()
    result = {'transport': 'http2_prior_knowledge', 'method': 'GET', 'path': path, 'stream_id': 1,
              'status': None, 'complete': False, 'error': None, 'headers': [], 'trailers': [], 'events': []}
    raw = bytearray()
    body = bytearray()
    try:
        import h2
        from h2.config import H2Configuration
        from h2.connection import H2Connection
        from h2.events import (ConnectionTerminated, DataReceived, ResponseReceived,
                               StreamEnded, StreamReset, TrailersReceived)
        from h2.exceptions import H2Error
    except ImportError as error:
        result['error'] = f'HTTP/2 development dependency unavailable: {error}'
        result['elapsed_ms'] = round((time.monotonic() - started) * 1000, 3)
        result['leaked_fake_markers'] = []
        return result
    result['h2_version'] = h2.__version__
    headers = [(':method', 'GET'), (':scheme', 'http'), (':authority', f'{endpoint[0]}:{endpoint[1]}'),
               (':path', path)]
    result['request_headers'] = headers
    protocol = H2Connection(config=H2Configuration(client_side=True, header_encoding='utf-8'))
    try:
        with socket.create_connection(endpoint, timeout=REQUEST_TIMEOUT) as connection:
            protocol.initiate_connection()
            protocol.send_headers(1, headers, end_stream=True)
            connection.sendall(protocol.data_to_send())
            while not result['complete']:
                remaining = REQUEST_TIMEOUT - (time.monotonic() - started)
                if remaining <= 0:
                    raise TimeoutError('Per-request three-second deadline exceeded')
                connection.settimeout(remaining)
                incoming = connection.recv(min(8192, MAX_WIRE_BYTES + 1 - len(raw)))
                if not incoming:
                    raise EOFError('HTTP/2 connection closed before stream completion')
                raw.extend(incoming)
                if len(raw) > MAX_WIRE_BYTES:
                    raise ValueError('HTTP/2 response exceeds bounded wire capture')
                for event in protocol.receive_data(incoming):
                    result['events'].append({'event': type(event).__name__,
                                             'stream_id': getattr(event, 'stream_id', None),
                                             'elapsed_ms': round((time.monotonic() - started) * 1000, 3)})
                    if getattr(event, 'stream_id', 1) != 1:
                        continue
                    if isinstance(event, ResponseReceived):
                        result['headers'] = event.headers
                        result['status'] = int(dict(event.headers)[':status'])
                    elif isinstance(event, DataReceived):
                        body.extend(event.data)
                        protocol.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, TrailersReceived):
                        result['trailers'] = event.headers
                    elif isinstance(event, StreamEnded):
                        result['complete'] = True
                    elif isinstance(event, (StreamReset, ConnectionTerminated)) and not result['complete']:
                        raise RuntimeError(f'{type(event).__name__} before completion: {event.error_code}')
                if len(body) > MAX_WIRE_BYTES:
                    raise ValueError('HTTP/2 decoded body exceeds capture limit')
                outgoing = protocol.data_to_send()
                if outgoing:
                    connection.sendall(outgoing)
    except (OSError, EOFError, RuntimeError, ValueError, H2Error) as error:
        result['error'] = f'{type(error).__name__}: {error}'
        result['complete'] = False
    result['elapsed_ms'] = round((time.monotonic() - started) * 1000, 3)
    result['wire_bytes'] = len(raw)
    result['wire_base64'] = base64.b64encode(raw).decode()
    result['body_bytes'] = len(body)
    result['body_base64'] = base64.b64encode(body).decode()
    result['body_text'] = body.decode('utf-8', errors='replace')
    try:
        result['json'] = json.loads(body)
    except (ValueError, UnicodeDecodeError):
        pass
    decoded_headers = json.dumps([result['headers'], result['trailers']]).encode()
    probes = {'fake_token': FAKE_TOKEN.encode(), 'private_key_marker': b'-----BEGIN PRIVATE KEY-----',
              'fake_private_key_payload': FAKE_PRIVATE_KEY.splitlines()[1].encode()}
    result['leaked_fake_markers'] = [name for name, marker in probes.items()
                                     if marker in raw or marker in body or marker in decoded_headers]
    return result


def collect_case(origin, gateway, name, path, expectation, method='GET', transport='http1', origin_calls=1,
                 security_headers=False, no_store=False, no_nosniff=False):
    before = origin_state(origin)
    response = h2_request(gateway, path) if transport == 'h2' else wire_request(gateway, method, path)
    after = origin_state(origin)
    delta = after['total_calls'] - before['total_calls']
    calls = after['calls'][-delta:] if delta > 0 else []
    headers = {key.lower(): value for key, value in response['headers']}
    checks = {'complete_response': response['complete'], 'origin_calls_exact': delta == origin_calls,
              'origin_path_and_method_match': calls == ([{'method': method, 'path': path}] if origin_calls else [])}
    if expectation == 'clean':
        checks['clean_200'] = response['status'] == 200 and response.get('json', {}).get('marker') == MARKER
        checks['no_fake_secret'] = not response['leaked_fake_markers']
    elif expectation == 'secret_blocked':
        checks['failure_status'] = response['status'] is not None and 400 <= response['status'] <= 599
        checks['no_fake_secret'] = not response['leaked_fake_markers']
    elif expectation == 'scanner_unavailable':
        checks['server_error_status'] = response['status'] is not None and 500 <= response['status'] <= 599
        checks['no_fake_secret'] = not response['leaked_fake_markers']
    elif expectation == 'canonical_denied':
        checks['forbidden_403'] = response['status'] == 403
        checks['no_fake_secret'] = not response['leaked_fake_markers']
    elif expectation == 'observe_secret':
        checks['fake_secret_intentionally_visible'] = (response['status'] == 200
                                                       and response.get('json', {}).get('fake_fixture_token') == FAKE_TOKEN
                                                       and 'fake_token' in response['leaked_fake_markers'])
    elif expectation == 'sse':
        checks['sse_200'] = (response['status'] == 200
                            and headers.get('content-type', '').startswith('text/event-stream')
                            and 'data: {"marker":"first"}\n\n' in response.get('body_text', '')
                            and 'data: {"marker":"last"}\n\n' in response.get('body_text', ''))
    else:
        raise ValueError(f'Unknown expectation: {expectation}')
    if security_headers:
        checks.update({'server_header_removed': 'server' not in headers,
                       'nosniff_added': headers.get('x-content-type-options') == 'nosniff',
                       'origin_referrer_policy_preserved': headers.get('referrer-policy') == 'no-referrer'})
    if no_store:
        checks['cache_control_no_store'] = 'no-store' in {
            token.strip().lower() for token in headers.get('cache-control', '').split(',')}
    if no_nosniff:
        checks['observe_does_not_add_nosniff'] = 'x-content-type-options' not in headers
    return {'name': name, 'passed': all(checks.values()), 'checks': checks, 'expectation': expectation,
            'expected_origin_calls': origin_calls, 'origin_calls_delta': delta, 'origin_calls': calls,
            'origin_before_total': before['total_calls'], 'origin_after_total': after['total_calls'],
            'response': response}


def run_phase(phase, origin=ORIGIN, gateway=GATEWAY):
    if phase not in PHASES or origin != ORIGIN or gateway not in (GATEWAY, ORIGIN):
        raise ValueError('Only predefined phases and dedicated loopback endpoints are permitted')
    cases = []

    def check(name, path, expectation, **kwargs):
        cases.append(collect_case(origin, gateway, name, path, expectation, **kwargs))

    if phase == 'enforce':
        check('h2_clean_response', '/api/clean', 'clean', transport='h2', no_store=True)
        for path in ('/api/private-key', '/api/split-secret'):
            check(f'h2_{path.rsplit("/", 1)[-1]}_blocked', path, 'secret_blocked', transport='h2', no_store=True)
        check('http1_normal_response_headers', '/', 'clean', security_headers=True)
        check('http1_guard_response_headers', '/api/clean', 'clean', security_headers=True, no_store=True)
        check('sse_response_passes', '/events', 'sse')
    elif phase == 'observe':
        for name, method, path in (('sensitive_file_observed', 'GET', '/.env'),
                                   ('admin_path_observed', 'GET', '/admin'),
                                   ('trace_method_observed', 'TRACE', '/trace-target')):
            check(name, path, 'clean', method=method, no_nosniff=True)
        check('api_secret_not_scanned_in_observe', '/api/token', 'observe_secret', no_nosniff=True)
    elif phase == 'scanner-down':
        check('ordinary_route_survives_scanner_failure', '/', 'clean')
        check('guard_fails_closed_without_scanner', '/api/clean', 'scanner_unavailable', origin_calls=0,
              no_store=True)
    else:
        for name, path in (('ordinary', '/'), ('sensitive_file', '/.env'), ('protected_admin', '/admin')):
            check(f'{name}_denied_when_canonicalizer_broken', path, 'canonical_denied', origin_calls=0)
    return {'schema_version': 1, 'suite': 'incident_protocols', 'phase': phase,
            'passed': bool(cases) and all(case['passed'] for case in cases), 'cases': cases,
            'executed_cases': len(cases), 'failed_cases': [case['name'] for case in cases if not case['passed']],
            'origin': f'http://{origin[0]}:{origin[1]}', 'gateway': f'http://{gateway[0]}:{gateway[1]}',
            'bounds': {'concurrency': 1, 'per_request_seconds': REQUEST_TIMEOUT,
                       'maximum_gateway_requests': 6, 'max_wire_bytes': MAX_WIRE_BYTES},
            'prerequisites': ['The requested profile or failure injection is already active on port 18090.',
                              '/api is response-guarded in enforce, /events is streaming, admission buckets allow this suite.',
                              'Scanner-down means only the inspection process is stopped; policy and gateway are healthy.',
                              'Canonical-broken means canonical metadata stays invalid under enforce RBAC.',
                              'No concurrent traffic reaches the dedicated 18102 origin during origin-call measurements.'],
            'limitations': ['Only fake fixture secrets are used. No external requests or Docker mutations.',
                            'Observe-mode fake token exposure is intentional and is not a prevention claim.',
                            'SSE verifies a complete event stream, not first-event buffering latency.',
                            'A finite protocol matrix does not certify arbitrary websites or encodings.']}


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
