"""Small read-only loopback checks for gateway header and route isolation."""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

from verify import local_url, request

UPGRADE_HEADERS = {
    'Connection': 'Upgrade', 'Upgrade': 'websocket',
    'Sec-WebSocket-Key': base64.b64encode(b'siteguard-test16').decode(), 'Sec-WebSocket-Version': '13',
}
CONTROL_HEADERS = {
    'X-Envoy-Retry-On': '5xx', 'X-Envoy-Retry-Grpc-On': 'cancelled',
    'X-Envoy-Max-Retries': '3', 'X-Envoy-Upstream-Rq-Timeout-Ms': '987654',
    'X-Envoy-Upstream-Rq-Per-Try-Timeout-Ms': '987653',
    'X-Envoy-Hedge-On-Per-Try-Timeout': 'true', 'X-Envoy-Expected-Rq-Timeout-Ms': '987652',
    'X-Envoy-Arbitrary-Fixture-Control': 'untrusted-fixture-marker', 'X-Test': 'ordinary-header-retained',
}
FORWARDED_HEADERS = {
    'X-Forwarded-For': '203.0.113.123', 'Forwarded': 'for=203.0.113.124;proto=https',
    'X-Real-IP': '203.0.113.125', 'X-Forwarded-Host': 'untrusted.example', 'X-Forwarded-Proto': 'https',
}


def security_suite(base_url, body_limit_bytes=None, timeout_seconds=None):
    base_url = local_url(base_url)
    if body_limit_bytes is not None and not 1 <= body_limit_bytes <= 128 * 1024:
        raise ValueError('Security body-limit verification requires a 1..131072 byte test profile')
    if timeout_seconds is not None and not 1 <= timeout_seconds <= 1.2:
        raise ValueError('Security timeout verification requires a 1..1.2 second test profile')
    checks = []
    control = request(base_url, 'GET', '/echo', headers=CONTROL_HEADERS)
    forwarded = control.get('json', {}).get('forwarded_headers', {})
    leaked = {key: value for key, value in CONTROL_HEADERS.items()
              if key.lower().startswith('x-envoy-') and forwarded.get(key.lower()) == value}
    valid_echo = control['status'] == 200 and 'forwarded_headers' in control.get('json', {})
    passed = valid_echo and not leaked and control['json'].get('x_test') == 'ordinary-header-retained'
    checks.append({'name': 'incoming_envoy_control_headers_removed', 'status': 'passed' if passed else 'failed',
                   'leaked_control_headers': leaked, 'requests': [control],
                   'interpretation': 'Tests supplied values; independently generated upstream Envoy headers are allowed.'})

    forwarded_request = request(base_url, 'GET', '/echo', headers=FORWARDED_HEADERS)
    received = forwarded_request.get('json', {}).get('forwarded_headers', {})
    spoof_markers = ('203.0.113.123', '203.0.113.124', '203.0.113.125', 'untrusted.example')
    leaked_forwarded = {name: value for name, value in received.items()
                        if any(marker in value for marker in spoof_markers)}
    passed = (forwarded_request['status'] == 200 and 'forwarded_headers' in forwarded_request.get('json', {})
              and not leaked_forwarded and received.get('x-forwarded-proto') == 'http')
    checks.append({'name': 'untrusted_forwarded_identity_replaced', 'status': 'passed' if passed else 'failed',
                   'leaked_identity_headers': leaked_forwarded, 'requests': [forwarded_request],
                   'prerequisite': 'Cleartext listener with trusted_proxy_cidrs empty and forwarded_proto http.'})

    if body_limit_bytes is None:
        checks.append({'name': 'upgrade_cannot_bypass_body_limit', 'status': 'skipped',
                       'reason': 'Supply --body-limit-bytes matching a dedicated small-body enforce profile.'})
    else:
        payload = b'x' * (body_limit_bytes + 1)
        normal = request(base_url, 'POST', '/echo', payload, {'Content-Type': 'text/plain'})
        upgraded = request(base_url, 'POST', '/echo', payload,
                           {'Content-Type': 'text/plain', **UPGRADE_HEADERS})
        passed = normal['status'] == 413 and upgraded['status'] in (400, 403, 413, 426)
        checks.append({'name': 'upgrade_cannot_bypass_body_limit', 'status': 'passed' if passed else 'failed',
                       'body_limit_bytes': body_limit_bytes, 'sent_body_bytes': len(payload),
                       'requests': [normal, upgraded],
                       'prerequisite': '/echo must remain an ordinary non-streaming route in enforce mode.'})

    if timeout_seconds is None:
        checks.append({'name': 'upgrade_and_control_headers_cannot_bypass_timeout', 'status': 'skipped',
                       'reason': 'Supply --timeout-seconds matching a dedicated 1..1.2 second enforce profile.'})
    else:
        path = '/delay?ms=1500'
        normal = request(base_url, 'GET', path)
        upgraded = request(base_url, 'GET', path, headers=UPGRADE_HEADERS)
        override = request(base_url, 'GET', path, headers={'X-Envoy-Upstream-Rq-Timeout-Ms': '3000',
                                                          'X-Envoy-Upstream-Rq-Per-Try-Timeout-Ms': '3000'})
        maximum_ms = (timeout_seconds + .25) * 1000
        passed = (normal['status'] in (408, 504) and normal['elapsed_ms'] <= maximum_ms
                  and upgraded['status'] in (400, 403, 408, 426, 504) and upgraded['elapsed_ms'] <= maximum_ms
                  and override['status'] in (408, 504) and override['elapsed_ms'] <= maximum_ms)
        checks.append({'name': 'upgrade_and_control_headers_cannot_bypass_timeout',
                       'status': 'passed' if passed else 'failed', 'timeout_seconds': timeout_seconds,
                       'origin_delay_ms': 1500, 'requests': [normal, upgraded, override],
                       'prerequisite': '/delay must remain an ordinary non-streaming route with the supplied timeout.'})

    return {'schema_version': 1, 'suite': 'bounded_gateway_security', 'base_url': base_url,
            'passed': all(check['status'] in ('passed', 'skipped') for check in checks), 'checks': checks,
            'coverage_complete': all(check['status'] != 'skipped' for check in checks),
            'executed_checks': sum(check['status'] != 'skipped' for check in checks),
            'skipped_checks': sum(check['status'] == 'skipped' for check in checks),
            'unrun_low_rate_requirements': [
                'Use a separate fresh enforce profile with per_ip_rate=1, per_ip_burst=1, '
                'and global/route buckets large enough not to mask the per-IP decision.',
                'Send at most three GET /echo requests within one second from the same local socket identity, '
                'each with a different forged X-Forwarded-For; expect one 200 then two 429 responses.',
                'Do not run header/body checks first against that fresh one-token bucket; '
                'they would consume the admission token and invalidate the sequence.',
                'This verifier does not launch, alter or reload gateway profiles.'],
            'limitations': [
                'Seven requests at most; checks inspect an owned fixture and do not alter gateway configuration.',
                'Missing optional-profile checks remain skipped and do not support a body/timeout claim.',
                'These are finite local regression checks, not a comprehensive security assessment.',
                'HTTP Upgrade rejection shows the fixture action could not bypass the boundary; '
                'gateway access logs can identify the rejection layer.']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', type=local_url, default='http://127.0.0.1:18088')
    parser.add_argument('--body-limit-bytes', type=int)
    parser.add_argument('--timeout-seconds', type=float)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = security_suite(args.base_url, args.body_limit_bytes, args.timeout_seconds)
    except ValueError as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    print(args.output)
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
