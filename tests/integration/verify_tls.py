"""Verify real TLS on owned fixed ports; Docker is managed separately."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import uuid

import httpx

from tls_fixture import CASES, GATEWAY_PORT, HOST, ORIGIN_HOST, ORIGIN_PORT


VERIFY_COUNTERS = ('cluster.origin_default.ssl.fail_verify_error',
                   'cluster.origin_default.ssl.fail_verify_san')


def private_metrics(deployment: Path | None, context: str | None, raw_path: Path) -> dict:
    if deployment is None:
        return {'available': False, 'error': '--deployment is required for negative TLS evidence'}
    try:
        deployment = deployment.resolve()
        receipt = json.loads((deployment / '.siteguard' / 'active.json').read_text())
        if receipt.get('project_name') != 'siteguard-tls':
            raise ValueError('Only the successfully deployed siteguard-tls project is permitted')
        if context is not None and context != receipt.get('docker_context'):
            raise ValueError('--docker-context must match the successful deployment receipt')
        command = [sys.executable, '-m', 'siteguard', 'metrics', '--output', str(deployment), '--format', 'json']
        if context is not None:
            command.extend(['--docker-context', context])
        completed = subprocess.run(command, cwd=Path(__file__).resolve().parents[2],
                                   capture_output=True, text=True, timeout=20, check=False)
        if completed.returncode:
            raise ValueError(f'Private metrics command failed: {completed.stderr.strip()[:1000]}')
        if len(completed.stdout) > 4 * 1024 * 1024:
            raise ValueError('Private metrics exceed the bounded fixture size')
        document = json.loads(completed.stdout)
        values = {row['name']: row.get('value') for row in document['stats'] if 'name' in row}
        required = (*VERIFY_COUNTERS, 'server.uptime')
        if any(type(values.get(name)) is not int or values[name] < 0 for name in required):
            raise ValueError('Missing or invalid TLS verification counters or server uptime')
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(completed.stdout)
        return {'available': True, 'captured_at': time.time(),
                'counters': {name: values[name] for name in VERIFY_COUNTERS},
                'server_uptime': values['server.uptime'], 'deployment_receipt': receipt,
                'raw_stats_path': str(raw_path.resolve())}
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        return {'available': False, 'error': f'{type(error).__name__}: {error}'}


def verification_delta(before: dict, after: dict, case: str) -> dict:
    if not before.get('available') or not after.get('available'):
        return {'valid': False, 'reason': 'missing_private_verification_metrics'}
    if (before['deployment_receipt'] != after['deployment_receipt']
            or after['server_uptime'] < before['server_uptime']):
        return {'valid': False, 'reason': 'deployment_or_process_changed_during_probe'}
    deltas = {name: after['counters'][name] - before['counters'][name] for name in VERIFY_COUNTERS}
    if any(value < 0 for value in deltas.values()):
        return {'valid': False, 'reason': 'verification_counters_reset', 'deltas': deltas}
    selected = VERIFY_COUNTERS if case == 'wrong-san' else VERIFY_COUNTERS[:1]
    total = sum(deltas[name] for name in selected)
    return {'valid': total >= 1, 'reason': 'verification_failure_increased' if total >= 1
            else 'no_verification_failure_increment', 'deltas': deltas,
            'selected_counter_delta': total}


def tls_handshake(port: int, hostname: str, ca: Path) -> dict:
    if port not in (ORIGIN_PORT, GATEWAY_PORT):
        raise ValueError('Only the two owned TLS fixture ports are permitted')
    context = ssl.create_default_context(cafile=ca)
    context.set_alpn_protocols(['h2', 'http/1.1'])
    try:
        with socket.create_connection((HOST, port), timeout=5) as connection:
            with context.wrap_socket(connection, server_hostname=hostname) as secured:
                return {'verified': True, 'alpn': secured.selected_alpn_protocol(),
                        'tls_version': secured.version(),
                        'certificate_sha256': hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest()}
    except ssl.SSLCertVerificationError as error:
        return {'verified': False, 'certificate_rejected': True,
                'verify_code': error.verify_code, 'verify_message': error.verify_message}
    except OSError as error:
        return {'verified': False, 'certificate_rejected': False,
                'error': f'{type(error).__name__}: {error}'}


def gateway_request(directory: Path, probe_id: str) -> dict:
    context = ssl.create_default_context(cafile=directory / 'certificates' / 'ca.pem')
    record = {'probe_id': probe_id, 'status': 0}
    try:
        with httpx.Client(http2=True, verify=context, timeout=7, trust_env=False,
                          follow_redirects=False) as client:
            with client.stream('GET', f'https://localhost:{GATEWAY_PORT}/tls',
                               headers={'x-siteguard-probe': probe_id}) as response:
                ssl_object = response.extensions['network_stream'].get_extra_info('ssl_object')
                record.update(status=response.status_code, http_version=response.http_version,
                              alpn=ssl_object.selected_alpn_protocol(), tls_version=ssl_object.version())
                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > 16384:
                        raise ValueError('TLS fixture response exceeds 16 KiB')
                record['body'] = body.decode('utf-8', errors='replace')
                try:
                    record['json'] = json.loads(body)
                except ValueError:
                    pass
    except (httpx.HTTPError, OSError, ValueError) as error:
        record['error'] = f'{type(error).__name__}: {error}'
    return record


def origin_records(directory: Path, probe_id: str) -> list[dict]:
    path = directory / 'origin-events.jsonl'
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError('Origin audit exceeds this bounded verification suite size')
    return [record for line in path.read_text().splitlines()
            if (record := json.loads(line)).get('probe_id') == probe_id]


def verify(directory: Path, case: str, deployment: Path | None = None, context: str | None = None) -> dict:
    manifest = json.loads((directory / 'manifest.json').read_text())
    variant = manifest['variants'][case]
    if (manifest['project'] != 'siteguard-tls' or manifest['origin_host'] != ORIGIN_HOST
            or manifest['gateway_url'] != f'https://localhost:{GATEWAY_PORT}'):
        raise ValueError('Manifest does not describe the owned fixed-port TLS fixture')
    ca = directory / 'certificates' / 'ca.pem'
    wrong_ca = directory / 'certificates' / 'wrong-ca.pem'
    probe_id = f'tls-{case}-{uuid.uuid4().hex}'
    origin = tls_handshake(ORIGIN_PORT, ORIGIN_HOST, wrong_ca if case == 'wrong-ca' else ca)
    gateway_untrusted_ca = tls_handshake(GATEWAY_PORT, 'localhost', wrong_ca)
    gateway_wrong_name = tls_handshake(GATEWAY_PORT, 'wrong.invalid', ca)
    negative = case.startswith('wrong-')
    before = private_metrics(deployment, context, directory / 'results' / f'{probe_id}-stats-before.json') if negative else None
    response = gateway_request(directory, probe_id)
    after = private_metrics(deployment, context, directory / 'results' / f'{probe_id}-stats-after.json') if negative else None
    metric_delta = verification_delta(before, after, case) if negative else None
    events = origin_records(directory, probe_id)
    checks = []

    def check(name: str, passed: bool):
        checks.append({'name': name, 'status': 'passed' if passed else 'failed'})

    check('downstream_verified_tls_h2_alpn', response.get('alpn') == 'h2'
          and response.get('http_version') == 'HTTP/2' and 'error' not in response)
    check('downstream_untrusted_ca_rejected', gateway_untrusted_ca.get('certificate_rejected') is True)
    check('downstream_wrong_hostname_rejected', gateway_wrong_name.get('certificate_rejected') is True)
    check('expected_gateway_status', response['status'] == variant['expected_status'])
    if case.startswith('good-'):
        check('origin_certificate_trusted', origin['verified'])
        body = response.get('json', {})
        check('origin_protocol_and_alpn', body.get('http_version') == variant['expected_origin_protocol']
              and body.get('alpn') == ('http/1.1' if case == 'good-http1' else 'h2'))
        check('origin_sni_comes_from_configured_hostname', body.get('sni') == ORIGIN_HOST)
        check('one_correlated_origin_request', len(events) == 1
              and body.get('probe_id') == probe_id and body.get('fixture') == 'siteguard-tls-v1')
    else:
        check('origin_certificate_rejected_directly', origin.get('certificate_rejected') is True)
        check('origin_rejection_matches_case', origin.get('verify_code') == 62 if case == 'wrong-san'
              else origin.get('verify_code') in (18, 19, 20, 21))
        check('no_http_request_reached_origin', len(events) == 0)
        check('private_upstream_certificate_verification_failure_increased', metric_delta['valid'])
    return {'version': 1, 'case': case, 'project': 'siteguard-tls', 'time': time.time(),
            'passed': all(item['status'] == 'passed' for item in checks), 'checks': checks,
            'origin_handshake': origin, 'gateway_untrusted_ca': gateway_untrusted_ca,
            'gateway_wrong_hostname': gateway_wrong_name, 'response': response,
            'origin_events': events, 'config': variant['config'],
            'private_verification_metrics': {'before': before, 'after': after, 'delta': metric_delta} if negative else None,
            'limitations': ['Owned local TLS fixture only; this does not validate every real-site TLS deployment.',
                            'Wrong-SAN verification requires restarting the origin with its wrong-san certificate.',
                            'Verification counters are scoped to the isolated origin_default cluster; run these probes sequentially.']}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', required=True, type=Path)
    parser.add_argument('--case', choices=CASES, required=True)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--deployment', type=Path, help='Successful siteguard-tls deployment; required for negative cases')
    parser.add_argument('--docker-context', help='Must match the successful siteguard-tls deployment receipt')
    args = parser.parse_args()
    directory = args.artifacts.resolve()
    result = verify(directory, args.case, args.deployment, args.docker_context)
    output = args.output or directory / 'results' / f'{args.case}.json'
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'case': args.case, 'passed': result['passed'], 'checks': result['checks'],
                      'output': str(output.resolve())}, indent=2))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
