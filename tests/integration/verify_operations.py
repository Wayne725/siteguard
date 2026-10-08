"""Real CLI/Docker lifecycle checks in the dedicated siteguard-compat project only."""
from __future__ import annotations

import argparse
import copy
import hashlib
import http.client
import json
import os
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from siteguard.config import validate_config
from siteguard.deployment import compose_config

CONTEXT = 'colima-data-security'
PROJECT = 'siteguard-compat'
NETWORK = 'siteguard-compat-origin'
ORIGIN = 'siteguard-compat-origin'
PORT = 18089
NGINX_IMAGE = 'nginx:1.28-alpine@sha256:a8b39bd9cf0f83869a2162827a0caf6137ddf759d50a171451b335cecc87d236'
ARTIFACT_ROOT = ROOT / 'artifacts/siteguard/compat'


class OperationsRun:
    def __init__(self, output):
        self.output = output
        self.deploy = output / 'deploy'
        self.config_path = output / 'siteguard.yaml'
        self.docker = ['docker', '--context', CONTEXT]
        self.report = {'schema_version': 1, 'created_at': datetime.now(timezone.utc).isoformat(),
                       'docker_context': CONTEXT, 'project': PROJECT, 'gateway_port': PORT,
                       'external_network': NETWORK, 'steps': [], 'checks': [], 'cleanup': [],
                       'limitations': ['Local operator and protocol evidence does not establish general production readiness.',
                                       'Failure restoration is tested by removing an owned candidate TLS key after validation.',
                                       'Nginx coverage is static HTML, headers, redirect, caching, ranges and method semantics.']}
        self.created_network = False
        self.created_origin = False
        self.managed_deployment = False

    def save(self):
        (self.output / 'operations.json').write_text(json.dumps(self.report, ensure_ascii=False, indent=2), encoding='utf-8')

    def command(self, name, argv, timeout=180, required=True):
        started = time.monotonic()
        print(f'{name} ...', flush=True)
        result = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        record = {'name': name, 'argv': argv, 'exit_code': result.returncode,
                  'elapsed_ms': round((time.monotonic() - started) * 1000, 3),
                  'stdout': result.stdout, 'stderr': result.stderr}
        self.report['steps'].append(record)
        self.save()
        if required and result.returncode:
            raise RuntimeError(f'{name} failed with exit {result.returncode}: {result.stderr[-1200:]}')
        return record

    def cli(self, action, required=True):
        self.managed_deployment = True
        return self.command(f'cli_{action}', [sys.executable, '-m', 'siteguard', action,
                            '--config', str(self.config_path), '--output', str(self.deploy),
                            '--docker-context', CONTEXT,
                            *(['--wait-timeout', '40'] if action in ('up', 'rollback') else [])],
                            timeout=300, required=required)

    def compose(self, *arguments):
        return self.docker + ['compose', '--project-name', PROJECT, '--file', str(self.deploy / 'compose.yaml'),
                              '--project-directory', str(self.deploy), '--env-file', os.devnull, *arguments]

    def receipt(self):
        path = self.deploy / '.siteguard/active.json'
        return json.loads(path.read_text()) if path.exists() else None

    def check(self, name, passed, **evidence):
        self.report['checks'].append({'name': name, 'passed': bool(passed), **evidence})
        self.save()

    def http(self, path='/', method='GET', headers=None):
        started = time.monotonic()
        connection = http.client.HTTPConnection('127.0.0.1', PORT, timeout=3)
        result = {'method': method, 'path': path, 'request_headers': headers or {}, 'status': 0}
        try:
            connection.request(method, path, headers=headers or {})
            response = connection.getresponse()
            data = response.read(65537)
            if len(data) > 65536:
                raise ValueError('Unexpectedly large operations response')
            result.update(status=response.status, headers=dict(response.getheaders()),
                          body=data.decode(errors='replace'), body_hex=data.hex())
        except (OSError, http.client.HTTPException, ValueError) as error:
            result['error'] = str(error)
        finally:
            connection.close()
        result['elapsed_ms'] = round((time.monotonic() - started) * 1000, 3)
        return result

    def wait_for_http(self):
        attempts = []
        for _ in range(30):
            response = self.http()
            attempts.append(response)
            if response['status'] == 200:
                return response, attempts
            time.sleep(.2)
        return response, attempts

    def prepare_origin(self):
        for kind, arguments in (
            ('project', ['ps', '--all', '--filter', f'label=com.docker.compose.project={PROJECT}', '--format', '{{.ID}}']),
            ('origin', ['ps', '--all', '--filter', f'name=^/{ORIGIN}$', '--format', '{{.ID}}']),
        ):
            existing = self.command(f'preflight_{kind}', self.docker + arguments)
            if existing['stdout'].strip():
                raise RuntimeError(f'Dedicated {kind} already exists; refusing to adopt or remove it')
        if self.command('preflight_network', self.docker + ['network', 'inspect', NETWORK], required=False)['exit_code'] == 0:
            raise RuntimeError('Dedicated network already exists; refusing to adopt or remove it')
        self.command('create_origin_network', self.docker + ['network', 'create', '--label',
                     'siteguard.compat.owner=verify_operations', NETWORK])
        self.created_network = True
        image = self.command('nginx_image_before', self.docker + ['image', 'inspect', NGINX_IMAGE], required=False)
        if image['exit_code']:
            image = self.command('pull_pinned_nginx_once', self.docker + ['pull', NGINX_IMAGE], timeout=120, required=False)
        if image['exit_code']:
            self.report['origin'] = {'implementation': 'existing-node-fallback', 'nginx_unavailable': True,
                                     'reason': image['stderr'][-1000:]}
            return {'url': 'http://host.lima.internal:18101', 'protocol': 'http1', 'preserve_host': True,
                    'network': NETWORK}
        self.command('nginx_image_identity', self.docker + ['image', 'inspect', NGINX_IMAGE])
        static = self.output / 'nginx/static'
        static.mkdir(parents=True)
        (static / 'index.html').write_text('<!doctype html><title>Real Nginx</title><h1>siteguard-compat Nginx 中文</h1>\n')
        (static / 'asset.txt').write_text('0123456789abcdef' * 256)
        nginx_config = self.output / 'nginx/nginx.conf'
        nginx_config.write_text('''worker_processes 1;
pid /tmp/nginx.pid;
error_log /dev/stderr notice;
events { worker_connections 128; }
http {
  access_log /dev/stdout;
  default_type text/html;
  charset utf-8;
  server {
    listen 8080;
    server_name _;
    root /srv/static;
    location = /redirect { return 302 /index.html; }
    location / { try_files $uri $uri/ =404; }
  }
}
''')
        self.command('start_nginx_origin', self.docker + ['run', '-d', '--name', ORIGIN,
                     '--label', 'siteguard.compat.owner=verify_operations', '--network', NETWORK,
                     '--network-alias', 'nginx-origin', '--read-only', '--tmpfs', '/tmp:rw,size=8m,mode=1777',
                     '--tmpfs', '/var/cache/nginx:rw,size=8m,mode=1777', '--user', '101:101',
                     '--cpus', '.5', '--memory', '128m', '--pids-limit', '32', '--cap-drop', 'ALL',
                     '--security-opt', 'no-new-privileges:true',
                     '--mount', f'type=bind,source={nginx_config},target=/etc/nginx/nginx.conf,readonly',
                     '--mount', f'type=bind,source={static},target=/srv/static,readonly',
                     '--entrypoint', 'nginx', NGINX_IMAGE, '-g', 'daemon off;'])
        self.created_origin = True
        self.command('nginx_binary_version', self.docker + ['exec', ORIGIN, 'nginx', '-v'])
        self.report['origin'] = {'implementation': 'nginx', 'image': NGINX_IMAGE,
                                 'container': ORIGIN, 'published_ports': []}
        return {'url': 'http://nginx-origin:8080', 'protocol': 'http1', 'preserve_host': True, 'network': NETWORK}

    def reuse_built_images(self, config):
        rendered = compose_config(validate_config(config, self.output))
        listing = self.command('existing_image_tags', self.docker + ['image', 'ls', '--format', '{{.Repository}}:{{.Tag}}'])
        tags = listing['stdout'].splitlines()
        for service in ('gateway', 'policy'):
            target = rendered['services'][service]['image']
            if target in tags:
                continue
            content_hash = target.split(':', 1)[1]
            candidates = [tag for tag in tags if tag.endswith(':' + content_hash) and f'-{service}:' in tag]
            if candidates:
                self.command(f'reuse_{service}_content_image', self.docker + ['tag', candidates[0], target])

    def write_config(self, config):
        self.config_path.write_text(yaml.safe_dump(config, sort_keys=False))

    def policy_outage(self, mode):
        self.command(f'{mode}_stop_policy', self.compose('stop', '--timeout', '5', 'policy'))
        stopped = self.command(f'{mode}_policy_stopped_state', self.compose('ps', '--all', '--format', 'json'))
        responses = [self.http() for _ in range(3)]
        metrics = self.cli('metrics', required=False)
        self.command(f'{mode}_start_policy', self.compose('start', 'policy'))
        recovered, attempts = self.wait_for_http()
        expected = 503 if mode == 'enforce' else 200
        self.check(f'{mode}_policy_failure_behavior', all(row['status'] == expected for row in responses)
                   and recovered['status'] == 200, responses=responses, expected_status=expected,
                   stopped_containers=stopped['stdout'], recovery_attempts=attempts,
                   metrics_step=metrics['name'])

    def restore_fault(self, stable_receipt):
        certificate = self.output / 'candidate-cert.pem'
        key = self.output / 'candidate-key.pem'
        missing_key = self.output / 'candidate-key.temporarily-unavailable'
        self.command('generate_owned_fault_certificate', ['openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                     '-nodes', '-days', '1', '-subj', '/CN=localhost', '-keyout', str(key), '-out', str(certificate)])
        key.chmod(0o600)
        config = yaml.safe_load(self.config_path.read_text())
        config['listener']['tls'] = {'certificate': str(certificate), 'private_key': str(key)}
        self.write_config(config)
        target = self.deploy / '.siteguard/target.json'
        original_mtime = target.stat().st_mtime_ns
        stop = threading.Event()
        injection = {'trigger': 'target receipt replaced after native validation', 'injected': False}

        def remove_candidate_key():
            while not stop.wait(.005):
                if target.exists() and target.stat().st_mtime_ns != original_mtime:
                    key.rename(missing_key)
                    injection.update(injected=True, key_removed_at=datetime.now(timezone.utc).isoformat())
                    return

        observer = threading.Thread(target=remove_candidate_key, daemon=True)
        observer.start()
        try:
            failed = self.cli('up', required=False)
        finally:
            stop.set()
            observer.join()
            if missing_key.exists():
                missing_key.rename(key)
        restored_receipt = self.receipt()
        served, attempts = self.wait_for_http()
        history_path = self.deploy / '.siteguard/history.jsonl'
        history = history_path.read_text() if history_path.exists() else ''
        self.check('failed_activation_restores_previous_deployment', injection['injected']
                   and failed['exit_code'] != 0 and restored_receipt['version'] == stable_receipt['version']
                   and 'failed_recovered' in history and served['status'] == 200,
                   injection=injection, failed_command=failed, stable_receipt=stable_receipt,
                   restored_receipt=restored_receipt, recovery_attempts=attempts, history=history)

    def run(self):
        self.output.mkdir(parents=True, exist_ok=False)
        self.save()
        try:
            upstream = self.prepare_origin()
            config = {'version': 1, 'name': PROJECT, 'mode': 'enforce',
                      'listener': {'host': '127.0.0.1', 'port': PORT}, 'upstream': upstream, 'hosts': ['*'],
                      'policy': {'max_concurrent': 4, 'queue_size': 4, 'rate_per_second': 100, 'burst': 200,
                                 'per_ip_rate': 100, 'per_ip_burst': 200, 'max_body_bytes': 131072,
                                 'request_timeout_seconds': 3, 'stream_idle_timeout_seconds': 30},
                      'routes': [], 'trusted_proxy_cidrs': [], 'trusted_proxy_hops': 0}
            self.write_config(config)
            self.reuse_built_images(config)
            self.cli('check')
            self.cli('up')
            initial = self.receipt()
            self.cli('status')
            identity = self.command('external_network_attachment', self.docker + ['network', 'inspect', NETWORK])
            self.report['network_inspect'] = json.loads(identity['stdout'])
            page, attempts = self.wait_for_http()
            if self.created_origin:
                asset = self.http('/asset.txt')
                etag = next((value for key, value in asset.get('headers', {}).items() if key.lower() == 'etag'), '')
                conditional = self.http('/asset.txt', headers={'If-None-Match': etag})
                ranged = self.http('/asset.txt', headers={'Range': 'bytes=100-199'})
                redirect = self.http('/redirect')
                post = self.http('/index.html', method='POST')
                networks = self.report['network_inspect'][0].get('Containers', {}).values()
                names = {value['Name'] for value in networks}
                self.check('real_nginx_over_existing_origin_network', page['status'] == 200
                           and 'siteguard-compat Nginx 中文' in page['body'] and asset['status'] == 200
                           and conditional['status'] == 304 and ranged['status'] == 206
                           and bytes.fromhex(ranged['body_hex']) == ('0123456789abcdef' * 256).encode()[100:200]
                           and redirect['status'] == 302 and post['status'] == 405
                           and ORIGIN in names and any(name.startswith(PROJECT + '-gateway') for name in names),
                           page=page, asset=asset, conditional=conditional, range=ranged, redirect=redirect,
                           post_method=post, network_container_names=sorted(names))
            else:
                self.check('fallback_origin_reachable', page['status'] == 200, attempts=attempts)
            self.policy_outage('enforce')
            config['mode'] = 'observe'
            self.write_config(config)
            self.cli('up')
            observed = self.receipt()
            self.policy_outage('observe')
            self.cli('rollback')
            rolled_back = self.receipt()
            rollback_page, rollback_attempts = self.wait_for_http()
            self.check('cli_rollback_restores_prior_successful_version', initial['version'] != observed['version']
                       and rolled_back['version'] == initial['version'] and rollback_page['status'] == 200,
                       initial=initial, observed=observed, rolled_back=rolled_back, requests=rollback_attempts)
            config['mode'] = 'enforce'
            self.write_config(config)
            self.restore_fault(rolled_back)
            self.cli('status')
        except Exception as error:
            self.report['error'] = f'{type(error).__name__}: {error}'
            self.save()
        finally:
            if self.managed_deployment and (self.deploy / 'compose.yaml').exists():
                down = self.cli('down', required=False)
                self.report['cleanup'].append({'action': 'cli_down', 'exit_code': down['exit_code']})
            if self.created_origin:
                removed = self.command('remove_owned_nginx', self.docker + ['rm', '-f', ORIGIN], required=False)
                self.report['cleanup'].append({'action': 'remove_origin', 'exit_code': removed['exit_code']})
            if self.created_network:
                removed = self.command('remove_owned_origin_network', self.docker + ['network', 'rm', NETWORK], required=False)
                self.report['cleanup'].append({'action': 'remove_network', 'exit_code': removed['exit_code']})
            remaining = self.command('remaining_owned_project_containers', self.docker + ['ps', '--all', '--filter',
                                     f'label=com.docker.compose.project={PROJECT}', '--format', '{{.Names}}'], required=False)
            self.report['cleanup_ok'] = (not remaining['stdout'].strip()
                                         and all(item['exit_code'] == 0 for item in self.report['cleanup']))
            self.report['passed'] = (not self.report.get('error') and self.report['checks']
                                     and all(check['passed'] for check in self.report['checks'])
                                     and self.report['cleanup_ok'])
            self.save()
        return self.report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-name', default=datetime.now().strftime('run-%Y%m%d-%H%M%S'))
    args = parser.parse_args()
    if not args.run_name.startswith('run-') or any(character not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for character in args.run_name):
        parser.error('run-name must begin run- and contain lowercase letters, digits and hyphens only')
    output = ARTIFACT_ROOT / args.run_name
    report = OperationsRun(output).run()
    print(json.dumps({'output': str(output / 'operations.json'), 'passed': report['passed'],
                      'checks': [{'name': check['name'], 'passed': check['passed']} for check in report['checks']],
                      'cleanup_ok': report['cleanup_ok'], 'error': report.get('error')}, ensure_ascii=False, indent=2))
    if not report['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
