"""Run bounded, paired local Compose comparisons with recorded order and provenance."""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import random
import shutil
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / 'local_ddos_lab'
VARIANTS = (
    ('gateway-off', 'off', 'bypass', 'off'),
    ('envoy-adaptive', 'adaptive', 'bypass', 'off'),
    ('adaptive-rls-bypass', 'rls_adaptive', 'bypass', 'off'),
    ('adaptive-rls-fixed', 'rls_adaptive', 'fixed', 'off'),
    ('adaptive-rls-feedback', 'rls_adaptive', 'feedback', 'off'),
    ('backend-fixed', 'off', 'bypass', 'fixed'),
)
SERVICES = ('postgres', 'app', 'rls', 'envoy')
INSPECT_FORMAT = ('{"image_id":{{json .Image}},"nano_cpus":{{json .HostConfig.NanoCpus}},'
                  '"cpu_period":{{json .HostConfig.CpuPeriod}},"cpu_quota":{{json .HostConfig.CpuQuota}},'
                  '"memory_bytes":{{json .HostConfig.Memory}}}')
HOST_FORMAT = ('{"cpus":{{.NCPU}},"memory_bytes":{{.MemTotal}},'
               '"architecture":{{json .Architecture}},"os":{{json .OSType}}}')


def run_command(argv: list[str], env: dict, timeout: int = 120, optional: bool = False) -> str | None:
    try:
        result = subprocess.run(argv, cwd=ROOT, env=env, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        if optional:
            return None
        raise RuntimeError(f'{Path(argv[0]).name} could not finish ({type(exc).__name__}).') from exc
    if result.returncode:
        if optional:
            return None
        # Raw subprocess errors may contain interpolated credentials or environment values.
        raise RuntimeError(f'{Path(argv[0]).name} command failed (exit {result.returncode}); '
                           'inspect the local Compose service manually. Raw output was not archived.')
    return result.stdout.strip()


def python_executable() -> str:
    candidate = ROOT / '.venv' / 'bin' / 'python'
    return str(candidate) if candidate.is_file() else sys.executable


def local_context_endpoint(endpoint: str) -> None:
    if not endpoint.startswith('unix:///'):
        raise ValueError('Only a local Unix-socket Docker context is supported; no TCP/SSH targets.')


def variant_environment(base: dict, envoy_mode: str, rls_mode: str) -> dict:
    env = dict(base)
    env.update(LAB_UID=str(os.getuid()), LAB_GID=str(os.getgid()),
               ENVOY_MODE=envoy_mode, RLS_MODE=rls_mode)
    return env


def compose_prefix(engine: list[str]) -> list[str]:
    return engine + ['--project-name', 'data-security-lab', '--file', str(ROOT / 'compose.yaml'),
                     '--project-directory', str(ROOT), '--env-file', os.devnull]


def experiment_command(args: argparse.Namespace, label: str, app_mode: str = 'off') -> list[str]:
    probe = args.workload == 'cancellation'
    command = [python_executable(), str(LAB / ('cancellation_probe.py' if probe else 'experiment.py')),
               '--mode', app_mode, '--seconds', str(args.seconds), '--seed', str(args.seed),
               '--arrival', args.arrival, '--report-rounds', str(args.report_rounds),
               '--fixed-limit', str(args.fixed_limit), '--base-url', 'http://127.0.0.1:8080',
               '--label', label]
    if probe:
        command += ['--kind', args.kind, '--cancel-after-ms', str(args.cancel_after_ms),
                    '--round-order', args.round_order]
    else:
        command += ['--scenario', args.scenario]
    return command


def comparison_plan(args: argparse.Namespace) -> list[dict]:
    first_order = list(VARIANTS)
    if args.order != 'fixed':
        random.Random(args.seed).shuffle(first_order)
    plan = []
    for repeat in range(args.repeats):
        ordered = list(first_order)
        if args.order == 'balanced':
            offset = repeat % len(ordered)
            ordered = ordered[offset:] + ordered[:offset]
        elif args.order == 'randomized':
            random.Random(args.seed + repeat).shuffle(ordered)
        round_order = args.round_order
        if round_order == 'balanced':
            round_order = 'wait-first' if repeat % 2 == 0 else 'cancel-first'
        for position, variant in enumerate(ordered):
            plan.append({'repeat_index': repeat, 'seed': args.seed + repeat,
                         'position': position, 'round_order': round_order,
                         'label': variant[0], 'envoy_mode': variant[1],
                         'rls_mode': variant[2], 'app_mode': variant[3]})
    return plan


def redact_config(value):
    if isinstance(value, dict):
        return {key: ('[redacted]' if key.lower() in ('environment', 'secrets') or
                      any(part in key.lower() for part in ('password', 'token', 'credential'))
                      else redact_config(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_config(item) for item in value]
    return value


def sanitized_logs(raw: str) -> dict:
    allowed = {'event', 'mode', 'state', 'run_id', 'report_rate', 'previous_report_rate', 'rates',
               'bursts', 'error_type', 'time', 'method', 'path', 'status', 'duration_ms', 'flags', 'details'}
    rows, omitted = [], 0
    for line in raw.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            omitted += 1
            continue
        if not isinstance(row, dict):
            omitted += 1
            continue
        row = {key: value for key, value in row.items() if key in allowed}
        if 'path' in row:
            path = str(row['path']).split('?', 1)[0]
            row['path'] = path if path in ('/', '/health', '/api/products', '/api/orders', '/api/report') else '[other_path]'
        rows.append(row)
    return {'events': rows, 'unstructured_lines_omitted': omitted,
            'notice': 'Only known structured Envoy/RLS fields are retained; query strings are removed.'}


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding='utf-8')


def envoy_stats(adaptive_only: bool = False) -> dict:
    path = '/stats?format=json' + ('&filter=adaptive_concurrency' if adaptive_only else '')
    connection = http.client.HTTPConnection('127.0.0.1', 9901, timeout=2)
    try:
        connection.request('GET', path)
        response = connection.getresponse()
        raw = response.read(2_000_001)
        if response.status != 200 or len(raw) > 2_000_000:
            raise RuntimeError('Envoy stats unavailable or oversized.')
        return json.loads(raw)
    finally:
        connection.close()


def collect_adaptive(stop: threading.Event, samples: list) -> None:
    while not stop.is_set():
        sample = {'monotonic_s': time.monotonic()}
        try:
            sample['stats'] = envoy_stats(adaptive_only=True)
        except (OSError, ValueError, RuntimeError, http.client.HTTPException) as exc:
            sample['error_type'] = type(exc).__name__
        samples.append(sample)
        stop.wait(1)


def source_hashes() -> dict:
    sources = [ROOT / 'compose.yaml', LAB / 'server.py', LAB / 'database.py',
               LAB / 'postgres_database.py', LAB / 'cancellation.py', LAB / 'policy.py',
               LAB / 'experiment.py', LAB / 'cancellation_probe.py',
               ROOT / 'rls' / 'server.py', ROOT / 'rls' / 'policy.py',
               ROOT / 'rls' / 'requirements.txt', ROOT / 'scripts' / 'run_comparison.py']
    sources += [path for path in (LAB / 'workload.py', LAB / 'event_analysis.py') if path.exists()]
    return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources}


def discover_docker(requested_context: str | None, env: dict) -> tuple[list[str], list[str], str, dict]:
    context = requested_context or run_command(['docker', 'context', 'show'], env)
    docker = ['docker', '--context', context]
    endpoint = json.loads(run_command(docker + ['context', 'inspect', context, '--format',
                                                '{{json .Endpoints.docker.Host}}'], env))
    local_context_endpoint(endpoint)
    env = dict(env)
    env.pop('DOCKER_HOST', None)
    env['DOCKER_CONTEXT'] = context
    engine = docker + ['compose']
    if run_command(engine + ['version'], env, optional=True) is None:
        engine = ['docker-compose']
        if run_command(engine + ['version'], env, optional=True) is None:
            raise RuntimeError('Docker Compose is not installed.')
    compose = compose_prefix(engine)
    if '--wait' not in run_command(compose + ['up', '--help'], env):
        raise RuntimeError('This Compose version has no --wait support. Install a current Compose release.')
    if '--format' not in run_command(compose + ['config', '--help'], env):
        raise RuntimeError('This Compose version cannot export config as JSON.')
    return docker, compose, context, env


def run_variant(args: argparse.Namespace, planned: dict, docker: list[str],
                compose: list[str], base_env: dict, artifact: Path, git_revision: str | None,
                host_resources: dict) -> None:
    label, envoy_mode, rls_mode = (planned[key] for key in ('label', 'envoy_mode', 'rls_mode'))
    env = variant_environment(base_env, envoy_mode, rls_mode)
    out = artifact / label
    out.mkdir(parents=True)
    manifest = {'experiment_type': 'compose_comparison', **planned, 'status': 'preparing',
                'git_revision': git_revision, 'host_resources': host_resources,
                'base_url': 'http://127.0.0.1:8080', 'scenario': args.scenario, 'seed': args.seed,
                'seconds': args.seconds, 'workload': args.workload, 'arrival': args.arrival,
                'report_rounds': args.report_rounds, 'fixed_limit': args.fixed_limit,
                'kind': args.kind, 'cancel_after_ms': args.cancel_after_ms,
                'source_sha256': source_hashes(),
                'envoy_config_sha256': hashlib.sha256((ROOT / 'deploy' / 'envoy' / f'{envoy_mode}.yaml').read_bytes()).hexdigest()}
    write_json(out / 'manifest.json', manifest)
    try:
        print(f'執行組別：{label}', flush=True)
        run_command(compose + ['up', '-d', '--no-deps', '--force-recreate', '--wait',
                               '--wait-timeout', '120', 'rls', 'envoy'], env, timeout=180)
        config = json.loads(run_command(compose + ['config', '--format', 'json'], env))
        write_json(out / 'compose_config.redacted.json', redact_config(config))
        containers = {}
        for service in SERVICES:
            identifier = run_command(compose + ['ps', '-q', service], env)
            if not identifier or '\n' in identifier:
                raise RuntimeError(f'Expected one running {service} container.')
            containers[service] = json.loads(run_command(docker + ['inspect', '--format', INSPECT_FORMAT,
                                                                   identifier], env))
        manifest['containers'] = containers
        manifest['envoy_version'] = run_command(compose + ['exec', '-T', 'envoy', 'envoy', '--version'], env)
        manifest['status'] = 'running'
        write_json(out / 'manifest.json', manifest)
        write_json(out / 'stats_before.json', envoy_stats())
        for service in ('envoy', 'rls'):
            raw = run_command(compose + ['logs', '--no-color', '--no-log-prefix', service], env)
            write_json(out / f'{service}_logs_before.json', sanitized_logs(raw))
        since = dt.datetime.now(dt.timezone.utc).isoformat()
        existing = set((LAB / 'results').glob('*'))
        stop, samples = threading.Event(), []
        observer = threading.Thread(target=collect_adaptive, args=(stop, samples), daemon=True)
        observer.start()
        try:
            command = experiment_command(args, label, planned['app_mode'])
            manifest['experiment_command'] = command
            write_json(out / 'manifest.json', manifest)
            output = run_command(command, env, timeout=args.seconds * (2 if args.workload == 'cancellation' else 1) + 90)
            (out / 'experiment.log').write_text(output + '\n', encoding='utf-8')
        finally:
            stop.set()
            observer.join(timeout=3)
            (out / 'adaptive_stats.jsonl').write_text('\n'.join(json.dumps(sample) for sample in samples) + '\n', encoding='utf-8')
            write_json(out / 'stats_after.json', envoy_stats())
            for service in ('envoy', 'rls'):
                raw = run_command(compose + ['logs', '--no-color', '--no-log-prefix', '--since', since, service], env)
                write_json(out / f'{service}_logs_after.json', sanitized_logs(raw))
        created = [path for path in set((LAB / 'results').glob('*')) - existing if path.is_dir()]
        if len(created) != 1:
            raise RuntimeError('Expected exactly one new result batch; another experiment may be running.')
        shutil.copytree(created[0], out / 'experiment')
        metadata_paths = list((out / 'experiment').rglob('metadata.json'))
        if len(metadata_paths) != 1:
            raise RuntimeError('Expected metadata for exactly one paired workload.')
        metadata = json.loads(metadata_paths[0].read_text())
        if metadata.get('mode') != planned['app_mode']:
            raise RuntimeError('Recorded app mode does not match the planned baseline.')
        manifest.update(status='complete', original_results=str(created[0].relative_to(ROOT)),
                        schedule_sha256=metadata.get('schedule_sha256'),
                        adaptive_stats_errors=sum('error_type' in sample for sample in samples))
    except (OSError, ValueError, RuntimeError, http.client.HTTPException) as exc:
        manifest.update(status='failed', error_type=type(exc).__name__)
        raise
    finally:
        write_json(out / 'manifest.json', manifest)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=30)
    parser.add_argument('--scenario', choices=('normal', 'mixed', 'surge', 'critical'), default='mixed')
    parser.add_argument('--seed', type=int, default=42)
    parser.add_argument('--workload', choices=('regular', 'cancellation'), default='regular')
    parser.add_argument('--arrival', choices=('periodic', 'jittered', 'burst'), default='periodic')
    parser.add_argument('--repeats', type=int, default=1)
    parser.add_argument('--order', choices=('fixed', 'randomized', 'balanced'), default='balanced')
    parser.add_argument('--report-rounds', type=int, default=40)
    parser.add_argument('--fixed-limit', type=int, default=2)
    parser.add_argument('--kind', choices=('report', 'products'), default='report')
    parser.add_argument('--cancel-after-ms', type=int, default=50)
    parser.add_argument('--round-order', choices=('wait-first', 'cancel-first', 'balanced'), default='balanced')
    parser.add_argument('--plan', action='store_true', help='Print commands and order without starting services.')
    parser.add_argument('--docker-context')
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    low, high = (3, 30) if args.workload == 'cancellation' else (30, 120)
    if not low <= args.seconds <= high:
        parser.error(f'{args.workload} seconds must be {low}..{high}.')
    if not (1 <= args.repeats <= 10 and 1 <= args.report_rounds <= 100
            and 1 <= args.fixed_limit <= 3 and 20 <= args.cancel_after_ms <= 1000):
        parser.error('Bounds: repeats=1..10, report-rounds=1..100, fixed-limit=1..3, cancel-after-ms=20..1000.')


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    validate_args(parser, args)
    plan = comparison_plan(args)
    if args.plan:
        preview = []
        for item in plan:
            current = argparse.Namespace(**{**vars(args), 'seed': item['seed'], 'round_order': item['round_order']})
            preview.append({**item, 'command': experiment_command(current, item['label'], item['app_mode'])})
        print(json.dumps(preview, ensure_ascii=False, indent=2))
        return
    try:
        docker, compose, context, env = discover_docker(args.docker_context, dict(os.environ))
        env = variant_environment(env, 'off', 'bypass')
        (LAB / 'runtime').mkdir(parents=True, exist_ok=True)
        print('建置本機 Compose 映像並等待 PostgreSQL／app 就緒。', flush=True)
        run_command(compose + ['build'], env, timeout=1200)
        run_command(compose + ['up', '-d', '--wait', '--wait-timeout', '180', 'postgres', 'app'], env, timeout=240)
        artifact = ROOT / 'artifacts' / f'comparison-{time.strftime("%Y%m%d-%H%M%S")}-{time.time_ns() % 1000000:06}'
        artifact.mkdir(parents=True)
        git_revision = run_command(['git', 'rev-parse', 'HEAD'], env, optional=True)
        frozen_sources = source_hashes()
        host_resources = json.loads(run_command(docker + ['info', '--format', HOST_FORMAT], env))
        write_json(artifact / 'manifest.json', {'experiment_type': 'compose_comparison',
                    'docker_context': context, 'variants': VARIANTS, 'plan': plan,
                    'parameters': vars(args), 'host_resources': host_resources,
                    'git_revision': git_revision, 'source_sha256': frozen_sources,
                    'notice': 'Paired bounded comparison; repeated runs alone do not prove superiority.'})
        paired_schedules = {}
        for item in plan:
            if source_hashes() != frozen_sources:
                raise RuntimeError('Source changed during comparison; freeze code and start a new batch.')
            current = argparse.Namespace(**{**vars(args), 'seed': item['seed'], 'round_order': item['round_order']})
            repeat_dir = artifact / f'repeat-{item["repeat_index"] + 1:02}-seed{item["seed"]}'
            run_variant(current, item, docker, compose, env, repeat_dir, git_revision, host_resources)
            manifest_path = repeat_dir / item['label'] / 'manifest.json'
            manifest = json.loads(manifest_path.read_text())
            expected_hash = paired_schedules.setdefault(item['repeat_index'], manifest['schedule_sha256'])
            if not expected_hash or expected_hash != manifest['schedule_sha256']:
                manifest.update(status='invalid', validity_issue='Paired schedule hashes differ.')
                write_json(manifest_path, manifest)
                raise RuntimeError('Paired workload schedules differ; comparison stopped.')
        run_command([python_executable(), str(LAB / 'summarize_results.py'), str(artifact),
                     '--output', str(artifact / 'comparison.html')], env)
        print(f'{len(VARIANTS)} 組 × {args.repeats} 輪比較已保存：{artifact}\n最後一組容器保持啟動；請依報告的證據限制判讀。')
    except KeyboardInterrupt:
        parser.exit(130, 'Stopped; bounded in-flight work may still be draining. Containers remain running.\n')
    except (OSError, ValueError, RuntimeError, http.client.HTTPException) as exc:
        parser.exit(1, f'Comparison stopped: {exc}\n')


if __name__ == '__main__':
    main()
