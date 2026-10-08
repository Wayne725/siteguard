"""Generate an isolated deployment and invoke Docker without a shell."""
from __future__ import annotations

import json
import hashlib
import datetime as dt
from contextlib import contextmanager
from importlib import resources
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

import yaml

try:
    import fcntl
except ImportError:
    fcntl = None

ENVOY_IMAGE = ('envoyproxy/envoy:v1.39.1@sha256:'
               '57e14a549d7bd43c8d3f6d03e8cfa653e037d4b38e133acd9b54f38c524401b4')
SERVICE = 'gateway'
PYTHON_IMAGE = ('python:3.13-slim@sha256:'
                '7c61056e61ac89e852de05f3dc6fa51a6dd2181797bceed46aa725dd7cb2cd3b')
GATEWAY_DOCKERFILE = f'''FROM {ENVOY_IMAGE}
USER root
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
USER 101:101
'''
POLICY_DOCKERFILE = f'''FROM {PYTHON_IMAGE}
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY ratelimit.py inspection.py ./
USER 101:101
CMD ["python", "/app/ratelimit.py"]
'''
POLICY_REQUIREMENTS = 'grpcio==1.84.0\nxds-protos==1.84.0\n'
LEGACY_BUNDLE_FILES = ('envoy.yaml', 'compose.yaml', 'policy.json', 'gateway/Dockerfile',
                       'gateway/.dockerignore', 'policy/Dockerfile', 'policy/.dockerignore',
                       'policy/requirements.txt', 'policy/ratelimit.py')
BUNDLE_FILES = LEGACY_BUNDLE_FILES + ('policy/inspection.py',)
GENERATED_MARKER = {'managed_by': 'siteguard-gateway', 'schema_version': 1}


class DeploymentError(RuntimeError):
    pass


@contextmanager
def deployment_lock(output: Path):
    if fcntl is None:
        raise DeploymentError('部署寫入操作目前只支援具備 fcntl 檔案鎖的 Linux／macOS。')
    directory = output.resolve() / '.siteguard'
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    descriptor = os.open(directory / 'operation.lock', os.O_CREAT | os.O_RDWR, 0o600)
    with os.fdopen(descriptor, 'a+') as stream:
        os.fchmod(stream.fileno(), 0o600)
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise DeploymentError('此部署目錄有另一個操作正在進行；請等待該操作結束後再試。') from error
        try:
            yield
        finally:
            # Keep the inode: unlinking a lock file can let concurrent callers lock different files.
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def render_envoy(config: dict) -> dict:
    from .renderer import render_envoy as render
    return render(config)


def render_policy(config: dict) -> dict:
    from .ratelimit import render_policy as render
    return render(config)


def policy_source() -> str:
    return resources.files('siteguard').joinpath('ratelimit.py').read_text(encoding='utf-8')


def bind_mount(source: str, target: str) -> dict:
    return {'type': 'bind', 'source': source.replace('$', '$$'), 'target': target,
            'read_only': True, 'bind': {'create_host_path': False}}


def build_contexts(source: str) -> dict:
    return {'gateway': {'Dockerfile': GATEWAY_DOCKERFILE},
            'policy': {'Dockerfile': POLICY_DOCKERFILE, 'requirements.txt': POLICY_REQUIREMENTS,
                       'ratelimit.py': source,
                       'inspection.py': resources.files('siteguard').joinpath('inspection.py').read_text(encoding='utf-8')}}


def context_hash(contents: dict) -> str:
    return hashlib.sha256(json.dumps(contents, sort_keys=True).encode()).hexdigest()


def compose_config(config: dict, source: str | None = None) -> dict:
    listener = config['listener']
    uid = os.getuid() if hasattr(os, 'getuid') else 1000
    gid = os.getgid() if hasattr(os, 'getgid') else 1000
    contexts = build_contexts(policy_source() if source is None else source)
    volumes = [bind_mount('./envoy.yaml', '/etc/siteguard/envoy.yaml')]
    tls = listener.get('tls')
    if tls:
        volumes.extend([
            bind_mount(str(tls['certificate']), '/etc/siteguard/tls/certificate.pem'),
            bind_mount(str(tls['private_key']), '/etc/siteguard/tls/private-key.pem'),
        ])
    if config['upstream'].get('tls_ca_file'):
        volumes.append(bind_mount(str(config['upstream']['tls_ca_file']),
                                  '/etc/siteguard/tls/upstream-ca.pem'))
    compose = {'name': config['name'], 'x-siteguard': GENERATED_MARKER, 'services': {SERVICE: {
        'image': f'{config["name"]}-gateway:{context_hash(contexts["gateway"])}',
        'build': {'context': './gateway'},
        'entrypoint': ['envoy'],
        'command': ['-c', '/etc/siteguard/envoy.yaml', '--concurrency', '2', '--log-level', 'info'],
        'user': f'{uid}:{gid}' if uid else '101:101',
        'ports': [{'target': 8080, 'published': str(listener['port']),
                   'host_ip': listener['host'], 'protocol': 'tcp'}],
        'volumes': volumes,
        'extra_hosts': ['host.docker.internal:host-gateway'],
        'cpus': 1.0, 'mem_limit': '512m', 'pids_limit': 128,
        'read_only': True, 'tmpfs': ['/tmp:size=32m,mode=1777'],
        'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
        'restart': 'unless-stopped', 'stop_grace_period': '30s',
        'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}},
        'networks': ['front', 'policy'],
        'depends_on': {'policy': {'condition': 'service_healthy'}},
        'healthcheck': {'test': ['CMD', 'curl', '--fail', '--silent', '--max-time', '2',
                                 'http://127.0.0.1:9901/ready'],
                        'interval': '5s', 'timeout': '3s', 'retries': 12, 'start_period': '5s'},
    }, 'policy': {
        'image': f'{config["name"]}-policy:{context_hash(contexts["policy"])}',
        'build': {'context': './policy'},
        'user': '101:101',
        'volumes': [bind_mount('./policy.json', '/etc/siteguard/policy.json')],
        'networks': ['policy'],
        'cpus': .5, 'mem_limit': '256m', 'pids_limit': 64,
        'read_only': True, 'tmpfs': ['/tmp:size=16m,mode=1777'],
        'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
        'restart': 'unless-stopped', 'stop_grace_period': '10s',
        'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}},
        'healthcheck': {'test': ['CMD', 'python', '-c',
                                 "import socket; [socket.create_connection(('127.0.0.1', port), timeout=2).close() for port in (50051, 50052)]"],
                        'interval': '5s', 'timeout': '3s', 'retries': 12, 'start_period': '5s'},
    }}, 'networks': {'front': {}, 'policy': {'internal': True}}}
    if config['upstream'].get('network'):
        compose['services'][SERVICE]['networks'].append('existing-origin')
        compose['networks']['existing-origin'] = {'external': True, 'name': config['upstream']['network']}
    return compose


def render_files(config: dict, output: Path) -> dict[str, Path]:
    with deployment_lock(output):
        return _render_files(config, output)


def _render_files(config: dict, output: Path) -> dict[str, Path]:
    output = output.resolve()
    require_managed_output(output)
    if (output / '.siteguard' / 'active.json').exists() or (output / '.siteguard' / 'target.json').exists():
        raise DeploymentError('此目錄已有部署紀錄；請用 up 更新，或 render 到另一個目錄。')
    envoy = render_envoy(config)
    source = policy_source()
    compose = compose_config(config, source)
    policy = render_policy(config)
    output.mkdir(parents=True, exist_ok=True)
    files = {'envoy': output / 'envoy.yaml', 'compose': output / 'compose.yaml',
             'policy': output / 'policy.json'}
    for key, value in (('envoy', envoy), ('compose', compose)):
        files[key].write_text(yaml.safe_dump(value, sort_keys=False), encoding='utf-8')
        files[key].chmod(0o644)
    files['policy'].write_text(json.dumps(policy, indent=2) + '\n', encoding='utf-8')
    files['policy'].chmod(0o644)
    for folder, contents in build_contexts(source).items():
        context = output / folder
        context.mkdir(exist_ok=True)
        allowed = '\n'.join(f'!{name}' for name in contents)
        (context / '.dockerignore').write_text(f'*\n{allowed}\n', encoding='utf-8')
        for name, value in contents.items():
            target = context / name
            target.write_text(value, encoding='utf-8')
            target.chmod(0o644)
    return files


def compose_argv(output: Path, context: str | None = None) -> list[str]:
    output = output.resolve()
    if not (output / 'compose.yaml').is_file():
        raise DeploymentError(f'找不到部署設定：{output / "compose.yaml"}；請先執行 render 或 up。')
    document = yaml.safe_load((output / 'compose.yaml').read_text(encoding='utf-8'))
    project_name = document.get('name') if isinstance(document, dict) else None
    if not isinstance(project_name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,39}', project_name):
        raise DeploymentError('部署設定缺少有效的 SiteGuard 專案名稱；請重新 render。')
    receipt = active_receipt(output) or target_receipt(output)
    if receipt:
        if project_name != receipt['project_name']:
            raise DeploymentError('產生的 Compose 專案名稱與部署紀錄不同；請用 up 恢復設定。')
        if context is not None and context != receipt['docker_context']:
            raise DeploymentError('此部署目錄已綁定另一個 Docker context；請使用另一個 output 目錄。')
        context = receipt['docker_context']
    argv = ['docker']
    if context:
        argv.extend(['--context', context])
    return argv + ['compose', '--project-name', project_name, '--file', str(output / 'compose.yaml'),
                   '--project-directory', str(output), '--env-file', os.devnull]


def docker_command(argv: list[str], *, capture: bool = True, timeout: int | None = 180) -> str:
    try:
        result = subprocess.run(argv, capture_output=capture, text=True, check=False, timeout=timeout)
    except FileNotFoundError as exc:
        raise DeploymentError('找不到 Docker CLI。請安裝 Docker Engine／Docker Desktop 與 Compose。') from exc
    except subprocess.TimeoutExpired as exc:
        raise DeploymentError('Docker 操作逾時；請用 status 與 logs 檢查實際狀態。') from exc
    if result.returncode:
        details = (result.stderr or result.stdout or '').strip() if capture else ''
        raise DeploymentError(f'Docker 操作失敗（exit {result.returncode}）。\n{details}')
    return (result.stdout or '').strip() if capture else ''


def active_receipt(output: Path) -> dict | None:
    path = output / '.siteguard' / 'active.json'
    return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else None


def target_receipt(output: Path) -> dict | None:
    path = output / '.siteguard' / 'target.json'
    return json.loads(path.read_text(encoding='utf-8')) if path.is_file() else None


def require_managed_output(output: Path) -> None:
    path = output / 'compose.yaml'
    if not path.exists() or active_receipt(output) or target_receipt(output):
        return
    try:
        document = yaml.safe_load(path.read_text(encoding='utf-8'))
    except (OSError, yaml.YAMLError):
        document = None
    if (not isinstance(document, dict) or document.get('x-siteguard') != GENERATED_MARKER
            or not isinstance(document.get('services'), dict)
            or set(document['services']) != {'gateway', 'policy'}):
        raise DeploymentError('output 已包含不屬於 SiteGuard 的 compose.yaml；請使用另一個 output 目錄，'
                              '不會覆寫或操作該 Compose 專案。')


def ownership_preflight(project_name: str, output: Path, context: str) -> None:
    docker = ['docker', '--context', context]
    raw = docker_command(docker + ['ps', '--all', '--filter',
                                  f'label=com.docker.compose.project={project_name}', '--format', '{{.ID}}'])
    identifiers = raw.splitlines()
    if not identifiers:
        return
    if any(not re.fullmatch(r'[a-f0-9]{12,64}', identifier) for identifier in identifiers):
        raise DeploymentError('無法確認既有 Docker 專案的容器識別碼；已停止操作。')
    labels = docker_command(docker + ['inspect', '--format', '{{json .Config.Labels}}', *identifiers])
    try:
        documents = [json.loads(line) for line in labels.splitlines()]
    except json.JSONDecodeError as error:
        raise DeploymentError('無法解析既有 Docker 專案的擁有目錄；已停止操作。') from error
    if len(documents) != len(identifiers):
        raise DeploymentError('Docker 容器擁有目錄資料不完整；已停止操作。')
    for document in documents:
        directory = document.get('com.docker.compose.project.working_dir') if isinstance(document, dict) else None
        if (not isinstance(directory, str) or not directory or not Path(directory).is_absolute()
                or Path(directory).resolve() != output.resolve()):
            raise DeploymentError(f'Docker 專案 {project_name} 已由其他目錄管理，或缺少擁有目錄標記；'
                                  '請使用不同的 name／output，不會停止、移除或更新既有容器。')


def write_record(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.chmod(0o600)
    temporary.replace(path)


def history(output: Path, **record) -> None:
    folder = output / '.siteguard'
    folder.mkdir(parents=True, exist_ok=True)
    record['at'] = dt.datetime.now(dt.timezone.utc).isoformat()
    with (folder / 'history.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(record, ensure_ascii=False) + '\n')


def bundle_files(folder: Path) -> tuple[str, ...]:
    return BUNDLE_FILES if (folder / 'policy/inspection.py').exists() else LEGACY_BUNDLE_FILES


def bundle_hash(folder: Path) -> str:
    digest = hashlib.sha256()
    for name in bundle_files(folder):
        digest.update(name.encode() + b'\0' + (folder / name).read_bytes() + b'\0')
    return digest.hexdigest()


def copy_bundle(source: Path, target: Path) -> None:
    files = bundle_files(source)
    for name in files:
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, path)
        path.chmod(0o644)
    for name in set(BUNDLE_FILES) - set(files):
        (target / name).unlink(missing_ok=True)


def saved_bundle(output: Path, version: str) -> Path:
    if not re.fullmatch(r'[a-f0-9]{64}', version):
        raise DeploymentError('部署快照版本無效。')
    folder = output / '.siteguard' / 'versions' / version
    try:
        valid = folder.is_dir() and bundle_hash(folder) == version
    except OSError:
        valid = False
    if not valid:
        raise DeploymentError('部署快照遺失或已變更，無法安全回復。')
    return folder


def save_bundle(staged: Path, output: Path) -> tuple[str, Path]:
    version = bundle_hash(staged)
    folder = output / '.siteguard' / 'versions' / version
    if folder.exists():
        saved_bundle(output, version)
    else:
        copy_bundle(staged, folder)
    return version, folder


def deployment_context(context: str | None, previous: dict | None) -> str:
    if previous:
        if context is not None and context != previous['docker_context']:
            raise DeploymentError('此部署目錄已綁定另一個 Docker context；請使用另一個 output 目錄。')
        return previous['docker_context']
    return context or docker_command(['docker', 'context', 'show'])


def ensure_images(staged: Path, context: str) -> None:
    compose = yaml.safe_load((staged / 'compose.yaml').read_text(encoding='utf-8'))
    missing = []
    for service, definition in compose['services'].items():
        try:
            docker_command(['docker', '--context', context, 'image', 'inspect',
                            '--format', '{{.Id}}', definition['image']])
        except DeploymentError:
            missing.append(service)
    if missing:
        docker_command(compose_argv(staged, context) + ['build', *missing], timeout=1200)


def validate_bundle(folder: Path, context: str) -> None:
    docker_command(compose_argv(folder, context) + ['run', '--rm', '--no-deps', '--pull', 'never', SERVICE,
                   '--mode', 'validate', '-c', '/etc/siteguard/envoy.yaml'])


def start_bundle(output: Path, context: str, wait_timeout: int) -> None:
    docker_command(compose_argv(output, context) + ['up', '-d', '--no-build', '--pull', 'never',
                   '--force-recreate', '--wait', '--wait-timeout', str(wait_timeout)],
                   timeout=wait_timeout + 120)


def failure_record(output: Path, context: str, action: str, version: str, error: Exception) -> Path:
    path = output / '.siteguard' / 'failures' / f'{time.time_ns()}.json'
    record = {'action': action, 'version': version, 'error': str(error)}
    for name, suffix in (('containers', ['ps', '--all', '--format', 'json']),
                         ('logs', ['logs', '--no-color', '--tail', '100'])):
        try:
            record[name] = docker_command(compose_argv(output, context) + suffix, timeout=15)
        except (DeploymentError, OSError, ValueError, yaml.YAMLError) as diagnostic_error:
            record[name] = str(diagnostic_error)
    write_record(path, record)
    return path


def activate_bundle(output: Path, version: str, folder: Path, context: str,
                    previous: dict | None, action: str, wait_timeout: int) -> None:
    project_name = yaml.safe_load((folder / 'compose.yaml').read_text())['name']
    write_record(output / '.siteguard' / 'target.json',
                 {'project_name': project_name, 'docker_context': context})
    try:
        copy_bundle(folder, output)
        start_bundle(output, context, wait_timeout)
    except (DeploymentError, OSError) as error:
        diagnostic = failure_record(output, context, action, version, error)
        if previous:
            try:
                copy_bundle(saved_bundle(output, previous['version']), output)
                start_bundle(output, context, wait_timeout)
            except (DeploymentError, OSError) as restore_error:
                history(output, action=action, version=version, status='recovery_failed',
                        restored_version=previous['version'], diagnostic=str(diagnostic),
                        recovery_error=str(restore_error))
                raise DeploymentError(f'更新失敗，前一版本也未能恢復。請立即檢查 status/logs；診斷：{diagnostic}\n'
                                      f'{error}\n回復錯誤：{restore_error}') from error
            history(output, action=action, version=version, status='failed_recovered',
                    restored_version=previous['version'], diagnostic=str(diagnostic))
            raise DeploymentError(f'更新失敗，已恢復前一成功版本。診斷：{diagnostic}\n{error}') from error
        history(output, action=action, version=version, status='failed_no_previous', diagnostic=str(diagnostic))
        raise DeploymentError(f'首次部署失敗，沒有先前成功版本可回復。已保留設定、容器與診斷：{diagnostic}；'
                              f'請用 status/logs 檢查，確認後可用 down 停止本部署。\n{error}') from error
    prior_version = previous['version'] if previous else None
    if previous and prior_version == version:
        prior_version = previous.get('previous_version')
    record = {'version': version, 'previous_version': prior_version, 'docker_context': context,
              'project_name': project_name,
              'updated_at': dt.datetime.now(dt.timezone.utc).isoformat()}
    write_record(output / '.siteguard' / 'active.json', record)
    history(output, action=action, version=version, status='complete', previous_version=prior_version)


def up(config: dict, output: Path, context: str | None = None, wait_timeout: int = 60) -> None:
    with deployment_lock(output):
        _up(config, output, context, wait_timeout)


def _up(config: dict, output: Path, context: str | None = None, wait_timeout: int = 60) -> None:
    output = output.resolve()
    require_managed_output(output)
    previous = active_receipt(output)
    target = previous or target_receipt(output)
    if target and target['project_name'] != config['name']:
        raise DeploymentError('不可在既有部署目錄變更 name；請使用新的 output 目錄。')
    context = deployment_context(context, target)
    ownership_preflight(config['name'], output, context)
    if previous:
        saved_bundle(output, previous['version'])
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.siteguard-validate-', dir=output.parent) as candidate:
        staged = Path(candidate)
        render_files(config, staged)
        ensure_images(staged, context)
        validate_bundle(staged, context)
        version, folder = save_bundle(staged, output)
    activate_bundle(output, version, folder, context, previous, 'up', wait_timeout)


def rollback(output: Path, context: str | None = None, wait_timeout: int = 60) -> None:
    with deployment_lock(output):
        _rollback(output, context, wait_timeout)


def _rollback(output: Path, context: str | None = None, wait_timeout: int = 60) -> None:
    output = output.resolve()
    previous = active_receipt(output)
    if not previous or not previous.get('previous_version'):
        raise DeploymentError('沒有前一成功版本可 rollback。')
    context = deployment_context(context, previous)
    ownership_preflight(previous['project_name'], output, context)
    folder = saved_bundle(output, previous['previous_version'])
    validate_bundle(folder, context)
    activate_bundle(output, previous['previous_version'], folder, context, previous, 'rollback', wait_timeout)


def status(output: Path, context: str | None = None) -> dict:
    raw = docker_command(compose_argv(output, context) + ['ps', '--all', '--format', 'json'])
    if not raw:
        containers = []
    else:
        try:
            parsed = json.loads(raw)
            containers = parsed if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            containers = [json.loads(line) for line in raw.splitlines() if line.strip()]
    running = bool(containers) and all(row.get('State') == 'running' for row in containers)
    missing_services = sorted({'gateway', 'policy'} - {row.get('Service') for row in containers})
    ready = False if not running or missing_services else None
    if running and not missing_services and all(row.get('Health') == 'healthy' for row in containers):
        ready = True
    elif any(row.get('Health') in ('unhealthy', 'starting') for row in containers):
        ready = False
    return {'running': running, 'ready': ready, 'containers': containers,
            'missing_services': missing_services,
            'deployment': active_receipt(output),
            'notice': 'running 表示容器執行中。ready 依代理與限流服務健康檢查判定；不代表來源網站與端到端可用性。ready=null 表示缺少健康檢查。'}


def metrics(output: Path, context: str | None = None, format: str = 'json') -> str:
    path = '/stats?format=json' if format == 'json' else '/stats/prometheus'
    return docker_command(compose_argv(output, context) + [
        'exec', '-T', SERVICE, 'curl', '--fail', '--silent', '--show-error', '--max-time', '5',
        f'http://127.0.0.1:9901{path}'], timeout=15)


def logs(output: Path, context: str | None = None, tail: int = 100, follow: bool = False,
         service: str = 'all') -> None:
    command = compose_argv(output, context) + ['logs', '--no-color', '--tail', str(tail)]
    if follow:
        command.append('--follow')
    if service != 'all':
        command.append(service)
    docker_command(command, capture=False, timeout=None if follow else 30)


def down(output: Path, context: str | None = None) -> None:
    with deployment_lock(output):
        output = output.resolve()
        require_managed_output(output)
        command = compose_argv(output, context)
        project_name = command[command.index('--project-name') + 1]
        context = deployment_context(context, active_receipt(output) or target_receipt(output))
        ownership_preflight(project_name, output, context)
        docker_command(compose_argv(output, context) + ['down', '--timeout', '30'])
