"""Command-line entry point for local configuration and Docker deployment."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import yaml

from . import __version__, deployment


def load_config(path: Path) -> dict:
    from .config import load_config as load
    return load(path)


def example_config(upstream: str) -> dict:
    from .config import example_config as example
    return example(upstream)


def security_summary(config: dict) -> str:
    security = config['security']
    firewall = config['firewall']
    mode = config['mode']
    guarded = sum(route['response_guard'] for route in config['routes'])
    enabled = guarded if mode == 'enforce' else 0
    lines = [
        '安全設定摘要（執行 up 後生效，非目前部署狀態）：',
        f'  模式：{mode}',
        f'  網站入口防火牆：預設 {firewall["default_action"]}；允許 {len(firewall["allow_cidrs"])} 個網段／封鎖 {len(firewall["deny_cidrs"])} 個網段；封鎖優先',
        f'  敏感檔案路徑封鎖：設定{"開啟" if security["block_sensitive_paths"] else "關閉"}',
        f'  封鎖 methods：{len(security["blocked_methods"])} 種',
        f'  protected_paths：{len(security["protected_paths"])} 條',
        f'  回應安全標頭：設定{"開啟" if security["response_headers"] else "關閉"}',
        f'  response_guard：設定 {guarded} 條／依此模式實際啟用 {enabled} 條',
    ]
    if firewall['default_action'] == 'deny' and not firewall['allow_cidrs']:
        lines.append('  防火牆未設定允許來源：enforce 將封鎖所有網站請求。')
    if mode == 'observe':
        lines.append('observe 只記錄資安請求影子規則，不封鎖；不掃描回應內容，response_guard 尚未提供防洩漏保護。')
    else:
        lines.append('enforce 會套用請求防護；只檢查明確啟用 response_guard 的小型 API 回應，並非完整資料外洩防護。')
    return '\n'.join(lines)


def common_arguments(parser: argparse.ArgumentParser, suppress: bool = False) -> None:
    parser.add_argument('--config', type=Path, default=argparse.SUPPRESS if suppress else Path('siteguard.yaml'))
    parser.add_argument('--output', type=Path, default=argparse.SUPPRESS if suppress else Path('siteguard-deploy'))
    parser.add_argument('--docker-context', default=argparse.SUPPRESS if suppress else None)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='siteguard', description='自架式 Envoy 網站防護閘道')
    parser.add_argument('--version', action='version', version=f'siteguard {__version__}')
    common_arguments(parser)
    commands = parser.add_subparsers(dest='command', required=True)
    for name, help_text in [('init', '產生起始設定'), ('check', '本機檢查設定格式'),
                            ('render', '產生 Envoy 與 Compose 設定'),
                            ('up', '經 Envoy 原生驗證後啟動'), ('status', '讀取實際容器狀態'),
                            ('logs', '查看代理日誌'), ('metrics', '讀取容器內代理指標'),
                            ('rollback', '恢復前一成功部署版本'),
                            ('down', '停止並移除本部署容器')]:
        command = commands.add_parser(name, help=help_text)
        common_arguments(command, suppress=True)
        if name == 'init':
            command.add_argument('--upstream', default='http://host.docker.internal:8000')
            command.add_argument('--force', action='store_true', help='覆寫既有設定')
        elif name in ('up', 'rollback'):
            command.add_argument('--wait-timeout', type=int, default=60)
        elif name == 'logs':
            command.add_argument('--tail', type=int, default=100)
            command.add_argument('--follow', action='store_true')
            command.add_argument('--service', choices=('all', 'gateway', 'policy'), default='all')
        elif name == 'metrics':
            command.add_argument('--format', choices=('json', 'prometheus'), default='json')
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in ('up', 'rollback') and not 1 <= args.wait_timeout <= 600:
        parser.error('--wait-timeout 必須介於 1 與 600 秒。')
    if args.command == 'logs' and not 1 <= args.tail <= 10000:
        parser.error('--tail 必須介於 1 與 10000。')
    try:
        if args.command == 'init':
            if args.config.exists() and not args.force:
                raise ValueError(f'設定已存在：{args.config}；需要覆寫時請加 --force。')
            config = example_config(args.upstream)
            args.config.parent.mkdir(parents=True, exist_ok=True)
            args.config.write_text(yaml.safe_dump(config, sort_keys=False), encoding='utf-8')
            print(f'已建立設定：{args.config.resolve()}；啟動前請檢查 upstream 與防護模式。')
        elif args.command == 'check':
            config = load_config(args.config)
            print('設定格式有效。尚未執行 Envoy 原生驗證，也未探測上游。')
            print(security_summary(config))
        elif args.command == 'render':
            files = deployment.render_files(load_config(args.config), args.output)
            print(f'已產生：{files["envoy"]}\n已產生：{files["compose"]}')
        elif args.command == 'up':
            print('正在建置隔離映像並執行 Envoy 原生驗證；首次建置需要下載固定基底映像與套件。', flush=True)
            deployment.up(load_config(args.config), args.output, args.docker_context, args.wait_timeout)
            print('Envoy 原生驗證與容器健康檢查通過。請執行 status 查看狀態，並實際送出請求驗證來源網站。')
        elif args.command == 'status':
            print(json.dumps(deployment.status(args.output, args.docker_context), ensure_ascii=False, indent=2))
        elif args.command == 'logs':
            deployment.logs(args.output, args.docker_context, args.tail, args.follow, args.service)
        elif args.command == 'metrics':
            print(deployment.metrics(args.output, args.docker_context, args.format))
        elif args.command == 'rollback':
            deployment.rollback(args.output, args.docker_context, args.wait_timeout)
            print('已恢復前一成功部署，原生驗證與容器健康檢查通過。外部憑證檔不包含在版本回復內。')
        elif args.command == 'down':
            deployment.down(args.output, args.docker_context)
            print('已停止並移除本部署容器；產生的設定檔仍保留。')
    except KeyboardInterrupt:
        print('操作已中斷；容器可能仍在執行，請用 status 確認。', file=sys.stderr)
        return 130
    except (OSError, ValueError, deployment.DeploymentError, yaml.YAMLError) as exc:
        print(f'錯誤：{exc}', file=sys.stderr)
        return 1
    return 0
