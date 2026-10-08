"""Check YAML and official protobuf field types, without starting Envoy."""
from __future__ import annotations

import argparse
import importlib
from pathlib import Path

import yaml
from envoy.config.bootstrap.v3.bootstrap_pb2 import Bootstrap
from google.protobuf.json_format import ParseDict


for module in (
    'envoy.extensions.filters.network.http_connection_manager.v3.http_connection_manager_pb2',
    'envoy.extensions.filters.http.adaptive_concurrency.v3.adaptive_concurrency_pb2',
    'envoy.extensions.filters.http.buffer.v3.buffer_pb2',
    'envoy.extensions.filters.http.health_check.v3.health_check_pb2',
    'envoy.extensions.filters.http.ratelimit.v3.rate_limit_pb2',
    'envoy.extensions.filters.http.router.v3.router_pb2',
    'envoy.extensions.access_loggers.stream.v3.stream_pb2',
    'envoy.extensions.upstreams.http.v3.http_protocol_options_pb2',
):
    importlib.import_module(module)


def validate(path: Path) -> Bootstrap:
    return ParseDict(yaml.safe_load(path.read_text(encoding='utf-8')), Bootstrap())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('files', nargs='*', type=Path)
    args = parser.parse_args()
    paths = args.files or sorted((Path(__file__).parent / 'envoy').glob('*.yaml'))
    for path in paths:
        validate(path)
        print(f'protobuf schema OK: {path}')
    print('Schema-only check. Run Envoy v1.39.1 --mode validate and HTTP smoke tests before claiming runtime validation.')


if __name__ == '__main__':
    main()
