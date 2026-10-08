"""Render the four comparable Envoy lab configurations."""
from __future__ import annotations

import argparse
from pathlib import Path

import yaml


MODES = ('off', 'adaptive', 'rls', 'rls_adaptive')
TYPE_PREFIX = 'type.googleapis.com/'


def socket_address(address: str, port: int) -> dict:
    return {'socket_address': {'address': address, 'port_value': port}}


def cluster(name: str, host: str, port: int) -> dict:
    return {
        'name': name,
        'type': 'STRICT_DNS',
        'connect_timeout': '1s',
        'lb_policy': 'ROUND_ROBIN',
        'load_assignment': {
            'cluster_name': name,
            'endpoints': [{'lb_endpoints': [{'endpoint': {'address': socket_address(host, port)}}]}],
        },
        'circuit_breakers': {'thresholds': [{
            'max_connections': 64,
            'max_pending_requests': 24,
            'max_requests': 64,
            'max_retries': 0,
        }]},
    }


def build_config(mode: str, upstream: str = 'app', rls_host: str = 'rls',
                 bind: str = '0.0.0.0', admin_bind: str = '0.0.0.0') -> dict:
    if mode not in MODES:
        raise ValueError(f'unknown mode: {mode}')
    use_rls = mode in ('rls', 'rls_adaptive')
    routes = []
    for path, kind in (('/health', None), ('/live', None), ('/', None), ('/ui.js', None),
                       ('/api/products', 'products'), ('/api/orders', 'orders'),
                       ('/api/report', 'report')):
        action = {'cluster': 'app', 'timeout': '5s'}
        if use_rls and kind:
            action['rate_limits'] = [{'actions': [{'generic_key': {
                'descriptor_key': 'kind', 'descriptor_value': kind,
            }}]}]
        routes.append({'match': {'path': path}, 'route': action})
    routes.append({'match': {'prefix': '/'}, 'direct_response': {
        'status': 404, 'body': {'inline_string': 'not exposed by the lab gateway\n'},
    }})

    filters = [{
        'name': 'envoy.filters.http.health_check',
        'typed_config': {
            '@type': TYPE_PREFIX + 'envoy.extensions.filters.http.health_check.v3.HealthCheck',
            'pass_through_mode': True,
            'headers': [{'name': ':path', 'string_match': {
                'safe_regex': {'regex': '^/(health|live)$'}}}],
        },
    }, {
        'name': 'envoy.filters.http.buffer',
        'typed_config': {
            '@type': TYPE_PREFIX + 'envoy.extensions.filters.http.buffer.v3.Buffer',
            'max_request_bytes': 16384,
        },
    }]
    if use_rls:
        filters.append({
            'name': 'envoy.filters.http.ratelimit',
            'typed_config': {
                '@type': TYPE_PREFIX + 'envoy.extensions.filters.http.ratelimit.v3.RateLimit',
                'domain': 'local-ddos-lab',
                'timeout': '0.1s',
                'failure_mode_deny': True,
                'status_on_error': {'code': 'ServiceUnavailable'},
                'rate_limit_service': {
                    'transport_api_version': 'V3',
                    'grpc_service': {'envoy_grpc': {'cluster_name': 'rls'}},
                },
            },
        })
    if mode in ('adaptive', 'rls_adaptive'):
        filters.append({
            'name': 'envoy.filters.http.adaptive_concurrency',
            'typed_config': {
                '@type': TYPE_PREFIX + 'envoy.extensions.filters.http.adaptive_concurrency.v3.AdaptiveConcurrency',
                'gradient_controller_config': {
                    'sample_aggregate_percentile': {'value': 90},
                    'concurrency_limit_params': {
                        'max_concurrency_limit': 24,
                        'concurrency_update_interval': '0.1s',
                    },
                    'min_rtt_calc_params': {
                        'interval': '60s',
                        'request_count': 50,
                        'jitter': {'value': 10},
                        'min_concurrency': 3,
                        'buffer': {'value': 25},
                    },
                },
                'enabled': {'default_value': True},
            },
        })
    filters.append({
        'name': 'envoy.filters.http.router',
        'typed_config': {'@type': TYPE_PREFIX + 'envoy.extensions.filters.http.router.v3.Router'},
    })
    clusters = [cluster('app', upstream, 8000)]
    if use_rls:
        rls_cluster = cluster('rls', rls_host, 50051)
        rls_cluster['typed_extension_protocol_options'] = {
            'envoy.extensions.upstreams.http.v3.HttpProtocolOptions': {
                '@type': TYPE_PREFIX + 'envoy.extensions.upstreams.http.v3.HttpProtocolOptions',
                'explicit_http_config': {'http2_protocol_options': {}},
            },
        }
        clusters.append(rls_cluster)

    return {
        'admin': {'address': socket_address(admin_bind, 9901)},
        'static_resources': {
            'listeners': [{
                'name': 'lab_gateway',
                'address': socket_address(bind, 8080),
                'per_connection_buffer_limit_bytes': 65536,
                'filter_chains': [{'filters': [{
                    'name': 'envoy.filters.network.http_connection_manager',
                    'typed_config': {
                        '@type': TYPE_PREFIX + 'envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager',
                        'stat_prefix': 'lab_gateway',
                        'codec_type': 'AUTO',
                        'normalize_path': True,
                        'merge_slashes': True,
                        'path_with_escaped_slashes_action': 'REJECT_REQUEST',
                        'max_request_headers_kb': 32,
                        'request_timeout': '6s',
                        'stream_idle_timeout': '6s',
                        'common_http_protocol_options': {'idle_timeout': '15s'},
                        'route_config': {
                            'name': 'lab_routes',
                            'request_headers_to_remove': ['x-lab-admin'],
                            'response_headers_to_add': [{
                                'header': {'key': 'X-Lab-Gateway-Mode', 'value': mode},
                                'append_action': 'OVERWRITE_IF_EXISTS_OR_ADD',
                            }],
                            'virtual_hosts': [{'name': 'lab', 'domains': ['*'], 'routes': routes}],
                        },
                        'http_filters': filters,
                        'access_log': [{
                            'name': 'envoy.access_loggers.stdout',
                            'typed_config': {
                                '@type': TYPE_PREFIX + 'envoy.extensions.access_loggers.stream.v3.StdoutAccessLog',
                                'log_format': {'json_format': {
                                    'time': '%START_TIME%',
                                    'method': '%REQ(:METHOD)%',
                                    'path': '%REQ(:PATH)%',
                                    'status': '%RESPONSE_CODE%',
                                    'duration_ms': '%DURATION%',
                                    'flags': '%RESPONSE_FLAGS%',
                                    'details': '%RESPONSE_CODE_DETAILS%',
                                }},
                            },
                        }],
                    },
                }]}],
            }],
            'clusters': clusters,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=MODES, required=True)
    parser.add_argument('--upstream', default='app')
    parser.add_argument('--rls-host', default='rls')
    parser.add_argument('--bind', default='0.0.0.0')
    parser.add_argument('--admin-bind', default='0.0.0.0')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    config = build_config(args.mode, args.upstream, args.rls_host, args.bind, args.admin_bind)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(yaml.safe_dump(config, sort_keys=False), encoding='utf-8')


if __name__ == '__main__':
    main()
