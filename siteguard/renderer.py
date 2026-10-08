"""Compile validated policy into Envoy, keeping application traffic off Python."""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from . import security


TYPE = 'type.googleapis.com/'
BUFFER = 'envoy.filters.http.buffer'
BODY_LIMIT = 'envoy.filters.http.lua'
RATE_LIMIT = 'envoy.filters.http.ratelimit'
ROUTER = 'envoy.filters.http.router'
H2_OPTIONS = {'initial_stream_window_size': 65536, 'initial_connection_window_size': 1048576,
              'max_concurrent_streams': 100}
BODY_LIMIT_SCRIPT = '''function envoy_on_request(handle)
  local body = handle:body()
  if body and body:length() > MAX_BODY_BYTES then
    handle:respond({[":status"] = "413", ["content-type"] = "text/plain"}, "Payload Too Large")
  end
end
'''


def typed(name: str, message: str, **fields) -> dict:
    return {'name': name, 'typed_config': {'@type': TYPE + message, **fields}}


def address(host: str, port: int) -> dict:
    return {'socket_address': {'address': host, 'port_value': port}}


def seconds(value) -> str:
    return f'{value:g}s'


def upstream_cluster(config: dict, name: str, limit: int) -> dict:
    upstream = config['upstream']
    parsed = urlsplit(upstream['url'])
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    enforce = config['mode'] == 'enforce'
    limit = limit if enforce else 1024
    threshold = {'max_connections': limit, 'max_requests': limit,
                 'max_pending_requests': config['policy']['queue_size'] if enforce else 1024,
                 'max_retries': 0, 'track_remaining': True}
    protocol = upstream['protocol']
    options = {'@type': TYPE + 'envoy.extensions.upstreams.http.v3.HttpProtocolOptions'}
    if protocol == 'auto':
        options['auto_config'] = {'http_protocol_options': {}, 'http2_protocol_options': dict(H2_OPTIONS)}
    else:
        options['explicit_http_config'] = {
            'http2_protocol_options' if protocol == 'http2' else 'http_protocol_options':
                dict(H2_OPTIONS) if protocol == 'http2' else {}}
    result = {
        'name': name, 'type': 'STRICT_DNS', 'connect_timeout': '3s',
        'lb_policy': 'ROUND_ROBIN', 'dns_lookup_family': 'AUTO',
        'per_connection_buffer_limit_bytes': 65536,
        'load_assignment': {'cluster_name': name, 'endpoints': [{'lb_endpoints': [
            {'endpoint': {'address': address(host, port)}}]}]},
        'circuit_breakers': {'thresholds': [threshold]},
        'typed_extension_protocol_options': {
            'envoy.extensions.upstreams.http.v3.HttpProtocolOptions': options},
    }
    if parsed.scheme == 'https':
        ca = '/etc/siteguard/tls/upstream-ca.pem' if upstream.get('tls_ca_file') else '/etc/ssl/certs/ca-certificates.crt'
        context = {'validation_context': {'trusted_ca': {'filename': ca}},
                   'alpn_protocols': ['h2', 'http/1.1'] if protocol != 'http1' else ['http/1.1'],
                   'tls_params': {'tls_minimum_protocol_version': 'TLSv1_2'}}
        tls = {'common_tls_context': context}
        try:
            ipaddress.ip_address(host)
        except ValueError:
            tls.update(sni=host, auto_sni_san_validation=True)
        else:
            context['validation_context']['match_typed_subject_alt_names'] = [
                {'san_type': 'IP_ADDRESS', 'matcher': {'exact': host}}]
        result['transport_socket'] = typed(
            'envoy.transport_sockets.tls', 'envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext', **tls)
    return result


def render_envoy(config: dict) -> dict:
    policy = config['policy']
    enforce = config['mode'] == 'enforce'
    reserved = sum(route.get('max_concurrent', 0) for route in config['routes'])
    clusters = [upstream_cluster(config, 'origin_default', policy['max_concurrent'] - reserved)]
    routes = []
    has_inspection = any(rule.get('response_guard', False) for rule in config['routes'])
    for rule in [*config['routes'], {'name': 'default', 'prefix': '/', 'streaming': False}]:
        name = rule['name']
        cluster = 'origin_default'
        if 'max_concurrent' in rule:
            cluster = f'origin_{name}'
            clusters.append(upstream_cluster(config, cluster, rule['max_concurrent']))
        streaming = rule['streaming']
        route_action = {
            'cluster': cluster,
            'timeout': '0s' if streaming else seconds(rule.get('timeout_seconds', policy['request_timeout_seconds'])),
            'idle_timeout': seconds(policy['stream_idle_timeout_seconds']),
            'rate_limits': [{'actions': [
                {'generic_key': {'descriptor_key': 'scope', 'descriptor_value': 'site'}},
                {'remote_address': {}},
                {'generic_key': {'descriptor_key': 'route', 'descriptor_value': name}},
            ]}],
            'upgrade_configs': [{'upgrade_type': 'websocket', 'enabled': streaming}],
        }
        if not streaming:
            route_action['max_stream_duration'] = {'max_stream_duration': seconds(
                rule.get('timeout_seconds', policy['request_timeout_seconds']))}
        if not config['upstream']['preserve_host']:
            route_action['host_rewrite_literal'] = urlsplit(config['upstream']['url']).netloc
        route = {
            'name': name,
            'match': {'prefix': '/'} if name == 'default' else {'path_separated_prefix': rule['prefix']},
            'route': route_action,
            'typed_per_filter_config': {BUFFER: {
                '@type': TYPE + 'envoy.extensions.filters.http.buffer.v3.BufferPerRoute',
                **({'disabled': True} if streaming or not enforce else {
                    'buffer': {'max_request_bytes': rule.get('max_body_bytes', policy['max_body_bytes'])}}),
            }, BODY_LIMIT: {
                '@type': TYPE + 'envoy.extensions.filters.http.lua.v3.LuaPerRoute',
                **({'disabled': True} if streaming or not enforce else {
                    'name': f'body_limit_{rule.get("max_body_bytes", policy["max_body_bytes"])}'}),
            }},
        }
        if has_inspection:
            route['typed_per_filter_config'][security.INSPECTION] = security.inspection_route(rule, enforce)
        if enforce and rule.get('response_guard', False):
            route['response_headers_to_add'] = [{
                'header': {'key': 'cache-control', 'value': 'no-store'},
                'append_action': 'OVERWRITE_IF_EXISTS_OR_ADD'}]
        routes.append(route)

    rate_filter = typed(RATE_LIMIT, 'envoy.extensions.filters.http.ratelimit.v3.RateLimit',
                        domain='siteguard', timeout='0.05s', failure_mode_deny=enforce,
                        status_on_error={'code': 'ServiceUnavailable'},
                        filter_enabled={'default_value': {'numerator': 100, 'denominator': 'HUNDRED'}},
                        filter_enforced={'default_value': {'numerator': 100 if enforce else 0, 'denominator': 'HUNDRED'}},
                        rate_limit_service={'transport_api_version': 'V3', 'grpc_service': {
                            'envoy_grpc': {'cluster_name': 'siteguard_policy'}}})
    router = typed(ROUTER, 'envoy.extensions.filters.http.router.v3.Router', suppress_envoy_headers=True)
    # Buffer first: an earlier asynchronous RLS can leave Envoy's watermark in streaming mode.
    request_security = security.request_filters(config)
    filters = [*request_security,
               typed(BUFFER, 'envoy.extensions.filters.http.buffer.v3.Buffer',
                     max_request_bytes=policy['max_body_bytes']),
               typed(BODY_LIMIT, 'envoy.extensions.filters.http.lua.v3.Lua',
                     source_codes={f'body_limit_{limit}': {
                         'inline_string': BODY_LIMIT_SCRIPT.replace('MAX_BODY_BYTES', str(limit))}
                         for limit in sorted({policy['max_body_bytes'], *(
                             rule.get('max_body_bytes', policy['max_body_bytes']) for rule in config['routes'])})},
                     clear_route_cache=False), rate_filter,
               *([security.inspection_filter()] if has_inspection else []), router]
    forwarded_proto = config['listener'].get('forwarded_proto', 'https' if 'tls' in config['listener'] else 'http')
    controls = ['x-envoy-internal', 'x-envoy-retry-on', 'x-envoy-retry-grpc-on',
                'x-envoy-max-retries', 'x-envoy-upstream-rq-timeout-ms',
                'x-envoy-upstream-rq-per-try-timeout-ms', 'x-envoy-hedge-on-per-try-timeout',
                'x-envoy-upstream-rq-timeout-alt-response', 'x-envoy-expected-rq-timeout-ms',
                'x-envoy-force-trace', 'forwarded', 'x-forwarded-client-cert', 'x-real-ip']
    header = lambda key, value: {'header': {'key': key, 'value': value},
                                  'append_action': 'OVERWRITE_IF_EXISTS_OR_ADD'}
    hcm = {
        'stat_prefix': 'siteguard', 'codec_type': 'AUTO',
        'early_header_mutation_extensions': [typed(
            'envoy.http.early_header_mutation.header_mutation',
            'envoy.extensions.http.early_header_mutation.header_mutation.v3.HeaderMutation',
            mutations=[{'remove_on_match': {'key_matcher': {'prefix': 'x-envoy-'}}}])],
        'use_remote_address': not bool(config['trusted_proxy_cidrs']),
        'internal_address_config': {'cidr_ranges': []},
        'normalize_path': True, 'merge_slashes': True,
        'path_with_escaped_slashes_action': 'REJECT_REQUEST',
        'max_request_headers_kb': 60, 'request_headers_timeout': '10s',
        'request_timeout': '0s', 'stream_idle_timeout': seconds(policy['stream_idle_timeout_seconds']),
        'common_http_protocol_options': {'idle_timeout': '60s', 'max_headers_count': 100},
        'http2_protocol_options': dict(H2_OPTIONS),
        'server_header_transformation': 'PASS_THROUGH', 'proxy_100_continue': False,
        'route_config': {
            'name': 'siteguard_routes',
            **security.response_headers(config),
            'request_headers_to_remove': controls,
            'request_headers_to_add': [
                header('x-forwarded-for', '%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%'),
                header('x-forwarded-proto', forwarded_proto),
                header('x-forwarded-host', '%REQ(:AUTHORITY)%'),
            ],
            'virtual_hosts': [{'name': config['name'], 'domains': config['hosts'], 'routes': routes}],
        },
        'http_filters': filters,
        'upgrade_configs': [{'upgrade_type': 'websocket', 'enabled': False,
                             'filters': [*request_security, rate_filter, router]}],
        'access_log': [typed('envoy.access_loggers.stdout', 'envoy.extensions.access_loggers.stream.v3.StdoutAccessLog',
                             log_format={'json_format': {
                                 'time': '%START_TIME%', 'method': '%REQ(:METHOD)%',
                                 'route': '%ROUTE_NAME%', 'status': '%RESPONSE_CODE%',
                                 'duration_ms': '%DURATION%', 'received_bytes': '%BYTES_RECEIVED%',
                                 'sent_bytes': '%BYTES_SENT%', 'flags': '%RESPONSE_FLAGS%',
                                 'details': '%RESPONSE_CODE_DETAILS%',
                                 'security_shadow_rule': '%DYNAMIC_METADATA(envoy.filters.http.rbac:shadow_effective_policy_id)%',
                                 'security_response_rule': '%DYNAMIC_METADATA(envoy.filters.http.ext_proc:rule)%',
                             }})],
    }
    if config['trusted_proxy_cidrs']:
        cidrs = [ipaddress.ip_network(value) for value in config['trusted_proxy_cidrs']]
        hcm['original_ip_detection_extensions'] = [typed(
            'envoy.http.original_ip_detection.xff', 'envoy.extensions.http.original_ip_detection.xff.v3.XffConfig',
            xff_trusted_cidrs={'cidrs': [{'address_prefix': str(network.network_address), 'prefix_len': network.prefixlen}
                                        for network in cidrs]})]
    listener = {
        'name': 'siteguard', 'address': address('0.0.0.0', 8080),
        'per_connection_buffer_limit_bytes': 65536,
        'filter_chains': [{'filters': [
            typed('envoy.filters.network.connection_limit', 'envoy.extensions.filters.network.connection_limit.v3.ConnectionLimit',
                  stat_prefix='siteguard_connections', max_connections=2048),
            typed('envoy.filters.network.http_connection_manager',
                  'envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager', **hcm),
        ]}],
    }
    if 'tls' in config['listener']:
        listener['filter_chains'][0]['transport_socket_connect_timeout'] = '10s'
        listener['filter_chains'][0]['transport_socket'] = typed(
            'envoy.transport_sockets.tls', 'envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext',
            common_tls_context={
                'tls_params': {'tls_minimum_protocol_version': 'TLSv1_2'},
                'alpn_protocols': ['h2', 'http/1.1'],
                'tls_certificates': [{'certificate_chain': {'filename': '/etc/siteguard/tls/certificate.pem'},
                                      'private_key': {'filename': '/etc/siteguard/tls/private-key.pem'}}],
            })
    clusters.append({
        'name': 'siteguard_policy', 'type': 'STRICT_DNS', 'connect_timeout': '0.25s',
        'load_assignment': {'cluster_name': 'siteguard_policy', 'endpoints': [{'lb_endpoints': [
            {'endpoint': {'address': address('policy', 50051)}}]}]},
        'circuit_breakers': {'thresholds': [{'max_connections': 2, 'max_requests': 128,
                                            'max_pending_requests': 32, 'max_retries': 0}]},
        'typed_extension_protocol_options': {'envoy.extensions.upstreams.http.v3.HttpProtocolOptions': {
            '@type': TYPE + 'envoy.extensions.upstreams.http.v3.HttpProtocolOptions',
            'explicit_http_config': {'http2_protocol_options': dict(H2_OPTIONS)},
        }},
    })
    if has_inspection:
        clusters.append({
            'name': 'siteguard_inspection', 'type': 'STRICT_DNS', 'connect_timeout': '0.25s',
            'load_assignment': {'cluster_name': 'siteguard_inspection', 'endpoints': [{'lb_endpoints': [
                {'endpoint': {'address': address('policy', 50052)}}]}]},
            'circuit_breakers': {'thresholds': [{'max_connections': 2, 'max_requests': 16,
                                                'max_pending_requests': 4, 'max_retries': 0}]},
            'typed_extension_protocol_options': {'envoy.extensions.upstreams.http.v3.HttpProtocolOptions': {
                '@type': TYPE + 'envoy.extensions.upstreams.http.v3.HttpProtocolOptions',
                'explicit_http_config': {'http2_protocol_options': dict(H2_OPTIONS)},
            }},
        })
    return {
        'admin': {'address': address('127.0.0.1', 9901)},
        'static_resources': {'listeners': [listener], 'clusters': clusters},
        'overload_manager': {
            'refresh_interval': '0.25s',
            'resource_monitors': [typed('envoy.resource_monitors.fixed_heap',
                                        'envoy.extensions.resource_monitors.fixed_heap.v3.FixedHeapConfig',
                                        max_heap_size_bytes=384 * 1024 * 1024)],
            'actions': [
                {'name': 'envoy.overload_actions.shrink_heap', 'triggers': [{
                    'name': 'envoy.resource_monitors.fixed_heap', 'threshold': {'value': 0.85}}]},
                {'name': 'envoy.overload_actions.stop_accepting_requests', 'triggers': [{
                    'name': 'envoy.resource_monitors.fixed_heap', 'threshold': {'value': 0.95}}]},
            ],
        },
    }
