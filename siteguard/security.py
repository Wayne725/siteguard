"""Compile bounded request screening and opt-in response inspection policies."""
from __future__ import annotations

import ipaddress
import re


TYPE = 'type.googleapis.com/'
CANONICAL = 'siteguard.canonical_path'
RBAC = 'envoy.filters.http.rbac'
INSPECTION = 'envoy.filters.http.ext_proc'
METADATA = 'siteguard.request_security'
INSPECTION_MODE = {'request_header_mode': 'SEND', 'response_header_mode': 'SEND',
                   'request_body_mode': 'NONE', 'response_body_mode': 'BUFFERED',
                   'request_trailer_mode': 'SKIP', 'response_trailer_mode': 'SEND'}
CANONICAL_SCRIPT = r'''function envoy_on_request(handle)
  local metadata = handle:streamInfo():dynamicMetadata()
  metadata:set("siteguard.request_security", "valid", false)
  local path = (handle:headers():get(":path") or ""):match("^[^?#]*")
  if not path or #path > 8192 or (path:sub(1, 1) ~= "/" and path ~= "*") then return end
  for iteration = 1, 3 do
    local decoded = path:gsub("%%(%x%x)", function(hex)
      local byte = tonumber(hex, 16)
      if byte < 128 then return string.char(byte) end
      return "%" .. string.upper(hex)
    end)
    if decoded == path then break end
    path = decoded
  end
  if path:find("[%z\1-\31\127]") or path:find("%%[0-7]%x") then return end
  path = path:gsub("[\128-\255]", function(byte) return string.format("%%%02X", byte:byte()) end)
  path = path:gsub("\\", "/"):lower()
  local segments = {}
  for part in path:gmatch("[^/]+") do
    part = part:match("^[^;]*"):gsub(" +$", "")
    if part == ".." then
      if #segments > 0 then table.remove(segments) end
    elseif part ~= "." then
      part = part:gsub("[ %.]+$", "")
      if #part > 0 then table.insert(segments, part) end
    end
  end
  local canonical = path == "*" and "*" or "/" .. table.concat(segments, "/")
  metadata:set("siteguard.request_security", "path", canonical)
  metadata:set("siteguard.request_security", "valid", true)
end
'''
SENSITIVE_PATHS = (
    r'.*/\.(?:env(?:\.[^/]*)?|git|svn|hg|ssh|aws|npmrc|pypirc|netrc|htpasswd)(?:/.*)?',
    r'.*/(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)(?:/.*)?',
    r'.*/(?:wp-config\.php|web\.config)(?:\.(?:bak|old|orig|save)|~)?',
)


def typed(name, message, **fields):
    return {'name': name, 'typed_config': {'@type': TYPE + message, **fields}}


def metadata_match(key, value):
    return {'metadata': {'filter': METADATA, 'path': [{'key': key}], 'value': value}}


def path_match(pattern):
    return metadata_match('path', {'string_match': {'safe_regex': {'regex': pattern}}})


def selected_route(routes, selected):
    def raw_path(route):
        return {'url_path': {'path': {'safe_regex': {
            'regex': re.escape(route['prefix']) + r'(?:/.*)?'}}}}
    earlier = routes[:routes.index(selected)]
    return {'and_rules': {'rules': [raw_path(selected), *([
        {'not_rule': {'or_rules': {'rules': [raw_path(route) for route in earlier]}}}]
        if earlier else [])]}}


def source_networks(cidrs, field='remote_ip'):
    mapped_range = ipaddress.ip_network('::ffff:0:0/96')

    def match(network):
        return {field: {'address_prefix': str(network.network_address), 'prefix_len': network.prefixlen}}

    principals = []
    for cidr in cidrs:
        network = ipaddress.ip_network(cidr)
        if network.version == 6 and network.subnet_of(mapped_range):
            network = ipaddress.ip_network((network.network_address.ipv4_mapped, network.prefixlen - 96))
        if network.version == 4:
            mapped = ipaddress.ip_network((ipaddress.IPv6Address(int(mapped_range.network_address)
                                            + int(network.network_address)), 96 + network.prefixlen))
            principals.extend([match(network), match(mapped)])
        else:
            principals.append({'and_ids': {'ids': [match(network), {'not_id': match(mapped_range)}]}})
    return {'or_ids': {'ids': principals}}


def firewall_policies(firewall):
    policies = {}
    if firewall['deny_cidrs']:
        policies['firewall_denied_source'] = {
            'permissions': [{'any': True}], 'principals': [source_networks(firewall['deny_cidrs'])]}
    if firewall['default_action'] == 'deny':
        principal = ({'not_id': source_networks(firewall['allow_cidrs'])}
                     if firewall['allow_cidrs'] else {'any': True})
        policies['firewall_default_deny'] = {'permissions': [{'any': True}], 'principals': [principal]}
    return policies


def request_filters(config):
    security = config['security']
    guarded = [route for route in config['routes'] if route.get('response_guard')]
    canonical_needed = bool(security['block_sensitive_paths'] or security['blocked_methods']
                            or security['protected_paths'] or guarded)
    policies = firewall_policies(config['firewall'])
    if policies and config['trusted_proxy_cidrs']:
        policies['firewall_unresolved_source'] = {
            'permissions': [{'any': True}], 'principals': [{'and_ids': {'ids': [
                source_networks(config['trusted_proxy_cidrs'], 'direct_remote_ip'),
                source_networks(config['trusted_proxy_cidrs'])]}}]}
    if not canonical_needed and not policies:
        return []
    if canonical_needed:
        policies['invalid_canonical_path'] = {
            'permissions': [{'not_rule': metadata_match('valid', {'bool_match': True})}],
            'principals': [{'any': True}],
        }
    if security['block_sensitive_paths']:
        policies['sensitive_file'] = {'permissions': [path_match(pattern) for pattern in SENSITIVE_PATHS],
                                      'principals': [{'any': True}]}
    if security['blocked_methods']:
        policies['blocked_method'] = {
            'permissions': [{'header': {'name': ':method', 'string_match': {
                'exact': method, 'ignore_case': True}}} for method in security['blocked_methods']],
            'principals': [{'any': True}],
        }
    for index, protected in enumerate(security['protected_paths']):
        pattern = r'/.*' if protected['prefix'] == '/' else re.escape(protected['prefix'].lower()) + r'(?:/.*)?'
        policies[f'protected_path_{index:02d}'] = {
            'permissions': [path_match(pattern)],
            'principals': [{'not_id': source_networks(protected['allowed_cidrs'])}],
        }
    for index, guard in enumerate(guarded):
        selected = {'or_rules': {'rules': [selected_route(config['routes'], route) for route in guarded
                                          if route['max_body_bytes'] <= guard['max_body_bytes']]}}
        policies[f'response_guard_alias_{index:02d}'] = {
            'permissions': [{'and_rules': {'rules': [
                path_match(re.escape(guard['prefix'].lower()) + r'(?:/.*)?'),
                {'not_rule': selected}]}}],
            'principals': [{'any': True}],
        }
    rules = {'action': 'DENY', 'policies': policies}
    canonical_filter = [
        typed(CANONICAL, 'envoy.extensions.filters.http.lua.v3.Lua',
              default_source_code={'inline_string': CANONICAL_SCRIPT}, clear_route_cache=False,
              stat_prefix='canonical_path')
    ] if canonical_needed else []
    return [*canonical_filter,
        typed(RBAC, 'envoy.extensions.filters.http.rbac.v3.RBAC',
              **({'rules': rules} if config['mode'] == 'enforce' else {'shadow_rules': rules}),
              track_per_rule_stats=True),
    ]


def inspection_filter():
    return typed(INSPECTION, 'envoy.extensions.filters.http.ext_proc.v3.ExternalProcessor',
                 grpc_service={'envoy_grpc': {'cluster_name': 'siteguard_inspection'}},
                 failure_mode_allow=False, message_timeout='0.25s',
                 allow_mode_override=False, disable_clear_route_cache=True,
                 status_on_error={'code': 'ServiceUnavailable'},
                 processing_mode={'request_header_mode': 'SKIP', 'response_header_mode': 'SKIP',
                                  'request_body_mode': 'NONE', 'response_body_mode': 'NONE',
                                  'request_trailer_mode': 'SKIP', 'response_trailer_mode': 'SKIP'})


def inspection_route(rule, enforce):
    guarded = enforce and rule.get('response_guard', False)
    return {'@type': TYPE + 'envoy.extensions.filters.http.ext_proc.v3.ExtProcPerRoute',
            **({'overrides': {'processing_mode': dict(INSPECTION_MODE), 'grpc_initial_metadata': [
                {'key': 'x-siteguard-max-bytes', 'value': str(rule['max_body_bytes'])}]}}
               if guarded else {'disabled': True})}


def response_headers(config):
    if config['mode'] != 'enforce' or not config['security']['response_headers']:
        return {}
    return {
        'response_headers_to_remove': ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'],
        'response_headers_to_add': [
            {'header': {'key': 'x-content-type-options', 'value': 'nosniff'},
             'append_action': 'OVERWRITE_IF_EXISTS_OR_ADD'},
            {'header': {'key': 'referrer-policy', 'value': 'strict-origin-when-cross-origin'},
             'append_action': 'ADD_IF_ABSENT'},
        ],
    }
