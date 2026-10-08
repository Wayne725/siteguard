"""Validate the small, versioned user interface before generating proxy configuration."""
from __future__ import annotations

import copy
import ipaddress
import math
import re
from pathlib import Path
from urllib.parse import urlsplit

import yaml


class ConfigError(ValueError):
    pass


class UniqueKeyLoader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        keys = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in keys:
                raise ConfigError(f'設定欄位必須是不重複的字串：{key!r}')
            keys.add(key)
        return super().construct_mapping(node, deep=deep)


POLICY_DEFAULTS = {
    'max_concurrent': 64, 'queue_size': 16,
    'rate_per_second': 100, 'burst': 200,
    'per_ip_rate': 20, 'per_ip_burst': 40,
    'max_body_bytes': 10 * 1024 * 1024,
    'request_timeout_seconds': 30, 'stream_idle_timeout_seconds': 300,
}

SECURITY_DEFAULTS = {
    'block_sensitive_paths': True,
    'blocked_methods': ['TRACE', 'TRACK', 'CONNECT'],
    'response_headers': True,
    'protected_paths': [],
}

FIREWALL_DEFAULTS = {'default_action': 'allow', 'allow_cidrs': [], 'deny_cidrs': []}


def example_config(upstream: str = 'http://host.docker.internal:8000') -> dict:
    return {
        'version': 1, 'name': 'siteguard', 'mode': 'observe',
        'listener': {'host': '127.0.0.1', 'port': 8088},
        'upstream': {'url': upstream, 'protocol': 'http1', 'preserve_host': True},
        'hosts': ['*'], 'policy': dict(POLICY_DEFAULTS), 'routes': [],
        'security': copy.deepcopy(SECURITY_DEFAULTS),
        'firewall': copy.deepcopy(FIREWALL_DEFAULTS),
        'trusted_proxy_cidrs': [], 'trusted_proxy_hops': 0,
    }


def mapping(value, path: str, allowed: set[str]) -> dict:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ConfigError(f'{path} 必須是設定物件。')
    unknown = set(value) - allowed
    if unknown:
        raise ConfigError(f'{path} 包含未知設定：{", ".join(sorted(unknown))}')
    return value


def number(value, path: str, low: float, high: float, integer=True):
    expected = int if integer else (int, float)
    if (isinstance(value, bool) or not isinstance(value, expected)
            or not math.isfinite(value) or not low <= value <= high):
        raise ConfigError(f'{path} 必須是 {low}～{high} 的{"整數" if integer else "數字"}。')
    return value


def boolean(value, path: str):
    if not isinstance(value, bool):
        raise ConfigError(f'{path} 必須是 true 或 false。')
    return value


def choice(value, path: str, options):
    if not isinstance(value, str) or value not in options:
        raise ConfigError(f'{path} 必須是 {", ".join(options)}。')
    return value


def file_path(value, path: str, base_dir: Path) -> str:
    if not isinstance(value, str) or not value.strip() or '\x00' in value:
        raise ConfigError(f'{path} 必須是檔案路徑。')
    result = Path(value).expanduser()
    if not result.is_absolute():
        result = base_dir / result
    result = result.resolve()
    if not result.is_file():
        raise ConfigError(f'{path} 找不到檔案：{result}')
    return str(result)


def canonical_prefix(value, label: str) -> str:
    if (not isinstance(value, str) or not value.isascii() or not value.startswith('/')
            or len(value) > 8192 or re.search(r'[\s%;?#\\\x00-\x1f\x7f]', value)
            or '//' in value or any(part.endswith('.') for part in value.split('/'))):
        raise ConfigError(f'{label} 必須是最多 8192 字元的 ASCII 絕對路徑，不可含編碼、空白、分號、'
                          '查詢、反斜線、點段或路徑段結尾句點。')
    return value.rstrip('/') or '/'


def validate_security(value) -> dict:
    security = copy.deepcopy(SECURITY_DEFAULTS)
    security.update(mapping(value, 'security', set(SECURITY_DEFAULTS)))
    for key in ('block_sensitive_paths', 'response_headers'):
        boolean(security[key], f'security.{key}')
    methods = security['blocked_methods']
    if not isinstance(methods, list) or len(methods) > 16:
        raise ConfigError('security.blocked_methods 必須是最多 16 個 HTTP 方法的清單。')
    for method in methods:
        if not isinstance(method, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Z-]+", method):
            raise ConfigError('security.blocked_methods 只接受非空白、使用大寫字母的 RFC token 方法名稱。')
    if len(methods) != len(set(methods)):
        raise ConfigError('security.blocked_methods 不可重複。')
    protected_paths = security['protected_paths']
    if not isinstance(protected_paths, list) or len(protected_paths) > 32:
        raise ConfigError('security.protected_paths 必須是最多 32 項的清單。')
    normalized, prefixes = [], set()
    for index, rule in enumerate(protected_paths):
        label = f'security.protected_paths[{index}]'
        mapping(rule, label, {'prefix', 'allowed_cidrs'})
        prefix = canonical_prefix(rule.get('prefix'), f'{label}.prefix')
        if prefix in prefixes:
            raise ConfigError(f'{label}.prefix 與其他保護路徑重複。')
        prefixes.add(prefix)
        cidrs = rule.get('allowed_cidrs')
        if not isinstance(cidrs, list) or not 1 <= len(cidrs) <= 32:
            raise ConfigError(f'{label}.allowed_cidrs 必須包含 1～32 個精確 CIDR 網段。')
        networks = []
        for cidr in cidrs:
            try:
                if not isinstance(cidr, str) or '/' not in cidr or '%' in cidr:
                    raise ValueError
                network = ipaddress.ip_network(cidr, strict=True)
            except (ValueError, TypeError):
                raise ConfigError(f'{label}.allowed_cidrs 包含不合法或非精確網段的 CIDR：{cidr!r}') from None
            if network.prefixlen == 0:
                raise ConfigError(f'{label}.allowed_cidrs 不可包含允許整個網際網路的 /0 網段。')
            if str(network) in networks:
                raise ConfigError(f'{label}.allowed_cidrs 不可包含重複網段。')
            networks.append(str(network))
        normalized.append({'prefix': prefix, 'allowed_cidrs': networks})
    security['protected_paths'] = normalized
    return security


def validate_firewall(value) -> dict:
    firewall = copy.deepcopy(FIREWALL_DEFAULTS)
    firewall.update(mapping(value, 'firewall', set(FIREWALL_DEFAULTS)))
    choice(firewall['default_action'], 'firewall.default_action', ('allow', 'deny'))
    for key in ('allow_cidrs', 'deny_cidrs'):
        label = f'firewall.{key}'
        entries = firewall[key]
        if not isinstance(entries, list) or len(entries) > 256:
            raise ConfigError(f'{label} 必須是最多 256 個 IP 或精確 CIDR 網段的清單。')
        normalized, seen = [], set()
        for value in entries:
            try:
                if (not isinstance(value, str) or '%' in value
                        or ('/' in value and not re.fullmatch(r'[0-9]{1,3}', value.split('/', 1)[1]))):
                    raise ValueError
                network = ipaddress.ip_network(value, strict=True)
            except (ValueError, TypeError):
                raise ConfigError(f'{label} 包含不合法的 IP 或非精確 CIDR 網段：{value!r}') from None
            if (network.version == 6 and network.prefixlen >= 96
                    and network.network_address.ipv4_mapped is not None):
                network = ipaddress.IPv4Network((network.network_address.ipv4_mapped, network.prefixlen - 96))
            cidr = str(network)
            if cidr in seen:
                raise ConfigError(f'{label} 不可包含正規化後重複的 IP 或網段。')
            seen.add(cidr)
            normalized.append(cidr)
        firewall[key] = normalized
    if firewall['default_action'] == 'allow' and firewall['allow_cidrs']:
        raise ConfigError('firewall.allow_cidrs 在 default_action: allow 時沒有放行作用；'
                          '若要只允許指定來源，請使用 default_action: deny。deny_cidrs 仍優先拒絕。')
    return firewall


def validate_config(raw: dict, base_dir: Path | None = None) -> dict:
    base_dir = Path(base_dir or Path.cwd())
    allowed = set(example_config())
    mapping(raw, 'config', allowed)
    config = example_config()
    config.update(copy.deepcopy(raw))
    if type(config['version']) is not int or config['version'] != 1:
        raise ConfigError('version 目前必須為 1。')
    name = config['name']
    if not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,39}', name):
        raise ConfigError('name 必須是 1～40 字的小寫字母、數字或連字號，以字母開頭。')
    choice(config['mode'], 'mode', ('observe', 'enforce'))

    listener = {'host': '127.0.0.1', 'port': 8088}
    listener.update(mapping(config['listener'], 'listener', {'host', 'port', 'tls', 'forwarded_proto'}))
    try:
        ipaddress.ip_address(listener['host'])
    except (ValueError, TypeError):
        raise ConfigError('listener.host 必須是綁定介面的 IPv4 或 IPv6 位址。') from None
    number(listener['port'], 'listener.port', 1, 65535)
    if 'forwarded_proto' in listener:
        choice(listener['forwarded_proto'], 'listener.forwarded_proto', ('http', 'https'))
    if 'tls' in listener:
        tls = mapping(listener['tls'], 'listener.tls', {'certificate', 'private_key'})
        if set(tls) != {'certificate', 'private_key'}:
            raise ConfigError('listener.tls 需要 certificate 與 private_key。')
        listener['tls'] = {key: file_path(value, f'listener.tls.{key}', base_dir)
                           for key, value in tls.items()}
        if listener.get('forwarded_proto', 'https') != 'https':
            raise ConfigError('TLS listener 的 forwarded_proto 必須是 https。')
    config['listener'] = listener

    upstream = {'protocol': 'http1', 'preserve_host': True}
    upstream.update(mapping(config['upstream'], 'upstream',
                            {'url', 'protocol', 'preserve_host', 'tls_ca_file', 'network'}))
    if 'network' in upstream and (not isinstance(upstream['network'], str)
                                 or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}', upstream['network'])):
        raise ConfigError('upstream.network 必須是既有 Docker 網路名稱。')
    url = upstream.get('url')
    if not isinstance(url, str) or re.search(r'[\s\x00-\x1f\x7f]', url):
        raise ConfigError('upstream.url 必須是完整的 http:// 或 https:// 來源站網址。')
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        raise ConfigError('upstream.url 的位址或埠無效。') from None
    if (parsed.scheme not in ('http', 'https') or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
        raise ConfigError('upstream.url 只接受 http(s) 的主機與埠，不接受帳密、路徑或查詢字串。')
    host = parsed.hostname
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if (len(host) > 253 or any(not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', label)
                                  for label in host.rstrip('.').split('.'))):
            raise ConfigError('upstream.url 主機須為有效 IP 或 ASCII／punycode DNS 名稱。') from None
    if port is not None:
        number(port, 'upstream.url port', 1, 65535)
    choice(upstream['protocol'], 'upstream.protocol', ('http1', 'http2', 'auto'))
    if upstream['protocol'] == 'auto' and parsed.scheme != 'https':
        raise ConfigError('protocol auto 需要 HTTPS ALPN；明文來源請指定 http1 或 http2。')
    boolean(upstream['preserve_host'], 'upstream.preserve_host')
    if 'tls_ca_file' in upstream:
        if parsed.scheme != 'https':
            raise ConfigError('tls_ca_file 只能用於 HTTPS 來源站。')
        upstream['tls_ca_file'] = file_path(upstream['tls_ca_file'], 'upstream.tls_ca_file', base_dir)
    config['upstream'] = upstream

    hosts = config['hosts']
    if not isinstance(hosts, list) or not hosts or len(hosts) > 100:
        raise ConfigError('hosts 必須包含 1～100 個主機名稱或 *。')
    for host in hosts:
        if (not isinstance(host, str) or len(host) > 253
                or not re.fullmatch(r'(?:\*|(?:\*\.)?[a-zA-Z0-9][a-zA-Z0-9.:-]*)', host)):
            raise ConfigError('hosts 只接受主機名稱、可選埠與前綴萬用字元。')
    if len(hosts) != len(set(hosts)):
        raise ConfigError('hosts 不可重複。')

    policy = dict(POLICY_DEFAULTS)
    policy.update(mapping(config['policy'], 'policy', set(POLICY_DEFAULTS)))
    for key, low, high in (
        ('max_concurrent', 1, 100000), ('queue_size', 0, 10000),
        ('rate_per_second', 1, 1000000), ('burst', 1, 1000000),
        ('per_ip_rate', 1, 1000000), ('per_ip_burst', 1, 1000000),
        ('max_body_bytes', 1, 1024 * 1024 * 1024),
    ):
        number(policy[key], f'policy.{key}', low, high)
    for key in ('request_timeout_seconds', 'stream_idle_timeout_seconds'):
        number(policy[key], f'policy.{key}', 1, 86400, integer=False)
    for prefix in ('', 'per_ip_'):
        rate = policy[f'{prefix}rate' if prefix else 'rate_per_second']
        if policy[f'{prefix}burst'] < rate:
            raise ConfigError(f'policy.{prefix}burst 不可小於每秒速率。')
    config['policy'] = policy
    config['security'] = validate_security(config['security'])
    config['firewall'] = validate_firewall(config['firewall'])

    if not isinstance(config['routes'], list) or len(config['routes']) > 100:
        raise ConfigError('routes 必須是最多 100 項的清單。')
    names, prefixes, reserved = set(), set(), 0
    routes = []
    route_keys = {'name', 'prefix', 'max_concurrent', 'streaming', 'timeout_seconds',
                  'rate_per_second', 'burst', 'max_body_bytes', 'response_guard'}
    for index, route in enumerate(config['routes']):
        label = f'routes[{index}]'
        mapping(route, label, route_keys)
        route = dict(route)
        if not isinstance(route.get('name'), str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,39}', route['name']):
            raise ConfigError(f'{label}.name 須為小寫字母開頭的英數字與底線。')
        prefix = route.get('prefix')
        if (not isinstance(prefix, str) or prefix == '/' or not prefix.startswith('/')
                or re.search(r'[\s%?#\\\x00-\x1f\x7f]', prefix)
                or '//' in prefix or any(part in ('.', '..') for part in prefix.split('/'))):
            raise ConfigError(f'{label}.prefix 須為不含編碼、查詢字串或點段的絕對路徑，根路徑由預設規則處理。')
        prefix = prefix.rstrip('/')
        route['prefix'] = prefix
        if route['name'] == 'default' or route['name'].endswith('_websocket'):
            raise ConfigError(f'{label}.name 使用了保留名稱。')
        if route['name'] in names or prefix in prefixes:
            raise ConfigError(f'{label} 的名稱或路徑重複。')
        names.add(route['name'])
        prefixes.add(prefix)
        route['streaming'] = boolean(route.get('streaming', False), f'{label}.streaming')
        route['response_guard'] = boolean(route.get('response_guard', False), f'{label}.response_guard')
        if route['response_guard']:
            canonical_prefix(prefix, f'{label}.prefix（response_guard）')
            if route['streaming']:
                raise ConfigError(f'{label}.response_guard 只能用於專用小型 API 路由，不可與 streaming 同時啟用。')
            if 'max_body_bytes' not in route:
                raise ConfigError(f'{label}.response_guard 需要專用小型 API 路由明確設定 max_body_bytes '
                                  '為 1～65536 bytes，作為請求與回應共用的硬緩衝上限；不可繼承全站上限。')
            number(route['max_body_bytes'],
                   f'{label}.max_body_bytes（response_guard 專用小型 API 的請求／回應共用硬緩衝上限）',
                   1, 65536)
        if 'max_concurrent' in route:
            reserved += number(route['max_concurrent'], f'{label}.max_concurrent', 1, 100000)
        for key in ('rate_per_second', 'burst', 'max_body_bytes'):
            if key in route:
                high = 1024 ** 3 if key == 'max_body_bytes' else 1000000
                number(route[key], f'{label}.{key}', 1, high)
        if ('rate_per_second' in route) != ('burst' in route):
            raise ConfigError(f'{label} 的 rate_per_second 與 burst 必須一起設定。')
        if 'burst' in route and route['burst'] < route['rate_per_second']:
            raise ConfigError(f'{label}.burst 不可小於每秒速率。')
        if 'timeout_seconds' in route:
            number(route['timeout_seconds'], f'{label}.timeout_seconds', 1, 86400, integer=False)
        if route['streaming'] and 'max_body_bytes' in route:
            raise ConfigError(f'{label} 串流不可使用需要完整緩衝的 max_body_bytes。')
        routes.append(route)
    if reserved >= policy['max_concurrent']:
        raise ConfigError('路由預留並行額度的總和必須小於 policy.max_concurrent，保留預設路由額度。')
    config['routes'] = sorted(routes, key=lambda route: len(route['prefix']), reverse=True)

    cidrs = config['trusted_proxy_cidrs']
    if not isinstance(cidrs, list) or len(cidrs) > 100:
        raise ConfigError('trusted_proxy_cidrs 必須是最多 100 個 CIDR 的清單。')
    normalized = []
    for value in cidrs:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except (ValueError, TypeError):
            raise ConfigError(f'不合法的受信代理 CIDR：{value!r}') from None
        if network.prefixlen == 0:
            raise ConfigError('不可把整個網際網路設為受信代理。')
        normalized.append(str(network))
    config['trusted_proxy_cidrs'] = normalized
    if type(config['trusted_proxy_hops']) is not int or config['trusted_proxy_hops'] != 0:
        raise ConfigError('使用 trusted_proxy_cidrs 的來源驗證；不接受僅依 hop 數信任 X-Forwarded-For。')
    return config


def load_config(path: Path | str) -> dict:
    path = Path(path)
    if path.stat().st_size > 1024 * 1024:
        raise ConfigError('設定檔不可超過 1 MiB。')
    try:
        raw = yaml.load(path.read_text(encoding='utf-8'), Loader=UniqueKeyLoader)
    except yaml.YAMLError as error:
        raise ConfigError(f'設定檔 YAML 格式無效：{error}') from error
    return validate_config(raw, base_dir=path.resolve().parent)
