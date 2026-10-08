"""Bounded, process-local admission buckets and the Envoy v3 RLS adapter."""
from __future__ import annotations

import asyncio
from collections import Counter, OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
import ipaddress
import json
import math
from pathlib import Path
import re
import signal
import threading
import time


DOMAIN = 'siteguard'
MAX_MESSAGE_BYTES = 4096
MAX_CONCURRENT_RPCS = 128
POLICY_FILE = Path('/etc/siteguard/policy.json')


def render_policy(config: dict) -> dict:
    policy_keys = ('rate_per_second', 'burst', 'per_ip_rate', 'per_ip_burst')
    return {
        'version': 1,
        'mode': config['mode'],
        'policy': {key: config['policy'][key] for key in policy_keys},
        'route_names': ['default', *[route['name'] for route in config['routes']]],
        'routes': {route['name']: {key: route[key] for key in ('rate_per_second', 'burst')}
                   for route in config['routes'] if 'rate_per_second' in route},
        'max_clients': 10000,
        'idle_ttl_seconds': 300,
    }


def _number(value, name: str, low: float, high: float, *, integer=False):
    if (isinstance(value, bool) or not isinstance(value, int if integer else (int, float))
            or not math.isfinite(value) or not low <= value <= high):
        raise ValueError(f'{name} must be a finite number in [{low}, {high}]')
    return value


def _rate(value: Mapping, name: str) -> tuple[float, float]:
    if not isinstance(value, Mapping) or set(value) != {'rate_per_second', 'burst'}:
        raise ValueError(f'{name} must contain rate_per_second and burst')
    return (_number(value['rate_per_second'], f'{name}.rate_per_second', .001, 1000000),
            _number(value['burst'], f'{name}.burst', 1, 1000000))


@dataclass
class Bucket:
    rate: float
    capacity: float
    tokens: float
    updated: float
    last_seen: float

    @classmethod
    def full(cls, rate: float, capacity: float, now: float) -> 'Bucket':
        return cls(rate, capacity, capacity, now, now)

    def refill(self, now: float) -> None:
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    limited_scopes: tuple[str, ...] = ()
    overflow: bool = False


class Policy:
    """Check and consume all applicable buckets atomically; modes share decisions.

    Envoy controls observe/enforce. A saturated client cache sends new clients to
    one shared bucket; eviction never restores credit before natural refill.
    """

    def __init__(self, config: Mapping, clock: Callable[[], float] = time.monotonic):
        fields = {'version', 'mode', 'policy', 'route_names', 'routes',
                  'max_clients', 'idle_ttl_seconds'}
        if not isinstance(config, Mapping) or set(config) != fields:
            raise ValueError('invalid policy fields')
        if type(config['version']) is not int or config['version'] != 1:
            raise ValueError('unsupported policy version')
        if config['mode'] not in ('observe', 'enforce'):
            raise ValueError('invalid policy mode')
        limits = config['policy']
        if (not isinstance(limits, Mapping)
                or set(limits) != {'rate_per_second', 'burst', 'per_ip_rate', 'per_ip_burst'}):
            raise ValueError('invalid policy rates')
        site_rate, site_burst = _rate({key: limits[key] for key in ('rate_per_second', 'burst')}, 'policy')
        self.client_rate, self.client_burst = _rate(
            {'rate_per_second': limits['per_ip_rate'], 'burst': limits['per_ip_burst']}, 'per_ip')
        names = config['route_names']
        if (not isinstance(names, list) or not 1 <= len(names) <= 101
                or any(not isinstance(name, str) or not re.fullmatch(r'[a-z][a-z0-9_]{0,39}', name)
                       for name in names)
                or len(set(names)) != len(names) or 'default' not in names):
            raise ValueError('invalid route_names')
        self.route_names = frozenset(names)
        routes = config['routes']
        if not isinstance(routes, Mapping) or not set(routes) <= self.route_names:
            raise ValueError('invalid route limits')
        route_rates = {name: _rate(rate, f'routes.{name}') for name, rate in routes.items()}
        self.max_clients = _number(config['max_clients'], 'max_clients', 1, 100000, integer=True)
        self.idle_ttl = _number(config['idle_ttl_seconds'], 'idle_ttl_seconds', .001, 86400)
        self.mode = config['mode']
        self.clock = clock
        self.lock = threading.Lock()
        self.last_now = clock()
        self.site = Bucket.full(site_rate, site_burst, self.last_now)
        self.routes = {name: Bucket.full(rate, burst, self.last_now)
                       for name, (rate, burst) in route_rates.items()}
        self.clients: OrderedDict[str, Bucket] = OrderedDict()
        self.overflow = Bucket.full(self.client_rate, self.client_burst, self.last_now)
        self.counters: Counter = Counter()

    def reject(self, reason: str) -> Decision:
        if reason not in ('invalid_request', 'cancelled'):
            raise ValueError('unsupported rejection reason')
        with self.lock:
            self.counters[reason] += 1
        return Decision(False, reason)

    def _expire_clients(self, now: float) -> None:
        # All client buckets have the same capacity/rate. This interval is safe
        # even for an entirely empty bucket, and work per admission stays bounded.
        safe_idle = max(self.idle_ttl, self.client_burst / self.client_rate)
        for _ in range(64):
            if not self.clients:
                break
            key, bucket = next(iter(self.clients.items()))
            if now - bucket.last_seen < safe_idle:
                break
            bucket.refill(now)
            if bucket.tokens < bucket.capacity:
                break
            del self.clients[key]

    def check(self, client_ip: str, route: str = 'default') -> Decision:
        if (not isinstance(client_ip, str) or len(client_ip) > 45 or '%' in client_ip
                or not isinstance(route, str) or route not in self.route_names):
            return self.reject('invalid_request')
        try:
            address = ipaddress.ip_address(client_ip)
        except ValueError:
            return self.reject('invalid_request')
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        client_ip = str(address)
        with self.lock:
            now = max(self.last_now, self.clock())
            self.last_now = now
            self._expire_clients(now)
            client = self.clients.get(client_ip)
            is_new = client is None
            self.overflow.refill(now)
            # Untracked clients cannot receive a fresh private bucket while
            # their shared bucket still carries debt, even if a slot opens.
            overflow = is_new and (len(self.clients) >= self.max_clients
                                   or self.overflow.tokens < self.overflow.capacity)
            if client is None:
                client = (self.overflow if overflow else
                          Bucket.full(self.client_rate, self.client_burst, now))
            elif not overflow:
                self.clients.move_to_end(client_ip)
            client.last_seen = now
            buckets = [('site', self.site), ('client', client)]
            if route in self.routes:
                buckets.append(('route', self.routes[route]))
            for _, bucket in buckets:
                bucket.refill(now)
            limited = tuple(scope for scope, bucket in buckets if bucket.tokens < 1)
            self.counters['checked'] += 1
            if overflow:
                self.counters['overflow_checked'] += 1
            if limited:
                self.counters['limited'] += 1
                for scope in limited:
                    self.counters[f'limited_{scope}'] += 1
                return Decision(False, 'rate_limited', limited, overflow)
            for _, bucket in buckets:
                bucket.tokens -= 1
            if is_new and not overflow:
                self.clients[client_ip] = client
            self.counters['allowed'] += 1
            return Decision(True, 'allowed', overflow=overflow)

    def snapshot(self) -> dict:
        with self.lock:
            return {'mode': self.mode, 'clients': len(self.clients),
                    'max_clients': self.max_clients, 'counters': dict(self.counters)}


class RateLimitService:
    def __init__(self, policy: Policy):
        self.policy = policy

    @staticmethod
    def _cancelled(context) -> bool:
        remaining = context.time_remaining()
        return context.cancelled() or (remaining is not None and remaining <= 0)

    async def ShouldRateLimit(self, request, context):
        from envoy.service.ratelimit.v3 import rls_pb2

        if self._cancelled(context):
            decision = self.policy.reject('cancelled')
        else:
            valid = (request.ByteSize() <= MAX_MESSAGE_BYTES and request.domain == DOMAIN
                     and request.hits_addend in (0, 1) and len(request.descriptors) == 1)
            values = {}
            if valid:
                descriptor = request.descriptors[0]
                valid = (len(descriptor.entries) == 3 and not descriptor.HasField('limit')
                         and not descriptor.HasField('hits_addend'))
                if valid:
                    values = {entry.key: entry.value for entry in descriptor.entries}
                    valid = (set(values) == {'scope', 'remote_address', 'route'}
                             and values['scope'] == 'site')
            if not valid:
                decision = self.policy.reject('invalid_request')
            elif self._cancelled(context):
                decision = self.policy.reject('cancelled')
            else:
                decision = self.policy.check(values['remote_address'], values['route'])
        code = rls_pb2.RateLimitResponse.OK if decision.allowed else rls_pb2.RateLimitResponse.OVER_LIMIT
        response = rls_pb2.RateLimitResponse(overall_code=code)
        if len(request.descriptors) == 1:
            response.statuses.add(code=code)
        response.dynamic_metadata.update({'reason': decision.reason,
                                          'overflow': decision.overflow,
                                          'limited_scopes': list(decision.limited_scopes)})
        return response


def load_policy(path: Path = POLICY_FILE) -> dict:
    with path.open('rb') as stream:
        data = stream.read(65537)
    if len(data) > 65536:
        raise ValueError('policy file exceeds 64 KiB')
    return json.loads(data)


def log_event(event: dict) -> None:
    print(json.dumps(event, separators=(',', ':')), flush=True)


async def serve() -> None:
    import grpc
    from envoy.service.ratelimit.v3 import rls_pb2_grpc
    if __package__:
        from .inspection import create_server
    else:
        from inspection import create_server

    policy = Policy(load_policy())
    server = grpc.aio.server(
        maximum_concurrent_rpcs=MAX_CONCURRENT_RPCS,
        options=(('grpc.max_receive_message_length', MAX_MESSAGE_BYTES),
                 ('grpc.max_send_message_length', MAX_MESSAGE_BYTES),
                 ('grpc.max_concurrent_streams', MAX_CONCURRENT_RPCS)))
    rls_pb2_grpc.add_RateLimitServiceServicer_to_server(RateLimitService(policy), server)
    if not server.add_insecure_port('0.0.0.0:50051'):
        raise RuntimeError('policy listener could not bind')
    inspection_server, inspection_service, _ = create_server()
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stopped.set)
    try:
        await server.start()
        await inspection_server.start()
        log_event({'event': 'policy_started', 'mode': policy.mode, 'max_clients': policy.max_clients})
        log_event({'event': 'inspection_started', 'max_concurrent_rpcs': 16})
        while not stopped.is_set():
            try:
                await asyncio.wait_for(stopped.wait(), timeout=30)
            except TimeoutError:
                pass
            log_event({'event': 'policy_metrics', **policy.snapshot()})
            log_event({'event': 'inspection_metrics', **inspection_service.snapshot()})
    finally:
        await asyncio.gather(server.stop(3), inspection_server.stop(3))


if __name__ == '__main__':
    asyncio.run(serve())
