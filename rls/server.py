"""Official Envoy v3 RateLimitService with bounded backend feedback polling."""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import signal
from pathlib import Path
from urllib.parse import urlsplit

import grpc
import httpx
from envoy.service.ratelimit.v3 import rls_pb2, rls_pb2_grpc

from rls.policy import AdmissionPolicy, Config, DOMAIN


def log_event(event: dict) -> None:
    print(json.dumps(event, ensure_ascii=False, separators=(',', ':')), flush=True)


class RateLimitService(rls_pb2_grpc.RateLimitServiceServicer):
    def __init__(self, policy: AdmissionPolicy):
        self.policy = policy

    async def ShouldRateLimit(self, request, context):
        kinds = []
        valid = request.domain == DOMAIN and 1 <= len(request.descriptors) <= 32
        for descriptor in request.descriptors:
            if (len(descriptor.entries) != 1 or descriptor.entries[0].key != 'kind'
                    or descriptor.HasField('limit') or descriptor.HasField('hits_addend')):
                valid = False
                break
            kinds.append(descriptor.entries[0].value)
        if valid:
            decision = self.policy.decide(kinds, request.hits_addend or 1)
            allowed, reason = decision.allowed, decision.reason
            limited = decision.limited_kinds
        else:
            allowed, reason, limited = False, 'invalid_request', ()
        code = rls_pb2.RateLimitResponse.OK if allowed else rls_pb2.RateLimitResponse.OVER_LIMIT
        response = rls_pb2.RateLimitResponse(overall_code=code)
        for index, descriptor in enumerate(request.descriptors):
            status = response.statuses.add()
            kind = kinds[index] if index < len(kinds) else ''
            status.code = (rls_pb2.RateLimitResponse.OVER_LIMIT
                           if not allowed and (not limited or kind in limited)
                           else rls_pb2.RateLimitResponse.OK)
        response.dynamic_metadata.update(self.policy.metadata(reason))
        if not allowed:
            response.raw_body = json.dumps({'ok': False, 'reason': reason}).encode()
            response.response_headers_to_add.add(key='content-type', value='application/json')
            if reason == 'rate_limited':
                response.response_headers_to_add.add(key='retry-after', value='1')
        return response


def validate_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme != 'http' or parsed.hostname not in ('app', 'localhost', '127.0.0.1')
            or parsed.port != 8000 or parsed.username or parsed.password
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment):
        raise ValueError('LAB_ORIGIN_URL must be http://app:8000 or the local origin on port 8000')
    return value.rstrip('/')


async def poll_backend(policy: AdmissionPolicy, origin: str, token_file: Path) -> None:
    failure_logged = False
    async with httpx.AsyncClient(timeout=.5, follow_redirects=False, trust_env=False) as client:
        while True:
            try:
                token = token_file.read_text(encoding='utf-8').strip()
                if not token:
                    raise ValueError('empty admin token')
                response = await client.get(f'{origin}/lab/state', headers={'x-lab-admin': token})
                response.raise_for_status()
                policy.observe(response.json())
                if failure_logged:
                    log_event({'event': 'backend_poll_recovered'})
                failure_logged = False
            except (OSError, ValueError, httpx.HTTPError) as exc:
                if not failure_logged:
                    log_event({'event': 'backend_poll_unavailable', 'error_type': type(exc).__name__})
                failure_logged = True
            policy.advance()
            await asyncio.sleep(.25)


async def serve() -> None:
    config = Config.from_env()
    origin = validate_origin(os.environ.get('LAB_ORIGIN_URL', 'http://127.0.0.1:8000'))
    token_file = Path(os.environ.get('LAB_ADMIN_TOKEN_FILE', 'local_ddos_lab/runtime/admin.token'))
    bind = os.environ.get('RLS_BIND', '127.0.0.1:50051')
    if bind not in ('127.0.0.1:50051', '0.0.0.0:50051'):
        raise ValueError('RLS_BIND must be 127.0.0.1:50051 or 0.0.0.0:50051')
    policy = AdmissionPolicy(config, on_change=log_event)
    server = grpc.aio.server(options=(('grpc.max_receive_message_length', 65536),
                                      ('grpc.max_send_message_length', 65536)))
    rls_pb2_grpc.add_RateLimitServiceServicer_to_server(RateLimitService(policy), server)
    if not server.add_insecure_port(bind):
        raise RuntimeError('RLS listener could not bind')
    await server.start()
    log_event({'event': 'rls_started', 'bind': bind, 'mode': config.mode,
               'rates': config.rates, 'bursts': config.bursts})
    polling = asyncio.create_task(poll_backend(policy, origin, token_file))
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stopped.set)
    try:
        await stopped.wait()
    finally:
        polling.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await polling
        await server.stop(3)


if __name__ == '__main__':
    asyncio.run(serve())
