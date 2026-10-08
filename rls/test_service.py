import asyncio
import os
import unittest

import grpc
from envoy.service.ratelimit.v3 import rls_pb2, rls_pb2_grpc

from rls.policy import AdmissionPolicy, Config, DOMAIN
from rls.server import RateLimitService, validate_origin


def request(kinds=('report',), domain=DOMAIN, hits=0):
    result = rls_pb2.RateLimitRequest(domain=domain, hits_addend=hits)
    for kind in kinds:
        result.descriptors.add().entries.add(key='kind', value=kind)
    return result


class ServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_official_messages_and_atomic_refusal(self):
        service = RateLimitService(AdmissionPolicy(Config(mode='fixed')))
        allowed = await service.ShouldRateLimit(request(hits=2), None)
        self.assertEqual(allowed.overall_code, rls_pb2.RateLimitResponse.OK)
        denied = await service.ShouldRateLimit(request(('orders', 'report')), None)
        self.assertEqual(denied.overall_code, rls_pb2.RateLimitResponse.OVER_LIMIT)
        self.assertEqual(denied.dynamic_metadata['decision'], 'rate_limited')
        self.assertEqual(denied.dynamic_metadata['mode'], 'fixed')
        self.assertEqual(service.policy.buckets['orders'].tokens, 8)
        self.assertEqual(len(denied.statuses), 2)

    async def test_invalid_domain_descriptor_and_override_are_denied(self):
        service = RateLimitService(AdmissionPolicy(Config(mode='bypass')))
        malformed = request()
        malformed.descriptors[0].entries[0].key = 'user-provided-kind'
        override = request()
        override.descriptors[0].limit.requests_per_unit = 100
        extra_entry = request()
        extra_entry.descriptors[0].entries.add(key='other', value='value')
        for value in (request(domain='other'), request(kinds=()), request(('admin',)),
                      malformed, override, extra_entry):
            result = await service.ShouldRateLimit(value, None)
            self.assertEqual(result.overall_code, rls_pb2.RateLimitResponse.OVER_LIMIT)
            self.assertEqual(result.dynamic_metadata['decision'], 'invalid_request')

    async def test_concurrent_callbacks_do_not_overspend_tokens(self):
        service = RateLimitService(AdmissionPolicy(Config(mode='fixed'), clock=lambda: 0))
        results = await asyncio.gather(*(service.ShouldRateLimit(request(), None) for _ in range(20)))
        self.assertEqual(sum(result.overall_code == rls_pb2.RateLimitResponse.OK for result in results), 2)

    def test_backend_origin_does_not_accept_external_hosts_or_redirect_targets(self):
        self.assertEqual(validate_origin('http://app:8000/'), 'http://app:8000')
        for value in ('https://example.com', 'http://example.com:8000', 'http://user:pass@app:8000',
                      'http://app:8000/other', 'http://app:8000?target=elsewhere', 'http://app:8080'):
            with self.assertRaises(ValueError):
                validate_origin(value)


@unittest.skipUnless(os.environ.get('RUN_RLS_SOCKET_TESTS') == '1', 'set RUN_RLS_SOCKET_TESTS=1 for loopback gRPC transport')
class GrpcTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_generated_client_calls_real_aio_server(self):
        server = grpc.aio.server()
        rls_pb2_grpc.add_RateLimitServiceServicer_to_server(
            RateLimitService(AdmissionPolicy(Config(mode='fixed'), clock=lambda: 0)), server)
        port = server.add_insecure_port('127.0.0.1:0')
        self.assertGreater(port, 0)
        await server.start()
        try:
            async with grpc.aio.insecure_channel(f'127.0.0.1:{port}') as channel:
                stub = rls_pb2_grpc.RateLimitServiceStub(channel)
                results = [await stub.ShouldRateLimit(request(), timeout=2) for _ in range(3)]
            self.assertEqual([result.overall_code for result in results], [1, 1, 2])
            self.assertEqual(results[-1].dynamic_metadata['report_rate'], 2)
        finally:
            await server.stop(0)


if __name__ == '__main__':
    unittest.main()
