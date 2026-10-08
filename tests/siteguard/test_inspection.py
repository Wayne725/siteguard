import asyncio
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import grpc
from envoy.service.ext_proc.v3 import external_processor_pb2 as proto
from envoy.service.ext_proc.v3 import external_processor_pb2_grpc

from siteguard.inspection import (
    LIMIT_METADATA, MAX_MESSAGE_BYTES, create_server, inspect_body, secret_reason,
)


def headers(kind, values, end_stream=False):
    request = proto.ProcessingRequest()
    message = getattr(request, kind)
    message.end_of_stream = end_stream
    for key, value in values:
        header = message.headers.headers.add(key=key)
        header.raw_value = value if isinstance(value, bytes) else value.encode()
    return request


def request_headers(method='GET'):
    return headers('request_headers', [(':method', method), ('authorization', 'do-not-log')], True)


def response_headers(extra=(), status='200', end_stream=False, content_type='application/json'):
    values = [(':status', status)]
    if content_type is not None:
        values.append(('content-type', content_type))
    return headers('response_headers', [*values, *extra], end_stream)


def body(value=b'{"ok":true}', end_stream=True):
    return proto.ProcessingRequest(response_body=proto.HttpBody(body=value, end_of_stream=end_stream))


class InspectionPatternTests(unittest.TestCase):
    def test_module_import_does_not_need_grpc_or_yaml(self):
        result = subprocess.run([sys.executable, '-S', '-c', 'import siteguard.inspection'],
                                cwd=Path(__file__).resolve().parents[2], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_precise_markers_and_boundary_preserving_combined_body(self):
        for key_type in ('', 'RSA ', 'EC ', 'OPENSSH ', 'ENCRYPTED '):
            self.assertEqual(secret_reason(f'-----BEGIN {key_type}PRIVATE KEY-----'.encode()),
                             'response_private_key')
        self.assertEqual(inspect_body(b'prefix ghp_' + b'A' * 18 + b'A' * 18, 128), 'response_token')
        for prefix in (b'glpat-', b'glpat_'):
            self.assertEqual(secret_reason(prefix + b'A' * 20), 'response_token')
        for clean in (b'ghp_short', b'-----BEGIN PUBLIC KEY-----', b'hello', b'glpat-short'):
            self.assertIsNone(secret_reason(clean))


class InspectionRpcTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.server, self.service, port = create_server('127.0.0.1:0')
        await self.server.start()
        self.channel = grpc.aio.insecure_channel(f'127.0.0.1:{port}')
        self.stub = external_processor_pb2_grpc.ExternalProcessorStub(self.channel)

    async def asyncTearDown(self):
        await self.channel.close()
        await self.server.stop(0)

    async def exchange(self, requests, limit='65536', metadata=None):
        async def stream():
            for request in requests:
                yield request

        metadata = [(LIMIT_METADATA, limit)] if metadata is None else metadata
        return [response async for response in self.stub.Process(stream(), metadata=metadata, timeout=2)]

    async def assert_aborts(self, requests, **kwargs):
        with self.assertRaises(grpc.aio.AioRpcError) as error:
            await self.exchange(requests, **kwargs)
        self.assertNotEqual(error.exception.code(), grpc.StatusCode.OK)
        self.assertNotIn('do-not-log', error.exception.details())
        return error.exception

    def assert_blocked(self, responses, reason):
        response = responses[-1]
        self.assertEqual(response.WhichOneof('response'), 'immediate_response')
        self.assertEqual(response.immediate_response.status.code, 502)
        self.assertEqual(response.immediate_response.details, reason)
        self.assertEqual(response.dynamic_metadata['rule'], reason)
        self.assertEqual(response.immediate_response.body, b'Response blocked by site policy.')
        header = response.immediate_response.headers.set_headers[0].header
        self.assertEqual(header.key, 'cache-control')
        self.assertEqual(header.raw_value, b'no-store')
        self.assertEqual(header.value, '')

    async def test_real_bidirectional_stream_holds_until_body_verdict(self):
        call = self.stub.Process(metadata=[(LIMIT_METADATA, '128')], timeout=2)
        await call.write(request_headers())
        first = await call.read()
        mutation = first.request_headers.response.header_mutation
        self.assertEqual(list(mutation.remove_headers), ['range', 'if-range'])
        header = mutation.set_headers[0].header
        self.assertEqual(header.key, 'accept-encoding')
        self.assertEqual(header.raw_value, b'identity')
        self.assertEqual(header.value, '')
        await call.write(response_headers())
        second = await call.read()
        self.assertEqual(second.WhichOneof('response'), 'response_headers')
        self.assertNotIn('response_allowed', self.service.counters)
        await call.write(body())
        final = await call.read()
        self.assertEqual(final.WhichOneof('response'), 'response_body')
        self.assertEqual(final.dynamic_metadata['rule'], 'response_allowed')
        self.assertIs(await call.read(), grpc.aio.EOF)
        self.assertEqual(await call.code(), grpc.StatusCode.OK)

    async def test_exact_size_boundary_and_actual_size_without_content_length(self):
        responses = await self.exchange([request_headers(), response_headers(), body(b'a' * 64)], limit='64')
        self.assertEqual(responses[-1].WhichOneof('response'), 'response_body')
        responses = await self.exchange([request_headers(), response_headers(), body(b'a' * 65)], limit='64')
        self.assert_blocked(responses, 'response_size')
        responses = await self.exchange([request_headers(), response_headers(), body(b'a' * 65536)])
        self.assertEqual(responses[-1].WhichOneof('response'), 'response_body')
        responses = await self.exchange([request_headers(), response_headers(), body(b'a' * 65537)])
        self.assert_blocked(responses, 'response_size')

    async def test_private_key_and_tokens_in_body_or_header_never_echo(self):
        for secret, reason in ((b'-----BEGIN PRIVATE KEY-----', 'response_private_key'),
                               (b'ghp_' + b'X' * 36, 'response_token')):
            for messages in ([response_headers(), body(secret)],
                             [response_headers(extra=[('x-debug', secret)])]):
                result = await self.exchange([request_headers(), *messages])
                self.assert_blocked(result, reason)
                self.assertNotIn(secret, b''.join(item.SerializeToString() for item in result))
                self.assertNotIn(secret.decode(), json.dumps(self.service.snapshot()))

    async def test_uninspectable_headers_fail_closed_before_body(self):
        cases = [
            (response_headers(extra=[('content-encoding', 'gzip')]), 'response_encoding'),
            (response_headers(extra=[('content-encoding', 'br')]), 'response_encoding'),
            (response_headers(extra=[('content-length', '65')]), 'response_size'),
            (response_headers(status='206'), 'response_partial'),
            (response_headers(content_type='application/octet-stream'), 'response_content_type'),
            (response_headers(content_type='text/plain; charset=utf-16'), 'response_content_type'),
            (response_headers(content_type='text/event-stream; charset=utf-8'), 'response_content_type'),
            (response_headers(content_type=None), 'response_content_type'),
            (response_headers(extra=[('trailer', 'x-debug')]), 'response_trailers_unsupported'),
        ]
        for response, reason in cases:
            with self.subTest(reason=reason):
                result = await self.exchange([request_headers(), response], limit='64')
                self.assert_blocked(result, reason)

    async def test_body_must_be_utf8_text_without_nul(self):
        for value in (b'\xff\xfe', b'a\x00b'):
            responses = await self.exchange([request_headers(), response_headers(), body(value)])
            self.assert_blocked(responses, 'response_content_type')

    async def test_head_and_no_body_statuses_still_scan_headers(self):
        for method, status in (('HEAD', '200'), ('GET', '204'), ('GET', '304')):
            for secret in (False, True):
                extra = [('content-length', '999999')]
                if secret:
                    extra.append(('x-debug', 'ghp_' + 'A' * 36))
                result = await self.exchange([request_headers(method), response_headers(
                    extra, status, end_stream=True, content_type=None)])
                if secret:
                    self.assert_blocked(result, 'response_token')
                else:
                    self.assertEqual(result[-1].dynamic_metadata['rule'], 'response_allowed')

    async def test_trailers_and_incomplete_body_are_not_approved(self):
        responses = await self.exchange([request_headers(), response_headers(), body(end_stream=False)])
        self.assert_blocked(responses, 'response_trailers_unsupported')
        trailers = proto.ProcessingRequest()
        trailers.response_trailers.SetInParent()
        await self.assert_aborts([request_headers(), response_headers(), trailers])

    async def test_missing_invalid_duplicate_metadata_never_returns_ok(self):
        for metadata in ([], [(LIMIT_METADATA, '0')], [(LIMIT_METADATA, '65537')],
                         [(LIMIT_METADATA, '64.0')], [(LIMIT_METADATA, ' 64')],
                         [(LIMIT_METADATA, '64'), (LIMIT_METADATA, '64')]):
            with self.subTest(metadata=metadata):
                error = await self.assert_aborts([request_headers()], metadata=metadata)
                self.assertEqual(error.code(), grpc.StatusCode.INTERNAL)
                self.assertEqual(error.details(), 'inspection_metadata')

    async def test_premature_eof_and_wrong_message_order_abort(self):
        for requests in ([], [request_headers()], [request_headers(), response_headers()],
                         [response_headers()], [request_headers(), request_headers()]):
            with self.subTest(count=len(requests)):
                await self.assert_aborts(requests)
        self.assertEqual(self.service.counters.get('response_allowed', 0), 0)

    async def test_observability_and_oversized_messages_are_not_silently_accepted(self):
        request = request_headers()
        request.observability_mode = True
        await self.assert_aborts([request])
        error = await self.assert_aborts([request_headers(), response_headers(),
                                        body(b'a' * (MAX_MESSAGE_BYTES + 1))])
        self.assertEqual(error.code(), grpc.StatusCode.RESOURCE_EXHAUSTED)

    async def test_header_budget_and_duplicate_control_fields_abort(self):
        await self.assert_aborts([request_headers(), response_headers(extra=[('x-value', 'a' * 65536)])])
        await self.assert_aborts([request_headers(), response_headers(extra=[('content-length', '1'),
                                                                         ('content-length', '2')])])

    async def test_rfc_token_header_names_and_extension_methods_are_accepted(self):
        result = await self.exchange([
            request_headers('custom!method.v1'),
            response_headers(extra=[('x-api.version', '1'), ('x!proof', 'safe'),
                                    ("x#$%&'*+^`|~", 'safe')]), body(),
        ])
        self.assertEqual(result[-1].dynamic_metadata['rule'], 'response_allowed')
        for method in ('bad method', 'a' * 65):
            await self.assert_aborts([request_headers(method)])
        for name in ('x:invalid', ':unknown', 'x invalid'):
            await self.assert_aborts([request_headers(), response_headers(extra=[(name, 'safe')])])

    async def test_sse_is_rejected_from_headers_even_for_empty_or_head_responses(self):
        for method, end_stream in (('GET', False), ('GET', True), ('HEAD', True)):
            result = await self.exchange([request_headers(method), response_headers(
                content_type='Text/Event-Stream', end_stream=end_stream)])
            self.assert_blocked(result, 'response_content_type')

    async def test_cancellation_does_not_record_a_completed_decision(self):
        call = self.stub.Process(metadata=[(LIMIT_METADATA, '64')], timeout=2)
        await call.write(request_headers())
        await call.read()
        await call.write(response_headers())
        await call.read()
        call.cancel()
        await asyncio.sleep(.02)
        self.assertEqual(self.service.counters.get('response_allowed', 0), 0)

    async def test_internal_scanner_exception_aborts_without_secret_error_details(self):
        with patch('siteguard.inspection.inspect_body', side_effect=RuntimeError('secret-must-not-escape')):
            error = await self.assert_aborts([request_headers(), response_headers(), body()])
        self.assertEqual(error.code(), grpc.StatusCode.INTERNAL)
        self.assertEqual(error.details(), 'inspection_error')
        self.assertEqual(self.service.counters.get('response_allowed', 0), 0)
        self.assertNotIn('secret-must-not-escape', json.dumps(self.service.snapshot()))

    async def test_deadline_before_response_is_not_an_allow_decision(self):
        call = self.stub.Process(metadata=[(LIMIT_METADATA, '64')], timeout=.05)
        await call.write(request_headers())
        await call.read()
        with self.assertRaises(grpc.aio.AioRpcError) as error:
            await call.read()
        self.assertEqual(error.exception.code(), grpc.StatusCode.DEADLINE_EXCEEDED)
        self.assertEqual(self.service.counters.get('response_allowed', 0), 0)


if __name__ == '__main__':
    unittest.main()
