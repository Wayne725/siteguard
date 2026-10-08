"""Bounded response inspection for explicit, non-streaming Envoy routes."""
from __future__ import annotations

import asyncio
from collections import Counter
import re


MAX_MESSAGE_BYTES = 131072
MAX_CONCURRENT_RPCS = 16
MAX_HEADER_BYTES = 65536
MAX_BODY_BYTES = 65536
LIMIT_METADATA = 'x-siteguard-max-bytes'
HTTP_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
PSEUDO_HEADERS = frozenset({':method', ':scheme', ':authority', ':path', ':status', ':protocol'})
PRIVATE_KEY = re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----')
TOKEN = re.compile(rb'(?<![A-Za-z0-9_])(?:ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9])|glpat[-_][A-Za-z0-9_-]{20,255})')
REASONS = frozenset({
    'response_allowed', 'response_private_key', 'response_token', 'response_encoding',
    'response_size', 'response_content_type', 'response_partial',
    'response_trailers_unsupported', 'inspection_metadata', 'inspection_protocol',
    'inspection_cancelled', 'inspection_error',
})


class InspectionError(ValueError):
    pass


def secret_reason(value: bytes) -> str | None:
    if PRIVATE_KEY.search(value):
        return 'response_private_key'
    if TOKEN.search(value):
        return 'response_token'
    return None


def parse_limit(metadata) -> int:
    values = [value for key, value in metadata if key == LIMIT_METADATA]
    if (len(values) != 1 or not isinstance(values[0], str)
            or not re.fullmatch(r'[1-9][0-9]{0,4}', values[0])):
        raise InspectionError('inspection_metadata')
    limit = int(values[0])
    if limit > MAX_BODY_BYTES:
        raise InspectionError('inspection_metadata')
    return limit


def header_pairs(message) -> list[tuple[str, bytes]]:
    result = []
    total = 0
    if len(message.headers.headers) > 128:
        raise InspectionError('inspection_protocol')
    for entry in message.headers.headers:
        key = entry.key.lower()
        if (not key.isascii() or (key not in PSEUDO_HEADERS and not HTTP_TOKEN.fullmatch(key.encode()))
                or (entry.value and entry.raw_value)):
            raise InspectionError('inspection_protocol')
        value = entry.raw_value or entry.value.encode('utf-8')
        total += len(key) + len(value)
        if total > MAX_HEADER_BYTES or b'\r' in value or b'\n' in value:
            raise InspectionError('inspection_protocol')
        result.append((key, value))
    return result


def single_header(headers: list[tuple[str, bytes]], key: str) -> bytes | None:
    values = [value for name, value in headers if name == key]
    if len(values) > 1:
        raise InspectionError('inspection_protocol')
    return values[0] if values else None


def inspect_headers(headers: list[tuple[str, bytes]], method: bytes,
                    end_stream: bool, limit: int) -> str | None:
    for _, value in headers:
        reason = secret_reason(value)
        if reason:
            return reason
    status_value = single_header(headers, ':status')
    if status_value is None or not re.fullmatch(rb'[2-5][0-9]{2}', status_value):
        raise InspectionError('inspection_protocol')
    status = int(status_value)
    if status == 206:
        return 'response_partial'
    encoding = single_header(headers, 'content-encoding')
    if encoding is not None and encoding.strip().lower() != b'identity':
        return 'response_encoding'
    if single_header(headers, 'trailer'):
        return 'response_trailers_unsupported'
    no_body = method == b'HEAD' or status in (204, 304)
    if no_body and not end_stream:
        raise InspectionError('inspection_protocol')
    length = single_header(headers, 'content-length')
    if length is not None:
        if not re.fullmatch(rb'[0-9]{1,20}', length):
            raise InspectionError('inspection_protocol')
        if not no_body and int(length) > limit:
            return 'response_size'
    content_type = single_header(headers, 'content-type')
    parts = [part.strip().lower() for part in content_type.split(b';')] if content_type else []
    if parts and parts[0] == b'text/event-stream':
        return 'response_content_type'
    if no_body:
        return None
    if content_type is None:
        return None if end_stream else 'response_content_type'
    media_type = parts[0] if parts else b''
    if not (re.fullmatch(rb'text/[a-z0-9.+_-]+', media_type)
            or media_type == b'application/json'
            or re.fullmatch(rb'application/[a-z0-9._+-]+\+json', media_type)):
        return 'response_content_type'
    for part in parts[1:]:
        if part.startswith(b'charset='):
            charset = part.partition(b'=')[2].strip(b'"')
            if charset not in (b'utf-8', b'utf8', b'us-ascii', b'ascii'):
                return 'response_content_type'
    return None


def inspect_body(body: bytes, limit: int) -> str | None:
    if len(body) > limit:
        return 'response_size'
    if b'\x00' in body:
        return 'response_content_type'
    try:
        body.decode('utf-8')
    except UnicodeDecodeError:
        return 'response_content_type'
    return secret_reason(body)


class InspectionService:
    def __init__(self):
        self.counters: Counter = Counter()

    def snapshot(self) -> dict:
        return {'counters': dict(self.counters)}

    def _record(self, reason: str) -> None:
        if reason not in REASONS:
            raise ValueError('unknown inspection rule')
        self.counters[reason] += 1

    def _reject(self, reason: str):
        from envoy.service.ext_proc.v3 import external_processor_pb2 as proto

        self._record(reason)
        response = proto.ProcessingResponse()
        immediate = response.immediate_response
        immediate.status.code = 502
        immediate.body = b'Response blocked by site policy.'
        immediate.details = reason
        header = immediate.headers.set_headers.add()
        header.header.key = 'cache-control'
        header.header.raw_value = b'no-store'
        header.append_action = 2
        response.dynamic_metadata.update({'rule': reason})
        return response

    async def Process(self, request_iterator, context):
        import grpc
        from envoy.service.ext_proc.v3 import external_processor_pb2 as proto

        state = 'request_headers'
        method = None
        try:
            limit = parse_limit(context.invocation_metadata())
            async for request in request_iterator:
                remaining = context.time_remaining()
                if context.cancelled() or (remaining is not None and remaining <= 0):
                    raise InspectionError('inspection_cancelled')
                kind = request.WhichOneof('request')
                if (request.ByteSize() > MAX_MESSAGE_BYTES or request.observability_mode
                        or kind != state):
                    raise InspectionError('inspection_protocol')
                response = proto.ProcessingResponse()
                if state == 'request_headers':
                    headers = header_pairs(request.request_headers)
                    method = single_header(headers, ':method')
                    if method is None or len(method) > 64 or not HTTP_TOKEN.fullmatch(method):
                        raise InspectionError('inspection_protocol')
                    mutation = response.request_headers.response.header_mutation
                    mutation.remove_headers.extend(['range', 'if-range'])
                    header = mutation.set_headers.add()
                    header.header.key = 'accept-encoding'
                    header.header.raw_value = b'identity'
                    header.append_action = 2
                    state = 'response_headers'
                    yield response
                elif state == 'response_headers':
                    message = request.response_headers
                    headers = header_pairs(message)
                    reason = inspect_headers(headers, method, message.end_of_stream, limit)
                    if reason:
                        yield self._reject(reason)
                        return
                    response.response_headers.response.SetInParent()
                    if message.end_of_stream:
                        self._record('response_allowed')
                        response.dynamic_metadata.update({'rule': 'response_allowed'})
                        yield response
                        return
                    state = 'response_body'
                    yield response
                else:
                    message = request.response_body
                    if not message.end_of_stream:
                        yield self._reject('response_trailers_unsupported')
                        return
                    if message.grpc_message_compressed or message.end_of_stream_without_message:
                        raise InspectionError('inspection_protocol')
                    reason = inspect_body(message.body, limit)
                    if reason:
                        yield self._reject(reason)
                        return
                    self._record('response_allowed')
                    response.response_body.response.SetInParent()
                    response.dynamic_metadata.update({'rule': 'response_allowed'})
                    yield response
                    return
            raise InspectionError('inspection_protocol')
        except InspectionError as error:
            reason = str(error)
            self._record(reason)
            await context.abort(grpc.StatusCode.INTERNAL, reason)
        except asyncio.CancelledError:
            self._record('inspection_cancelled')
            raise
        except Exception:
            self._record('inspection_error')
            await context.abort(grpc.StatusCode.INTERNAL, 'inspection_error')


def create_server(address: str = '0.0.0.0:50052'):
    import grpc
    from envoy.service.ext_proc.v3 import external_processor_pb2_grpc

    service = InspectionService()
    server = grpc.aio.server(
        maximum_concurrent_rpcs=MAX_CONCURRENT_RPCS,
        options=(('grpc.max_receive_message_length', MAX_MESSAGE_BYTES),
                 ('grpc.max_send_message_length', MAX_MESSAGE_BYTES),
                 ('grpc.max_concurrent_streams', MAX_CONCURRENT_RPCS)))
    external_processor_pb2_grpc.add_ExternalProcessorServicer_to_server(service, server)
    port = server.add_insecure_port(address)
    if not port:
        raise RuntimeError('inspection listener could not bind')
    return server, service, port
