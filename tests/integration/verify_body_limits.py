"""Ten bounded requests to verify the 1024-byte gateway body limit on real transports."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import socket
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HOST = '127.0.0.1'
PORT = 18088
LIMIT = 1024
TIMEOUT = 3
PIECE_DELAY_SECONDS = .05
RESPONSE_LIMIT = 16384
TRANSPORTS = ('http1_content_length_one_piece', 'http1_content_length_two_pieces',
              'http1_chunked_two_pieces', 'http2_one_data_frame', 'http2_two_data_frames')


def local_url(value):
    normalized = value.removesuffix('/')
    if normalized not in ('http://127.0.0.1:18088', 'http://localhost:18088'):
        raise argparse.ArgumentTypeError('Only the local gateway at http://127.0.0.1:18088 is permitted.')
    return f'http://{HOST}:{PORT}'


def new_record(transport, size):
    payload = (b'0123456789abcdef' * ((size + 15) // 16))[:size]
    return payload, {
        'transport': transport, 'request_bytes': size, 'configured_limit_bytes': LIMIT,
        'method': 'POST', 'path': '/echo', 'request_payload_utf8': payload.decode('ascii'),
        'request_sha256': hashlib.sha256(payload).hexdigest(), 'expected_status': 200 if size <= LIMIT else 413,
        'status': 0, 'response_complete': False, 'response_headers': {}, 'response_body_utf8': '',
        'transport_error': None, 'send_events': [], 'receive_events': [],
    }


def finish_record(record, payload, response_body, started):
    record['elapsed_ms'] = round((time.monotonic() - started) * 1000, 3)
    record['response_body_utf8'] = response_body.decode('utf-8', errors='replace')
    record['response_body_hex'] = response_body.hex()
    record['response_body_bytes'] = len(response_body)
    record['response_sha256'] = hashlib.sha256(response_body).hexdigest()
    try:
        body = json.loads(response_body).get('body')
    except (ValueError, AttributeError):
        body = None
    echoed = body.encode('utf-8') if isinstance(body, str) else None
    record['echoed_body_bytes'] = len(echoed) if echoed is not None else None
    record['echo_matches_request'] = echoed == payload
    record['passed'] = (record['transport_error'] is None and record['response_complete']
                        and record['status'] == record['expected_status']
                        and (record['expected_status'] == 413 or record['echo_matches_request']))
    return record


def http1_case(transport, size):
    payload, record = new_record(transport, size)
    connection = http.client.HTTPConnection(HOST, PORT, timeout=TIMEOUT)
    started = time.monotonic()
    response_body = b''
    chunked = transport == 'http1_chunked_two_pieces'
    two_pieces = transport != 'http1_content_length_one_piece'
    headers = {'Content-Type': 'text/plain; charset=utf-8', 'Host': f'{HOST}:{PORT}',
               **({'Transfer-Encoding': 'chunked'} if chunked else {'Content-Length': str(size)})}
    record['request_headers'] = headers
    try:
        connection.putrequest('POST', '/echo', skip_host=True, skip_accept_encoding=True)
        for name, value in headers.items():
            connection.putheader(name, value)
        connection.endheaders()
        pieces = [payload[:size // 2], payload[size // 2:]] if two_pieces else [payload]
        for index, piece in enumerate(pieces):
            if index:
                time.sleep(PIECE_DELAY_SECONDS)
            sent = f'{len(piece):x}\r\n'.encode() + piece + b'\r\n' if chunked else piece
            connection.send(sent)
            record['send_events'].append({'piece': index + 1, 'body_bytes': len(piece),
                                          'wire_bytes': len(sent),
                                          'elapsed_ms': round((time.monotonic() - started) * 1000, 3)})
        if chunked:
            connection.send(b'0\r\n\r\n')
            record['send_events'].append({'chunked_terminator_bytes': 5})
        response = connection.getresponse()
        record['status'] = response.status
        record['response_headers'] = dict(response.getheaders())
        response_body = response.read(RESPONSE_LIMIT + 1)
        if len(response_body) > RESPONSE_LIMIT:
            raise ValueError('Response exceeds the bounded matrix limit')
        record['response_complete'] = True
        record['receive_events'].append({'event': 'http_response_complete', 'status': response.status})
    except (OSError, http.client.HTTPException, ValueError) as exc:
        record['transport_error'] = f'{type(exc).__name__}: {exc}'
    finally:
        connection.close()
    return finish_record(record, payload, response_body, started)


def http2_case(transport, size):
    payload, record = new_record(transport, size)
    started = time.monotonic()
    response_body = bytearray()
    try:
        import h2.config
        import h2.connection
        import h2.events
        import h2.exceptions
    except ImportError as exc:
        record['transport_error'] = f'HTTP/2 development dependency is unavailable: {exc}'
        return finish_record(record, payload, bytes(response_body), started)
    record['http2_library_version'] = h2.__version__
    headers = [(':method', 'POST'), (':scheme', 'http'), (':authority', f'{HOST}:{PORT}'),
               (':path', '/echo'), ('content-type', 'text/plain; charset=utf-8')]
    record['request_headers'] = dict(headers)
    record['stream_id'] = 1
    protocol = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True, header_encoding='utf-8'))
    pieces = [payload[:size // 2], payload[size // 2:]] if transport == 'http2_two_data_frames' else [payload]
    try:
        with socket.create_connection((HOST, PORT), timeout=TIMEOUT) as connection:
            protocol.initiate_connection()
            protocol.send_headers(1, headers, end_stream=False)
            for index, piece in enumerate(pieces):
                if index:
                    time.sleep(PIECE_DELAY_SECONDS)
                last = index == len(pieces) - 1
                protocol.send_data(1, piece, end_stream=last)
                outgoing = protocol.data_to_send()
                connection.sendall(outgoing)
                record['send_events'].append({'data_frame': index + 1, 'stream_id': 1,
                                              'body_bytes': len(piece), 'end_stream': last,
                                              'wire_bytes_including_pending_control_frames': len(outgoing),
                                              'elapsed_ms': round((time.monotonic() - started) * 1000, 3)})
            for _ in range(32):
                incoming = connection.recv(RESPONSE_LIMIT)
                if not incoming:
                    raise EOFError('HTTP/2 connection ended without a complete stream response')
                for event in protocol.receive_data(incoming):
                    record['receive_events'].append({'event': type(event).__name__,
                                                     'stream_id': getattr(event, 'stream_id', None),
                                                     'error_code': int(event.error_code)
                                                     if hasattr(event, 'error_code') else None})
                    if getattr(event, 'stream_id', 1) != 1:
                        continue
                    if isinstance(event, h2.events.ResponseReceived):
                        record['response_headers'] = dict(event.headers)
                        record['status'] = int(record['response_headers'].get(':status', 0))
                    elif isinstance(event, h2.events.DataReceived):
                        response_body.extend(event.data)
                        protocol.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, h2.events.StreamEnded):
                        record['response_complete'] = True
                    elif isinstance(event, h2.events.StreamReset) and not record['response_complete']:
                        raise RuntimeError(f'HTTP/2 stream reset before response completion: {event.error_code}')
                    elif isinstance(event, h2.events.ConnectionTerminated) and not record['response_complete']:
                        raise RuntimeError(f'HTTP/2 connection terminated before response completion: {event.error_code}')
                if len(response_body) > RESPONSE_LIMIT:
                    raise ValueError('HTTP/2 response exceeds the bounded matrix limit')
                if record['response_complete']:
                    break
                outgoing = protocol.data_to_send()
                if outgoing:
                    connection.sendall(outgoing)
            if not record['response_complete']:
                raise RuntimeError('HTTP/2 response did not finish within the bounded receive loop')
    except (OSError, EOFError, RuntimeError, ValueError, h2.exceptions.H2Error) as exc:
        record['transport_error'] = f'{type(exc).__name__}: {exc}'
    return finish_record(record, payload, bytes(response_body), started)


def run_matrix(base_url):
    base_url = local_url(base_url)
    records = [(http2_case(transport, size) if transport.startswith('http2') else http1_case(transport, size))
               for transport in TRANSPORTS for size in (LIMIT, LIMIT + 1)]
    return {
        'schema_version': 1, 'suite': 'exact_body_limit_transports', 'base_url': base_url,
        'created_at': datetime.now(timezone.utc).isoformat(), 'python': sys.version,
        'configured_limit_bytes': LIMIT, 'piece_delay_ms': PIECE_DELAY_SECONDS * 1000,
        'request_count': len(records), 'passed': all(record['passed'] for record in records),
        'passed_requests': sum(record['passed'] for record in records), 'requests': records,
        'prerequisites': [
            'Gateway is already running in enforce mode with max_body_bytes exactly 1024.',
            '/echo is an ordinary non-streaming route pointing at the owned fixture.',
            'Global, route and per-IP admission buckets permit all ten requests; an unrelated 429 is a failure.',
            'This tool never starts or changes gateway, fixture, policy, Docker or configuration.'],
        'interpretation': [
            'Exactly 1024 bytes requires HTTP 200 and an exact echoed payload on the same response.',
            'Exactly 1025 bytes requires a complete real HTTP 413 response; a reset, EOF or timeout is not a substitute.',
            'HTTP/2 uses prior knowledge with one stream per case and no Content-Length header.',
            'The two-piece variants wait 50 ms between application writes or HTTP/2 DATA frames; '
            'TCP segmentation itself is controlled by the network stack.',
            'The ten-request matrix is a boundary regression, not a load test or broad protocol certification.'],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', type=local_url, default=f'http://{HOST}:{PORT}')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run_matrix(args.base_url)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
    for record in result['requests']:
        print(f'{record["transport"]}: {record["request_bytes"]} bytes -> '
              f'{record["status"]}; {"PASS" if record["passed"] else "FAIL"}')
    print(args.output)
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
