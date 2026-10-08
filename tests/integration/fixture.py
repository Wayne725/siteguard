"""Owned loopback-only HTTP fixture; no dependency on the existing lab."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from email.parser import BytesParser
from email.policy import default
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

HOST = '127.0.0.1'
PORTS = (18100, 18101)
BODY_LIMIT = 1024 * 1024
WORKERS = 4
MAX_OUTSTANDING = 24
HEAVY_SECONDS = .35
SSE_DELAY_SECONDS = .7
RANGE_BODY = bytes(range(256)) * 128


class FixtureState:
    def __init__(self):
        self.lock = threading.Lock()
        self.available = True
        self.outstanding = 0
        self.running = 0
        self.peak_running = 0
        self.orders = {}
        self.post_attempts = {}
        self.post_executions = {}
        self.worker_records = []
        self.pool = ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix='fixture-worker')

    def snapshot(self):
        with self.lock:
            return {'fixture': 'siteguard-loopback-v1', 'available': self.available,
                    'workers': WORKERS, 'outstanding': self.outstanding,
                    'running': self.running, 'peak_running': self.peak_running,
                    'orders': dict(self.orders), 'post_attempts': dict(self.post_attempts),
                    'post_executions': dict(self.post_executions),
                    'worker_records': list(self.worker_records)}

    def submit(self, kind, request_id):
        with self.lock:
            if self.outstanding >= MAX_OUTSTANDING:
                return None
            self.outstanding += 1
        queued_at = time.monotonic()

        def execute():
            started_at = time.monotonic()
            with self.lock:
                self.running += 1
                self.peak_running = max(self.peak_running, self.running)
            try:
                if kind == 'heavy':
                    deadline = started_at + HEAVY_SECONDS
                    while time.monotonic() < deadline:
                        hashlib.pbkdf2_hmac('sha256', b'bounded-fixture-work', b'fixed-salt', 3000)
                    return {'ok': True, 'kind': kind}
                with self.lock:
                    self.post_executions[request_id] = self.post_executions.get(request_id, 0) + 1
                    self.orders.setdefault(request_id, {'order_id': request_id, 'quantity': 1})
                    return {'ok': True, 'persisted': True, **self.orders[request_id]}
            finally:
                ended_at = time.monotonic()
                with self.lock:
                    self.running -= 1
                    self.outstanding -= 1
                    self.worker_records.append({'kind': kind, 'request_id': request_id,
                                                'queue_ms': round((started_at - queued_at) * 1000, 3),
                                                'started_at': started_at, 'ended_at': ended_at})

        return self.pool.submit(execute)


def read_exact(stream, length):
    chunks = bytearray()
    while len(chunks) < length:
        chunk = stream.read(length - len(chunks))
        if not chunk:
            raise EOFError('WebSocket stream ended before frame completion')
        chunks.extend(chunk)
    return bytes(chunks)


def read_frame(stream, require_mask=False):
    first, second = read_exact(stream, 2)
    if not first & 0x80 or first & 0x70:
        raise ValueError('Fixture accepts unfragmented frames without extensions only')
    masked = bool(second & 0x80)
    if require_mask and not masked:
        raise ValueError('Client frames must be masked')
    length = second & 0x7f
    if length == 126:
        length = struct.unpack('!H', read_exact(stream, 2))[0]
    elif length == 127:
        length = struct.unpack('!Q', read_exact(stream, 8))[0]
    if length > 65536:
        raise ValueError('Fixture frame exceeds 64 KiB')
    mask = read_exact(stream, 4) if masked else None
    payload = read_exact(stream, length)
    if mask:
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return first & 0x0f, payload


def frame(opcode, payload, mask=None):
    length = len(payload)
    header = bytes([0x80 | opcode, (0x80 if mask else 0) | (length if length < 126 else 126)])
    if length >= 126:
        if length > 65535:
            raise ValueError('Fixture frame exceeds 65535 bytes')
        header += struct.pack('!H', length)
    if mask:
        return header + mask + bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return header + payload


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    @property
    def state(self):
        return self.server.fixture_state

    def log_message(self, *_):
        pass

    def reply(self, status, body=b'', content_type='application/json', headers=None):
        if isinstance(body, dict):
            body = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        try:
            self.route()
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            self.close_connection = True

    def route(self):
        split = urlsplit(self.path)
        path = unquote(split.path)
        size = int(self.headers.get('Content-Length', 0))
        if size < 0 or size > BODY_LIMIT:
            self.close_connection = True
            return self.reply(413, {'error': 'fixture_body_limit'})
        body = self.rfile.read(size) if size else b''
        if len(body) != size:
            self.close_connection = True
            return
        if path == '/fixture/state':
            return self.reply(200, self.state.snapshot())
        if path == '/fixture/reset' and self.command == 'POST':
            with self.state.lock:
                if self.state.outstanding:
                    return self.reply(409, {'error': 'wait_for_drain'})
                self.state.orders.clear()
                self.state.post_attempts.clear()
                self.state.post_executions.clear()
                self.state.worker_records.clear()
                self.state.peak_running = 0
            return self.reply(200, {'ok': True})
        if path == '/fixture/availability' and self.command == 'POST':
            available = json.loads(body).get('available')
            if not isinstance(available, bool):
                return self.reply(400, {'error': 'boolean_required'})
            self.state.available = available
            return self.reply(200, {'available': available})
        if not self.state.available:
            return self.reply(503, {'error': 'origin_temporarily_unavailable'}, headers={'Retry-After': '1'})
        if path == '/health':
            return self.reply(200, {'fixture': 'siteguard-loopback-v1', 'ready': True})
        if path == '/':
            return self.reply(200, '<!doctype html><title>測試網站</title><p>正常頁面</p>'.encode(),
                              'text/html; charset=utf-8')
        if path in ('/echo', '/中文/頁面'):
            return self.reply(200, {'method': self.command, 'path': path,
                                   'query': parse_qs(split.query, keep_blank_values=True),
                                   'authorization': self.headers.get('Authorization'),
                                   'cookie': self.headers.get('Cookie'),
                                   'content_type': self.headers.get('Content-Type'),
                                   'body': body.decode('utf-8'),
                                   'forwarded_headers': {
                                       name.lower(): value for name, value in self.headers.items()
                                       if name.lower().startswith('x-envoy-') or name.lower() in
                                       ('x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto',
                                        'x-real-ip', 'forwarded')},
                                   'x_test': self.headers.get('X-Test')},
                              headers={'Set-Cookie': 'fixture_cookie=ok; Path=/; HttpOnly; SameSite=Lax'})
        if path == '/redirect':
            return self.reply(302, b'', headers={'Location': '/destination?from=redirect'})
        if path == '/destination':
            return self.reply(200, {'destination': True})
        if path == '/cache':
            headers = {'ETag': '"fixture-v1"', 'Cache-Control': 'public, max-age=60'}
            return self.reply(304 if self.headers.get('If-None-Match') == '"fixture-v1"' else 200,
                              b'' if self.headers.get('If-None-Match') == '"fixture-v1"' else b'cache-body',
                              'text/plain', headers)
        if path == '/range':
            selected = self.headers.get('Range')
            if not selected:
                return self.reply(200, RANGE_BODY, 'application/octet-stream', {'Accept-Ranges': 'bytes'})
            if selected != 'bytes=100-199':
                return self.reply(416, b'', headers={'Content-Range': f'bytes */{len(RANGE_BODY)}'})
            return self.reply(206, RANGE_BODY[100:200], 'application/octet-stream',
                              {'Content-Range': f'bytes 100-199/{len(RANGE_BODY)}', 'Accept-Ranges': 'bytes'})
        if path == '/upload' and self.command == 'POST':
            content_type = self.headers.get('Content-Type', '')
            message = BytesParser(policy=default).parsebytes(
                f'Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n'.encode() + body)
            parts = [{'name': part.get_param('name', header='content-disposition'),
                      'filename': part.get_filename(), 'size': len(part.get_payload(decode=True)),
                      'sha256': hashlib.sha256(part.get_payload(decode=True)).hexdigest()}
                     for part in message.iter_parts()]
            return self.reply(200, {'body_bytes': len(body), 'parts': parts})
        if path == '/events':
            self.send_response(200)
            for name, value in {'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache',
                                'Connection': 'close', 'X-Accel-Buffering': 'no'}.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(b'event: first\ndata: immediately\n\n')
            self.wfile.flush()
            time.sleep(SSE_DELAY_SECONDS)
            self.wfile.write(b'event: second\ndata: later\n\n')
            self.wfile.flush()
            self.close_connection = True
            return
        if path == '/delay':
            milliseconds = int(parse_qs(split.query).get('ms', ['700'])[0])
            if not 0 <= milliseconds <= 1500:
                return self.reply(400, {'error': 'delay_out_of_bounds'})
            time.sleep(milliseconds / 1000)
            return self.reply(200, {'ok': True, 'delay_ms': milliseconds})
        if path == '/ws':
            return self.websocket()
        if path in ('/heavy', '/orders'):
            request_id = self.headers.get('X-Request-ID', '')
            if path == '/orders':
                if self.command != 'POST':
                    return self.reply(405, {'error': 'POST_required'})
                request_id = json.loads(body).get('request_id', '')
                if not request_id or len(request_id) > 64:
                    return self.reply(400, {'error': 'request_id_required'})
                with self.state.lock:
                    self.state.post_attempts[request_id] = self.state.post_attempts.get(request_id, 0) + 1
            future = self.state.submit('heavy' if path == '/heavy' else 'orders', request_id)
            if future is None:
                return self.reply(503, {'error': 'fixture_capacity'})
            return self.reply(200, future.result(timeout=4))
        return self.reply(404, {'error': 'not_found'})

    def websocket(self):
        key = self.headers.get('Sec-WebSocket-Key', '')
        if self.headers.get('Upgrade', '').lower() != 'websocket' or not key:
            return self.reply(400, {'error': 'websocket_upgrade_required'})
        accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        self.send_response(101)
        for name, value in {'Upgrade': 'websocket', 'Connection': 'Upgrade', 'Sec-WebSocket-Accept': accept}.items():
            self.send_header(name, value)
        self.end_headers()
        self.connection.settimeout(3)
        self.close_connection = True
        try:
            for _ in range(8):
                opcode, payload = read_frame(self.rfile, require_mask=True)
                if opcode not in (1, 2, 8, 9):
                    return
                self.wfile.write(frame(10 if opcode == 9 else opcode, payload))
                self.wfile.flush()
                if opcode == 8:
                    return
        except (EOFError, ValueError):
            return


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = False
    allow_reuse_address = True
    request_queue_size = 32

    def __init__(self, port):
        if port not in PORTS:
            raise ValueError(f'Fixture may bind only {HOST} on {PORTS}')
        self.connections_lock = threading.Lock()
        self.connections = set()
        self.fixture_state = FixtureState()
        super().__init__((HOST, port), FixtureHandler)

    def get_request(self):
        connection, address = super().get_request()
        with self.connections_lock:
            self.connections.add(connection)
        return connection, address

    def close_request(self, connection):
        with self.connections_lock:
            self.connections.discard(connection)
        super().close_request(connection)

    def server_close(self):
        self.socket.close()
        with self.connections_lock:
            connections = list(self.connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                # The peer or its handler may have closed this socket already.
                pass
        # Non-daemon handlers must finish before their shared worker pool closes.
        super().server_close()
        self.fixture_state.pool.shutdown(wait=True)


class OwnedFixture:
    def __init__(self, port=18101):
        self.port = port
        self.server = None
        self.thread = None

    def start(self):
        if self.server is not None:
            raise RuntimeError('Owned fixture is already running')
        self.server = FixtureServer(self.port)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join()
            self.server = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()


@contextmanager
def running_fixture(port=18101):
    with OwnedFixture(port) as fixture:
        yield fixture.server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, choices=PORTS, default=18100)
    args = parser.parse_args()
    server = FixtureServer(args.port)
    print(f'Owned fixture listening on http://{HOST}:{args.port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
