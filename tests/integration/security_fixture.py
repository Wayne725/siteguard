"""Independent, bounded loopback origin containing deliberately fake secrets only."""
from __future__ import annotations

import argparse
import gzip
import json
import signal
import socket
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

HOST = '127.0.0.1'
PORT = 18102
FIXTURE_ID = 'siteguard-incident-fixture-v1'
MARKER = 'fixture-origin-reached'
FAKE_TOKEN = 'ghp_' + 'FAKEONLY0123456789abcdefghijklmnopqr'
FAKE_PRIVATE_KEY = ('-----BEGIN PRIVATE KEY-----\n'
                    'Tk9UX0FfUkVBTF9LRVlfRklYVFVSRV9PTkxZ\n'
                    '-----END PRIVATE KEY-----')
assert len(FAKE_TOKEN) == 40
MAX_CALLS = 256
MAX_REQUEST_BODY = 4096
CLEAN_HEADERS = {'x-api.version': 'fixture-v1', 'x!proof': 'legal-header-retained'}


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()


class FixtureState:
    def __init__(self):
        self.lock = threading.Lock()
        self.calls = deque(maxlen=MAX_CALLS)
        self.total_calls = 0

    def record(self, method, path):
        with self.lock:
            self.total_calls += 1
            self.calls.append({'method': method, 'path': path[:512]})

    def reset(self):
        with self.lock:
            self.calls.clear()
            self.total_calls = 0

    def snapshot(self):
        with self.lock:
            return {'fixture': FIXTURE_ID, 'total_calls': self.total_calls,
                    'dropped_calls': self.total_calls - len(self.calls), 'calls': list(self.calls)}


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def setup(self):
        super().setup()
        self.connection.settimeout(3)

    def log_message(self, *_):
        pass

    def reply(self, body, content_type='application/json', headers=None, status=200):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Fixture-Marker', MARKER)
        self.send_header('Referrer-Policy', 'no-referrer')
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(body)

    def chunked(self, parts, content_type='application/json', delay=.015, trailers=None):
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Transfer-Encoding', 'chunked')
        self.send_header('X-Fixture-Marker', MARKER)
        self.send_header('Referrer-Policy', 'no-referrer')
        if trailers:
            self.send_header('Trailer', ', '.join(trailers))
        self.end_headers()
        if self.command == 'HEAD':
            return
        for part in parts:
            self.wfile.write(f'{len(part):x}\r\n'.encode() + part + b'\r\n')
            self.wfile.flush()
            time.sleep(delay)
        trailer_bytes = ''.join(f'{key}: {value}\r\n' for key, value in (trailers or {}).items()).encode('ascii')
        self.wfile.write(b'0\r\n' + trailer_bytes + b'\r\n')

    def handle_request(self):
        if 'close' in {token.strip().lower() for token in self.headers.get('Connection', '').split(',')}:
            self.close_connection = True
        if self.headers.get('Transfer-Encoding'):
            self.close_connection = True
            self.reply(b'Fixture accepts bounded Content-Length requests only', 'text/plain', status=400)
            return
        try:
            length = int(self.headers.get('Content-Length', '0'))
        except ValueError:
            self.close_connection = True
            self.reply(b'Invalid Content-Length', 'text/plain', status=400)
            return
        if not 0 <= length <= MAX_REQUEST_BODY:
            self.close_connection = True
            self.reply(b'Fixture request body limit', 'text/plain', status=413)
            return
        if len(self.rfile.read(length)) != length:
            self.close_connection = True
            return
        path = urlsplit(self.path).path
        state = self.server.fixture_state
        if path == '/fixture/state':
            self.reply(json_bytes(state.snapshot()))
            return
        if path in ('/fixture/reset', '/fixture/state/reset') and self.command == 'POST':
            state.reset()
            self.reply(json_bytes(state.snapshot()))
            return
        state.record(self.command, path)
        path = '/'.join(segment.split(';', 1)[0] for segment in unquote(path).split('/')).casefold()
        clean = json_bytes({'ok': True, 'marker': MARKER})
        secret = json_bytes({'fake_fixture_token': FAKE_TOKEN})
        if path == '/client-info':
            self.reply(json_bytes({'ok': True, 'marker': MARKER,
                                   'forwarded_for': self.headers.get('X-Forwarded-For')}))
        elif path == '/api/clean':
            self.reply(clean, headers=CLEAN_HEADERS)
        elif path == '/api/private-key':
            self.reply(json_bytes({'fake_fixture_private_key': FAKE_PRIVATE_KEY}))
        elif path == '/api/token':
            self.reply(secret)
        elif path == '/api/split-secret':
            self.chunked([b'{"fake_fixture_token":"g', b'hp_', FAKE_TOKEN[4:22].encode(),
                          FAKE_TOKEN[22:].encode(), b'"}'])
        elif path == '/api/oversize':
            self.reply(json_bytes({'padding': 'x' * (64 * 1024), 'fake_fixture_token': FAKE_TOKEN}))
        elif path == '/api/chunked-oversize':
            self.chunked([b'{"padding":"', *([b'x' * 8192] * 8),
                          b'","fake_fixture_token":"' + FAKE_TOKEN.encode() + b'"}'])
        elif path == '/api/partial206':
            self.reply(secret, status=206,
                       headers={'Content-Range': f'bytes 0-{len(secret) - 1}/{len(secret) * 2}'})
        elif path == '/api/trailers':
            self.chunked([clean], trailers={'X-Test-Secret': FAKE_TOKEN})
        elif path == '/api/gzip':
            self.reply(gzip.compress(secret, mtime=0), headers={'Content-Encoding': 'gzip'})
        elif path == '/api/binary':
            self.reply(b'\x00FAKE-FIXTURE-ONLY\x00' + FAKE_TOKEN.encode(), 'application/octet-stream')
        elif path == '/api/cookie-private':
            self.reply(clean, headers={'Set-Cookie': f'fake_fixture_session={FAKE_TOKEN}; HttpOnly; Path=/'})
        elif path == '/events':
            self.chunked([b'data: {"marker":"first"}\n\n', b'data: {"marker":"last"}\n\n'],
                         'text/event-stream', delay=.1)
        elif path == '/ws':
            self.reply(b'WebSocket intentionally unsupported by this security fixture', 'text/plain', status=400)
        else:
            self.reply(clean)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = do_TRACE = handle_request


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = False
    allow_reuse_address = True
    request_queue_size = 8

    def __init__(self):
        self.fixture_state = FixtureState()
        self.socket_lock = threading.Lock()
        self.accepted_sockets = set()
        super().__init__((HOST, PORT), FixtureHandler)

    def get_request(self):
        connection, address = super().get_request()
        with self.socket_lock:
            self.accepted_sockets.add(connection)
        return connection, address

    def close_request(self, request):
        with self.socket_lock:
            self.accepted_sockets.discard(request)
        super().close_request(request)

    def server_close(self):
        self.socket.close()
        with self.socket_lock:
            connections = list(self.accepted_sockets)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        super().server_close()


class OwnedFixture:
    def __init__(self):
        self.server = None
        self.thread = None

    def start(self):
        if self.server is not None:
            raise RuntimeError('Security fixture is already running')
        self.server = FixtureServer()
        self.thread = threading.Thread(target=self.server.serve_forever, name='security-fixture')
        self.thread.start()
        return self

    def stop(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join()
            self.server = None

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    with OwnedFixture():
        print(f'Security fixture listening on http://{HOST}:{PORT}; all secrets are fake.', flush=True)
        stopped.wait()


if __name__ == '__main__':
    main()
