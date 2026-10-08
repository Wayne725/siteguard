"""Real loopback TLS/ALPN fixture; preparation never starts Docker."""
from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import secrets
import signal
import ssl
import subprocess
import sys
import tempfile
import time


HOST = '127.0.0.1'
ORIGIN_PORT = 18543
GATEWAY_PORT = 18443
ORIGIN_HOST = 'host.lima.internal'
CASES = ('good-http1', 'good-http2', 'good-auto', 'wrong-ca', 'wrong-san')


def openssl(*arguments: str) -> None:
    subprocess.run(['openssl', *arguments], check=True, capture_output=True, text=True, timeout=30)


def make_ca(directory: Path, name: str) -> None:
    configuration = directory / f'{name}.cnf'
    configuration.write_text(
        '[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ca\n'
        f'[dn]\nCN=Siteguard temporary {name}\n'
        '[ca]\nbasicConstraints=critical,CA:TRUE\n'
        'keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n')
    openssl('req', '-new', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256',
            '-days', '2', '-config', str(configuration), '-keyout', str(directory / f'{name}.key'),
            '-out', str(directory / f'{name}.pem'))
    (directory / f'{name}.key').chmod(0o600)


def make_leaf(directory: Path, name: str, san: str) -> None:
    key, csr, certificate = [directory / f'{name}.{extension}' for extension in ('key', 'csr', 'pem')]
    extensions = directory / f'{name}.ext'
    extensions.write_text(
        'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
        f'extendedKeyUsage=serverAuth\nsubjectAltName={san}\n')
    openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-sha256',
            '-subj', '/CN=Siteguard test endpoint', '-keyout', str(key), '-out', str(csr))
    openssl('x509', '-req', '-in', str(csr), '-CA', str(directory / 'ca.pem'),
            '-CAkey', str(directory / 'ca.key'), '-set_serial', str(secrets.randbits(128) or 1),
            '-days', '2', '-sha256', '-extfile', str(extensions), '-out', str(certificate))
    key.chmod(0o600)


def prepare(output: Path | None = None) -> dict:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    import yaml
    from siteguard.config import example_config, validate_config

    directory = (output or Path(tempfile.mkdtemp(prefix='siteguard-tls-'))).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    if any(directory.iterdir()):
        raise ValueError('Use a new, empty artifact directory; existing certificates are never replaced.')
    certificates = directory / 'certificates'
    certificates.mkdir()
    make_ca(certificates, 'ca')
    make_ca(certificates, 'wrong-ca')
    san = 'DNS:localhost,DNS:host.lima.internal,DNS:host.docker.internal,IP:127.0.0.1'
    make_leaf(certificates, 'origin', san)
    make_leaf(certificates, 'gateway', san)
    make_leaf(certificates, 'wrong-san', 'DNS:wrong.invalid')
    configs = directory / 'configs'
    configs.mkdir()
    variants = {}
    for case in CASES:
        config = example_config(f'https://{ORIGIN_HOST}:{ORIGIN_PORT}')
        config.update(name='siteguard-tls', mode='enforce')
        config['listener'].update(port=GATEWAY_PORT, tls={
            'certificate': str(certificates / 'gateway.pem'),
            'private_key': str(certificates / 'gateway.key')})
        protocol = {'good-http1': 'http1', 'good-http2': 'http2', 'good-auto': 'auto'}.get(case, 'http2')
        config['upstream'].update(protocol=protocol, tls_ca_file=str(
            certificates / ('wrong-ca.pem' if case == 'wrong-ca' else 'ca.pem')))
        config['policy']['request_timeout_seconds'] = 5
        path = configs / f'{case}.yaml'
        path.write_text(yaml.safe_dump(validate_config(config), sort_keys=False))
        variants[case] = {'config': str(path),
                          'origin_certificate': 'wrong-san' if case == 'wrong-san' else 'good',
                          'expected_status': 503 if case.startswith('wrong-') else 200,
                          'expected_origin_protocol': 'HTTP/1.1' if protocol == 'http1' else 'HTTP/2'}
    manifest = {'version': 1, 'project': 'siteguard-tls', 'artifacts': str(directory),
                'origin_bind': f'{HOST}:{ORIGIN_PORT}', 'origin_host': ORIGIN_HOST,
                'gateway_url': f'https://localhost:{GATEWAY_PORT}',
                'ca_file': str(certificates / 'ca.pem'),
                'origin_events': str(directory / 'origin-events.jsonl'), 'variants': variants,
                'sequence': list(CASES), 'instructions': [
                    'Start tls_fixture.py serve --artifacts DIR --certificate good.',
                    'For each of the first four cases, deploy that config with project siteguard-tls, then run verify_tls.py.',
                    'Before wrong-san, stop the fixture and restart it with --certificate wrong-san; this closes old TLS sessions.',
                    'Deploy wrong-san.yaml and verify. Stop only the owned fixture and siteguard-tls project afterwards.',
                    'Certificates are temporary test material, valid for two days; never install this CA in a system trust store.',
                ]}
    (directory / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (directory / 'origin-events.jsonl').touch()
    return manifest


def server_context(directory: Path, certificate: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    leaf = 'origin' if certificate == 'good' else 'wrong-san'
    context.load_cert_chain(directory / 'certificates' / f'{leaf}.pem',
                            directory / 'certificates' / f'{leaf}.key')
    context.set_alpn_protocols(['h2', 'http/1.1'])

    def record_sni(connection, server_name, initial_context):
        connection.fixture_sni = server_name

    context.sni_callback = record_sni
    return context


class TLSFixture:
    def __init__(self, directory: Path, certificate: str):
        self.directory = directory
        self.certificate = certificate
        self.writers = set()

    def response(self, ssl_object, protocol: str, headers: dict) -> bytes:
        record = {'fixture': 'siteguard-tls-v1', 'certificate': self.certificate,
                  'http_version': protocol, 'alpn': ssl_object.selected_alpn_protocol(),
                  'sni': getattr(ssl_object, 'fixture_sni', None),
                  'probe_id': headers.get('x-siteguard-probe', ''), 'time': time.time()}
        with (self.directory / 'origin-events.jsonl').open('a') as stream:
            stream.write(json.dumps(record, separators=(',', ':')) + '\n')
        return json.dumps(record).encode()

    async def http1(self, reader, writer, ssl_object):
        raw = await asyncio.wait_for(reader.readuntil(b'\r\n\r\n'), 5)
        lines = raw.decode('iso-8859-1').split('\r\n')
        headers = dict(line.lower().split(':', 1) for line in lines[1:] if ':' in line)
        headers = {key: value.strip() for key, value in headers.items()}
        if lines[0] != 'GET /tls HTTP/1.1':
            raise ValueError('Fixture only accepts GET /tls')
        body = self.response(ssl_object, 'HTTP/1.1', headers)
        writer.write(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n'
                     + f'Content-Length: {len(body)}\r\n\r\n'.encode() + body)
        await writer.drain()

    async def http2(self, reader, writer, ssl_object):
        from h2.config import H2Configuration
        from h2.connection import H2Connection
        from h2.events import ConnectionTerminated, DataReceived, RequestReceived, StreamEnded, StreamReset

        connection = H2Connection(config=H2Configuration(client_side=False, header_encoding='utf-8'))
        connection.initiate_connection()
        writer.write(connection.data_to_send())
        await writer.drain()
        streams = {}
        while data := await asyncio.wait_for(reader.read(16384), 10):
            for event in connection.receive_data(data):
                if isinstance(event, RequestReceived):
                    if len(streams) >= 16:
                        connection.reset_stream(event.stream_id)
                    else:
                        streams[event.stream_id] = dict(event.headers)
                elif isinstance(event, DataReceived):
                    connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, StreamReset):
                    streams.pop(event.stream_id, None)
                elif isinstance(event, StreamEnded) and event.stream_id in streams:
                    headers = streams.pop(event.stream_id)
                    if headers.get(':method') != 'GET' or headers.get(':path') != '/tls':
                        connection.send_headers(event.stream_id, [(':status', '404')], end_stream=True)
                        continue
                    body = self.response(ssl_object, 'HTTP/2', headers)
                    connection.send_headers(event.stream_id, [(':status', '200'),
                                            ('content-type', 'application/json'), ('content-length', str(len(body)))])
                    connection.send_data(event.stream_id, body, end_stream=True)
                elif isinstance(event, ConnectionTerminated):
                    return
            writer.write(connection.data_to_send())
            await writer.drain()

    async def handle(self, reader, writer):
        self.writers.add(writer)
        try:
            ssl_object = writer.get_extra_info('ssl_object')
            if ssl_object.selected_alpn_protocol() == 'h2':
                await self.http2(reader, writer, ssl_object)
            else:
                await self.http1(reader, writer, ssl_object)
        except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            self.writers.discard(writer)
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass

    async def start(self):
        return await asyncio.start_server(self.handle, HOST, ORIGIN_PORT,
                                          ssl=server_context(self.directory, self.certificate),
                                          ssl_handshake_timeout=5, ssl_shutdown_timeout=2, limit=16384)

    async def close_connections(self):
        for writer in tuple(self.writers):
            writer.close()
        await asyncio.gather(*(writer.wait_closed() for writer in tuple(self.writers)), return_exceptions=True)


async def serve(directory: Path, certificate: str) -> None:
    fixture = TLSFixture(directory, certificate)
    server = await fixture.start()
    stopped = asyncio.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        asyncio.get_running_loop().add_signal_handler(signum, stopped.set)
    print(json.dumps({'event': 'tls_fixture_ready', 'bind': f'{HOST}:{ORIGIN_PORT}',
                      'certificate': certificate, 'alpn': ['h2', 'http/1.1']}), flush=True)
    async with server:
        await stopped.wait()
    await fixture.close_connections()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    preparation = commands.add_parser('prepare')
    preparation.add_argument('--output', type=Path)
    listener = commands.add_parser('serve')
    listener.add_argument('--artifacts', type=Path, required=True)
    listener.add_argument('--certificate', choices=('good', 'wrong-san'), default='good')
    args = parser.parse_args()
    if args.command == 'prepare':
        print(json.dumps(prepare(args.output), indent=2))
    else:
        asyncio.run(serve(args.artifacts.resolve(), args.certificate))


if __name__ == '__main__':
    main()
