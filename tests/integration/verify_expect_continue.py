"""A local client that waits for 100 Continue before sending its request body."""
import argparse
import http.client
import json
import socket
import time
from pathlib import Path


def verify():
    started = time.monotonic()
    result = {'passed': False, 'interim_response': '', 'status': 0, 'error': None}
    payload = b'continue-before-upload'
    try:
        with socket.create_connection(('127.0.0.1', 18088), timeout=2) as connection:
            headers = (f'POST /echo HTTP/1.1\r\nHost: localhost\r\nExpect: 100-continue\r\n'
                       f'Content-Length: {len(payload)}\r\nContent-Type: text/plain\r\n\r\n')
            connection.sendall(headers.encode())
            interim = bytearray()
            while not interim.endswith(b'\r\n\r\n') and len(interim) < 8192:
                byte = connection.recv(1)
                if not byte:
                    break
                interim.extend(byte)
            result['interim_response'] = interim.decode('latin1')
            if not interim.startswith(b'HTTP/1.1 100 '):
                return result
            connection.sendall(payload)
            response = http.client.HTTPResponse(connection)
            response.begin()
            body = response.read()
            result.update(status=response.status, response=body.decode())
            result['passed'] = response.status == 200 and json.loads(body)['body'].encode() == payload
    except (OSError, ValueError, http.client.HTTPException) as exc:
        result['error'] = str(exc)
    finally:
        result['elapsed_ms'] = round((time.monotonic() - started) * 1000, 3)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = verify()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)
