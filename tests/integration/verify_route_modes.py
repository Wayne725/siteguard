"""Finite loopback checks for the dedicated route-body enforce/observe profiles."""
import argparse
import http.client
import json
from pathlib import Path


def check(mode):
    cases = [('GET', '/echo', 0, 200), ('HEAD', '/echo', 0, 200),
             ('POST', '/echo', 512, 200), ('POST', '/echo', 513, 413),
             ('POST', '/', 1024, 200), ('POST', '/', 1025, 413),
             ('POST', '/events', 2048, 200)]
    results = []
    for method, path, size, expected in cases:
        connection = http.client.HTTPConnection('127.0.0.1', 18088, timeout=3)
        try:
            connection.request(method, path, b'x' * size, {'Content-Type': 'text/plain'})
            response = connection.getresponse()
            body = response.read()
            target = 200 if mode == 'observe' else expected
            valid = response.status == target
            if response.status == 200 and method == 'POST' and path == '/echo':
                valid &= json.loads(body)['body'] == 'x' * size
            results.append({'method': method, 'path': path, 'bytes': size,
                            'expected_status': target, 'status': response.status,
                            'body': body.decode(), 'passed': valid})
        finally:
            connection.close()
    return {'mode': mode, 'passed': all(r['passed'] for r in results), 'requests': results,
            'prerequisites': 'Loopback gateway 18088; default 1024 bytes, /echo 512 bytes, /events streaming.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('enforce', 'observe'), required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = check(args.mode)
    args.output.write_text(json.dumps(result, indent=2))
    print({'mode': args.mode, 'passed': result['passed']})
    raise SystemExit(0 if result['passed'] else 1)
