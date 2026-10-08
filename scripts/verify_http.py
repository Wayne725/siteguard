"""Small destructive-to-lab-only acceptance check; never accepts remote URLs."""
import argparse
import json
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'local_ddos_lab'))
from experiment import ALLOWED_BASE_URLS, LAB_ID


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-url', choices=ALLOWED_BASE_URLS, default='http://127.0.0.1:8000')
    args = parser.parse_args()
    token = (ROOT / 'local_ddos_lab/runtime/admin.token').read_text().strip()
    headers = {'x-lab-admin': token}
    checks = []

    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        checks.append(name)

    with httpx.Client(timeout=5, trust_env=False, follow_redirects=False) as client:
        base = args.base_url
        origin = 'http://127.0.0.1:8000'
        health = client.get(f'{base}/health')
        check('lab ready and identity', health.status_code == 200
              and health.json()['lab_id'] == LAB_ID and health.json()['ready'])
        check('liveness', client.get(f'{base}/live').json()['alive'])
        check('admin requires token', client.get(f'{origin}/lab/state').status_code == 403)
        reset = client.post(f'{origin}/lab/reset', headers=headers, json={'mode': 'off'})
        check('idle reset', reset.status_code == 200)
        check('homepage', client.get(base).status_code == 200)
        check('UI script', client.get(f'{base}/ui.js').status_code == 200)
        health = client.get(f'{base}/health')
        run_id = reset.json()['run_id']
        check('readiness exposes current app mode and run', health.json()['app_mode'] == 'off'
              and health.json()['run_id'] == run_id)
        products = client.get(f'{base}/api/products').json()
        check('20 real products', products['ok'] and len(products['products']) == 20)
        payload = {'request_id': 'http-acceptance', 'product_id': 2}
        guarded_payload = {**payload, 'expected_run_id': run_id}
        first = client.post(f'{base}/api/orders', json=guarded_payload)
        second = client.post(f'{base}/api/orders', json=guarded_payload)
        check('idempotent acknowledged order', first.status_code == second.status_code == 200
              and first.json()['persisted'] and second.json()['persisted'])
        mismatch = client.post(f'{base}/api/orders', json={**payload, 'product_id': 3})
        check('key conflict rejected', mismatch.status_code == 503 and not mismatch.json()['ok'])
        report = client.get(f'{base}/api/report')
        check('real report', report.status_code == 200 and report.json()['checksum'] == 800_800_000)
        audit = client.get(f'{origin}/lab/audit', headers=headers).json()
        check('exact committed order', audit['committed_orders'] == [payload])
        check('exact stock decrement', audit['stock_used'] == 1
              and audit['products'][1]['stock'] == 99999
              and all(p['stock'] == 100000 for p in audit['products'] if p['id'] != 2))
        if base.endswith(':8080'):
            check('gateway identifies its own mode', health.headers.get('X-Lab-Gateway-Mode')
                  in ('off', 'adaptive', 'rls', 'rls_adaptive'))
            check('gateway blocks management', client.get(f'{base}/lab/state', headers=headers).status_code == 404)
            check('gateway bounds body', client.post(f'{base}/api/orders', content=b'x' * 20000).status_code == 413)
        check('final clean reset', client.post(f'{origin}/lab/reset', headers=headers,
                                              json={'mode': 'off'}).status_code == 200)
        stale = client.post(f'{base}/api/orders', json=guarded_payload)
        check('old-run retry does not create a new order', stale.status_code == 409
              and stale.json()['reason'] == 'run_changed'
              and client.get(f'{origin}/lab/audit', headers=headers).json()['stock_used'] == 0)
    print(json.dumps({'base_url': args.base_url, 'passed': len(checks), 'checks': checks},
                     ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
