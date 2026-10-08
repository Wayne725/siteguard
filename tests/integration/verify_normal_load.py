"""A small alternating direct/gateway baseline against an owned idle Python site."""
import argparse
import json
import math
import time
from pathlib import Path

from verify import OwnedFixture, request


def run():
    urls = {'direct': 'http://127.0.0.1:18100', 'gateway': 'http://127.0.0.1:18088'}
    rows = {name: [] for name in urls}
    with OwnedFixture(18100):
        for url in urls.values():
            assert request(url, 'GET', '/echo')['status'] == 200
        for name in ('direct', 'gateway', 'gateway', 'direct'):
            start = time.monotonic()
            for index in range(20):
                due = start + index * .05
                time.sleep(max(0, due - time.monotonic()))
                lag_ms = (time.monotonic() - due) * 1000
                result = request(urls[name], 'GET', '/echo')
                result['schedule_lag_ms'] = round(lag_ms, 3)
                rows[name].append(result)
    summary = {}
    for name, values in rows.items():
        latency = sorted(row['elapsed_ms'] for row in values)
        summary[name] = {'requests': len(values), 'successful': sum(row['status'] == 200 for row in values),
                         'p50_ms': latency[math.ceil(len(latency) * .5) - 1],
                         'p95_ms': latency[math.ceil(len(latency) * .95) - 1],
                         'max_schedule_lag_ms': max(row['schedule_lag_ms'] for row in values)}
    return {'passed': all(row['status'] == 200 and row['schedule_lag_ms'] < 100
                          for values in rows.values() for row in values),
            'summary': summary, 'requests': rows, 'requests_per_second': 20,
            'limitations': '40 observations per path on an idle local echo endpoint; no general latency SLO claim.'}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = run()
    args.output.write_text(json.dumps(result, indent=2))
    print(json.dumps(result['summary'], indent=2))
    raise SystemExit(0 if result['passed'] else 1)
