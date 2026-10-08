"""Evidence from matched server lifecycles, without inferring policy superiority."""
from __future__ import annotations

import math
from collections import Counter, defaultdict

from policy import percentile


def analyze_events(rows: list[dict], envelope: dict, state: dict,
                   initial_run_id: str | None = None) -> dict:
    events = envelope.get('events', [])
    issues = []
    request_ids = [row['request_id'] for row in rows]
    requests = {row['request_id']: row for row in rows}
    issued = {key for key, row in requests.items() if row['issued']}
    if len(request_ids) != len(requests):
        issues.append('Duplicate client request IDs.')
    run_id = envelope.get('run_id')
    if not run_id or run_id != state.get('run_id') or (initial_run_id and run_id != initial_run_id):
        issues.append('Server run changed or run identity is unavailable.')
    dropped = envelope.get('dropped_events')
    truncated = dropped > 0 if dropped is not None else len(events) >= envelope.get('capacity', 4096)
    if truncated:
        issues.append('Event buffer is truncated or may be truncated.')
    if envelope.get('total_events', len(events)) != len(events) + (dropped or 0):
        issues.append('Event count does not match the envelope counters.')
    grouped = defaultdict(list)
    invalid_events = 0
    for event in events:
        elapsed = event.get('elapsed_s')
        if (not isinstance(elapsed, (int, float)) or not math.isfinite(elapsed) or elapsed < 0
                or any(not isinstance(event.get(field), str) for field in ('request_id', 'kind', 'event'))):
            invalid_events += 1
            continue
        grouped[event.get('request_id')].append(event)
    if invalid_events:
        issues.append(f'{invalid_events} events have invalid timestamps or identity fields.')
    all_event_ids = {event.get('request_id') for event in events}
    unexpected = all_event_ids - issued
    if unexpected:
        issues.append('Origin events include IDs absent from issued requests.')
    missing_origin = issued - all_event_ids
    successful_missing = [key for key in missing_origin if requests[key].get('business_ok')]
    if successful_missing:
        issues.append('Successful client requests have no origin lifecycle.')
    intervals, queue_values, residual_values = [], defaultdict(list), defaultdict(list)
    incomplete = []
    accepted_count = starts_count = finishes_count = 0
    for request_id, lifecycle in grouped.items():
        if request_id not in issued:
            continue
        row = requests[request_id]
        kinds = {event.get('kind') for event in lifecycle}
        if kinds != {row['kind']}:
            incomplete.append(request_id)
            continue
        by_event = defaultdict(list)
        for event in lifecycle:
            by_event[event['event']].append(event)
        accepted, starts, finishes = (by_event[name] for name in
                                      ('accepted', 'db_work_started', 'db_work_finished'))
        exits, rejections = by_event['queue_exit'], by_event['admission_rejected']
        disconnects = by_event['http_disconnect_observed']
        accepted_count += len(accepted)
        starts_count += len(starts)
        finishes_count += len(finishes)
        if rejections and len(rejections) == 1 and not (accepted or starts or finishes or exits):
            continue
        if (len(accepted) != 1 or len(starts) > 1 or len(finishes) > 1 or len(exits) > 1
                or len(disconnects) > 1 or rejections):
            incomplete.append(request_id)
            continue
        accepted_at = accepted[0]['elapsed_s']
        if any(event['elapsed_s'] < accepted_at for event in lifecycle):
            incomplete.append(request_id)
            continue
        if not starts:
            if len(exits) != 1 or finishes:
                incomplete.append(request_id)
            continue
        if len(finishes) != 1 or exits:
            incomplete.append(request_id)
            continue
        start, end = starts[0]['elapsed_s'], finishes[0]['elapsed_s']
        if end < start:
            incomplete.append(request_id)
            continue
        intervals.append((start, end, row['kind'], request_id))
        queue_ms = starts[0].get('queue_ms', (start - accepted_at) * 1000)
        if not isinstance(queue_ms, (int, float)) or not math.isfinite(queue_ms) or queue_ms < 0:
            incomplete.append(request_id)
        else:
            queue_values[row['kind']].append(queue_ms)
        if disconnects:
            disconnected_at = disconnects[0]['elapsed_s']
            residual_values[row['kind']].append(max(0, end - max(start, disconnected_at)) * 1000)
    if incomplete:
        issues.append('Some origin request lifecycles are incomplete or inconsistent.')
    if any(value != 0 for field in ('outstanding', 'running', 'active_after_disconnect')
           for value in state.get(field, {}).values()):
        issues.append('Backend had not drained when events were collected.')

    boundaries = []
    for start, end, kind, request_id in intervals:
        if end > start:
            boundaries.extend(((start, 1, kind), (end, -1, kind)))
    counts, peaks = Counter(), Counter()
    peak = 0
    overlap_ms = full_ms = 0.0
    workers = state.get('db_workers')
    previous = 0.0
    for elapsed, change, kind in sorted(boundaries):
        span_ms = (elapsed - previous) * 1000
        if counts['orders'] and counts['report']:
            overlap_ms += span_ms
        if workers and sum(counts.values()) >= workers:
            full_ms += span_ms
        counts[kind] += change
        peaks[kind] = max(peaks[kind], counts[kind])
        peak = max(peak, sum(counts.values()))
        previous = elapsed
    overlaps = [(order[3], report[3]) for order in intervals if order[2] == 'orders'
                for report in intervals if report[2] == 'report'
                if min(order[1], report[1]) > max(order[0], report[0])]

    def queue_summary(values):
        return {'measured_requests': len(values), 'p95_ms': percentile(values, .95),
                'max_ms': max(values) if values else None, 'total_ms': round(sum(values), 3)}

    def residual_summary(values):
        return {'completed_requests': len(values), 'total_ms': round(sum(values), 3),
                'max_ms': round(max(values), 3) if values else None}

    return {
        'schema_version': 1, 'run_id': run_id,
        'status': 'incomplete' if issues else 'complete', 'validity_issues': issues,
        'coverage': {
            'planned_requests': len(rows), 'issued_requests': len(issued),
            'accepted_requests': accepted_count, 'db_started': starts_count, 'db_finished': finishes_count,
            'matched_event_request_ids': sorted(all_event_ids & issued),
            'unexpected_event_request_ids': sorted(unexpected, key=str),
            'missing_origin_request_ids': sorted(missing_origin),
            'missing_event_lifecycles': sorted(set(incomplete)),
            'truncated': truncated, 'event_count': len(events), 'dropped_events': dropped},
        'observations': {
            'order_report_overlap_ms': round(overlap_ms, 3),
            'orders_overlapping_reports': len({pair[0] for pair in overlaps}),
            'order_report_overlap_pairs': len(overlaps),
            'peak_running': peak, 'peak_running_by_kind': dict(peaks),
            'worker_capacity': workers,
            'worker_capacity_reached': peak >= workers if workers else None,
            'worker_capacity_reached_ms': round(full_ms, 3) if workers else None,
            'queue': queue_summary([value for values in queue_values.values() for value in values])
                     | {'by_kind': {kind: queue_summary(values) for kind, values in queue_values.items()}},
            'residual_after_disconnect': residual_summary(
                [value for values in residual_values.values() for value in values])
                | {'by_kind': {kind: residual_summary(values) for kind, values in residual_values.items()}}},
        'limitations': [
            'Overlap and occupied worker capacity alone do not establish saturation or service harm.',
            'Post-disconnect DB worker cleanup time alone is not a vulnerability or policy failure.',
            'Times describe the server-observed worker lifecycle, not database CPU consumption.',
            'Absent origin events for rejected or cancelled traffic may reflect upstream handling.',
            'Metrics use complete matched DB intervals; incomplete evidence must not support conclusions.']}
