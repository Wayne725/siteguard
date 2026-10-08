"""Replayable arrival changes within fixed half-second workload windows."""
from __future__ import annotations

import math
import random
from collections import defaultdict

ARRIVALS = ('periodic', 'jittered', 'burst')
ARRIVAL_WINDOW_S = .5


def retime_schedule(rows: list[dict], seconds: int, seed: int | str,
                    arrival: str, phased: bool = True) -> list[dict]:
    """Keep every request in its original half-second window and workload phase.

    Bursts group only the requests already planned in that window; they cannot
    increase its count or trigger catch-up traffic. Runtime inflight caps still
    apply, with dropped requests retained in the completion denominator.
    """
    if arrival not in ARRIVALS:
        raise ValueError(f'Unknown arrival pattern: {arrival}')
    if arrival == 'periodic':
        return [dict(row) for row in rows]
    windows = defaultdict(list)
    phase_bounds = {'warmup': (0, seconds * .2), 'load': (seconds * .2, seconds * .8),
                    'recovery': (seconds * .8, seconds)}
    for row in rows:
        window = math.floor(row['offset_s'] / ARRIVAL_WINDOW_S)
        lower, upper = phase_bounds[row['phase']] if phased else (0, seconds)
        lower = max(lower, window * ARRIVAL_WINDOW_S)
        upper = min(upper, (window + 1) * ARRIVAL_WINDOW_S)
        windows[(lower, upper)].append(dict(row))
    rng = random.Random(f'{seed}:arrival:{arrival}')
    result = []
    for (lower, upper), items in sorted(windows.items()):
        width = upper - lower
        if arrival == 'jittered':
            for row in items:
                row['offset_s'] = round(lower + width * rng.uniform(.04, .96), 6)
        else:
            first = lower + width * rng.uniform(.04, .16)
            # At most six requests in a standard-run window, two in a probe
            # window; spacing keeps a burst bounded and the ordering stable.
            for index, row in enumerate(items):
                row['offset_s'] = round(first + width * .02 * index, 6)
        result.extend(items)
    return sorted(result, key=lambda row: row['offset_s'])
