"""Pedagogical controller; a baseline to replace, NOT a novel proven defense."""
from __future__ import annotations
import math
from dataclasses import dataclass


def percentile(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(q*len(ordered))-1)]


@dataclass
class Controller:
    limit: int = 2
    maximum: int = 3
    quiet_windows: int = 0

    def update(self, foreground_wait_p95_ms: float | None,
               foreground_timeouts: int, reports_rejected: int) -> str:
        # This signal is queue wait, NOT CPU consumption or attack probability.
        if foreground_timeouts or (foreground_wait_p95_ms is not None
                                   and foreground_wait_p95_ms > 50):
            before = self.limit
            self.limit = max(1, self.limit-1)
            self.quiet_windows = 0
            return 'reduce' if self.limit < before else 'at_minimum'
        # Require actual foreground samples. No samples is not proof of recovery.
        if (foreground_wait_p95_ms is not None
                and foreground_wait_p95_ms < 10 and reports_rejected > 0):
            self.quiet_windows += 1
            if self.quiet_windows >= 2:
                before = self.limit
                self.limit = min(self.maximum, self.limit+1)
                self.quiet_windows = 0
                return 'increase' if self.limit > before else 'at_maximum'
        else:
            self.quiet_windows = 0
        return 'hold'
