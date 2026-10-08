"""Single-event-loop token buckets; admission rates are not concurrency permits."""
from __future__ import annotations

import math
import os
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field


KINDS = ('products', 'orders', 'report')
MODES = ('bypass', 'fixed', 'feedback')
DOMAIN = 'local-ddos-lab'


@dataclass(frozen=True)
class Config:
    mode: str = 'bypass'
    rates: dict[str, float] = field(default_factory=lambda: {'products': 12.0, 'orders': 8.0, 'report': 2.0})
    bursts: dict[str, float] = field(default_factory=lambda: {'products': 12.0, 'orders': 8.0, 'report': 2.0})

    def __post_init__(self):
        if self.mode not in MODES:
            raise ValueError(f'mode must be one of {MODES}')
        for values, label, minimum, maximum in ((self.rates, 'rate', .5, 50),
                                                 (self.bursts, 'burst', 1, 100)):
            if set(values) != set(KINDS):
                raise ValueError(f'{label} must specify exactly {KINDS}')
            for kind, value in values.items():
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
                    raise ValueError(f'{kind} {label} must be a finite number')
                if not minimum <= value <= maximum:
                    raise ValueError(f'{kind} {label} must be in [{minimum}, {maximum}]')

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> 'Config':
        env = os.environ if environ is None else environ
        defaults = cls()
        rates = {kind: float(env.get(f'RLS_{kind.upper()}_RATE', defaults.rates[kind])) for kind in KINDS}
        bursts = {kind: float(env.get(f'RLS_{kind.upper()}_BURST', max(1, rates[kind]))) for kind in KINDS}
        return cls(mode=env.get('RLS_MODE', 'bypass'), rates=rates, bursts=bursts)


@dataclass
class Bucket:
    rate: float
    capacity: float
    tokens: float
    updated: float

    def refill(self, now: float) -> None:
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        self.updated = max(self.updated, now)

    def change_rate(self, rate: float, now: float) -> None:
        self.refill(now)
        self.rate = rate


@dataclass(frozen=True)
class Snapshot:
    run_id: str
    running: int
    outstanding: int
    active_after_disconnect: int
    workers: int
    received: int

    @classmethod
    def parse(cls, value: Mapping) -> 'Snapshot':
        if not isinstance(value, Mapping):
            raise ValueError('snapshot must be an object')
        run_id = value.get('run_id')
        if not isinstance(run_id, str) or not 1 <= len(run_id) <= 128:
            raise ValueError('snapshot requires run_id')
        workers = value.get('db_workers')
        if type(workers) is not int or not 1 <= workers <= 64:
            raise ValueError('snapshot requires bounded positive db_workers')

        def count_map(name: str) -> int:
            counts = value.get(name)
            if not isinstance(counts, Mapping):
                raise ValueError(f'snapshot requires {name}')
            if any(type(count) is not int or count < 0 for count in counts.values()):
                raise ValueError(f'{name} must contain non-negative integer counts')
            return sum(counts.values())

        totals = value.get('totals')
        if not isinstance(totals, Mapping):
            raise ValueError('snapshot requires totals')
        received = [totals.get(f'{kind}_received', 0) for kind in KINDS]
        if any(type(count) is not int or count < 0 for count in received):
            raise ValueError('received totals must be non-negative integers')
        running = count_map('running')
        outstanding = count_map('outstanding')
        active = count_map('active_after_disconnect')
        if not 0 <= active <= running <= workers or running > outstanding:
            raise ValueError('snapshot work counts are inconsistent')
        return cls(run_id, running, outstanding, active, workers, sum(received))


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    limited_kinds: tuple[str, ...] = ()


class AdmissionPolicy:
    def __init__(self, config: Config, clock: Callable[[], float] = time.monotonic,
                 on_change: Callable[[dict], None] | None = None):
        self.config = config
        self.clock = clock
        self.on_change = on_change or (lambda event: None)
        self.snapshot: Snapshot | None = None
        self.snapshot_at: float | None = None
        self.last_received = 0
        self.healthy_windows = 0
        self.feedback_state = 'fixed_no_snapshot'
        self.next_control = clock() + 1
        self.buckets: dict[str, Bucket] = {}
        self._reset_buckets(clock())

    def _reset_buckets(self, now: float) -> None:
        self.buckets = {kind: Bucket(self.config.rates[kind], self.config.bursts[kind],
                                     self.config.bursts[kind], now) for kind in KINDS}

    @property
    def report_rate(self) -> float:
        return self.buckets['report'].rate

    def observe(self, value: Mapping) -> None:
        snapshot = Snapshot.parse(value)
        now = self.clock()
        if self.snapshot is None or snapshot.run_id != self.snapshot.run_id:
            self._reset_buckets(now)
            self.healthy_windows = 0
            self.last_received = snapshot.received
            self.next_control = now + 1
            self.feedback_state = 'observing'
            self.on_change({'event': 'run_reset', 'run_id': snapshot.run_id,
                            'mode': self.config.mode, 'report_rate': self.report_rate})
        self.snapshot = snapshot
        self.snapshot_at = now

    def advance(self) -> None:
        now = self.clock()
        if now < self.next_control:
            return
        self.next_control = now + 1
        if self.config.mode != 'feedback':
            return
        previous_rate = self.report_rate
        previous_state = self.feedback_state
        fresh = self.snapshot_at is not None and now - self.snapshot_at <= 2
        if not fresh:
            self.buckets['report'].change_rate(self.config.rates['report'], now)
            self.healthy_windows = 0
            self.feedback_state = 'fixed_stale' if self.snapshot is not None else 'fixed_no_snapshot'
        else:
            snapshot = self.snapshot
            busy = snapshot.running / snapshot.workers
            queued = max(0, snapshot.outstanding - snapshot.running)
            received_delta = max(0, snapshot.received - self.last_received)
            self.last_received = snapshot.received
            pressure = busy >= .75 and (queued > 0 or snapshot.active_after_disconnect > 0)
            if pressure:
                self.buckets['report'].change_rate(max(.5, self.report_rate / 2), now)
                self.healthy_windows = 0
                self.feedback_state = 'pressure'
            elif busy < .5 and queued == 0 and received_delta > 0:
                self.healthy_windows += 1
                self.feedback_state = 'recovering'
                if self.healthy_windows >= 3:
                    self.buckets['report'].change_rate(min(self.config.rates['report'], self.report_rate + .25), now)
                    self.healthy_windows = 0
            else:
                self.healthy_windows = 0
                self.feedback_state = 'holding'
        if previous_rate != self.report_rate or previous_state != self.feedback_state:
            self.on_change({'event': 'control_update', 'mode': self.config.mode,
                            'run_id': self.snapshot.run_id if self.snapshot else None,
                            'state': self.feedback_state, 'previous_report_rate': previous_rate,
                            'report_rate': self.report_rate})

    def decide(self, kinds: Sequence[str], hits: int = 1) -> Decision:
        if (not kinds or len(kinds) > 32 or any(kind not in KINDS for kind in kinds)
                or type(hits) is not int or not 1 <= hits <= 100):
            return Decision(False, 'invalid_request')
        self.advance()
        if self.config.mode == 'bypass':
            return Decision(True, 'bypass')
        now = self.clock()
        costs = Counter(kinds)
        for kind in costs:
            self.buckets[kind].refill(now)
        limited = tuple(kind for kind, count in costs.items() if self.buckets[kind].tokens + 1e-9 < count * hits)
        if limited:
            return Decision(False, 'rate_limited', limited)
        for kind, count in costs.items():
            self.buckets[kind].tokens -= count * hits
        return Decision(True, 'admitted')

    def metadata(self, reason: str) -> dict:
        return {'mode': self.config.mode, 'report_rate': self.report_rate,
                'decision': reason, 'feedback_state': self.feedback_state,
                'run_id': self.snapshot.run_id if self.snapshot else ''}
