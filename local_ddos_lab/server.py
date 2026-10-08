"""Local-only lab server. Run ONE worker. No public deployment supported."""
from __future__ import annotations

import asyncio
import contextlib
import importlib.metadata
import os
import secrets
import sqlite3
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel, Field

import database
from cancellation import Cancellation, WorkCancelled
from policy import Controller, percentile

ROOT = Path(__file__).resolve().parent
RUNTIME = Path(os.environ.get('APP_RUNTIME_DIR', str(ROOT / 'runtime')))
DB = os.environ.get('APP_DATABASE_URL') or RUNTIME / 'lab.sqlite3'
if os.environ.get('APP_DATABASE_URL'):
    import postgres_database as database
LAB_ID = 'local-resource-defense-lab-v1'
WORKERS = 4
MAX_OUTSTANDING = 24
QUEUE_TIMEOUT = 1.5
HEALTH_CACHE_SECONDS = 5
HEALTH_TIMEOUT_SECONDS = .5
EventRequestId = Annotated[str | None, Header(min_length=16, max_length=64,
                                             pattern=r'^[A-Za-z0-9_-]+$')]


class State:
    def __init__(self) -> None:
        self.mode = 'off'
        self.run_id = secrets.token_hex(8)
        self.fixed_limit = 2
        self.report_rounds = 40
        self.controller = Controller()
        self.outstanding: Counter = Counter()
        self.running: Counter = Counter()
        self.totals: Counter = Counter()
        self.fg_waits: list[float] = []
        self.fg_timeouts = 0
        self.report_rejections = 0
        self.last_control: dict = {}
        self.epoch = time.monotonic()
        self.next_control = self.epoch + 2
        self.admin_busy = False
        self.active_after_disconnect: Counter = Counter()
        self.events = deque(maxlen=4096)
        self.total_events = 0
        self.cancel_tasks: set[asyncio.Task] = set()

    def event(self, kind, request_id, event, **values):
        self.total_events += 1
        self.events.append({'elapsed_s': round(time.monotonic()-self.epoch, 6),
                            'kind': kind, 'request_id': request_id,
                            'event': event, **values})

    def report_limit(self) -> int | None:
        if self.mode == 'off':
            return None
        return self.fixed_limit if self.mode == 'fixed' else self.controller.limit

    def snapshot(self) -> dict:
        return {'mode': self.mode, 'run_id': self.run_id, 'backend': database.BACKEND,
                'elapsed_s': round(time.monotonic()-self.epoch, 3),
                'report_limit': self.report_limit(), 'report_rounds': self.report_rounds,
                'db_workers': WORKERS, 'outstanding': dict(self.outstanding),
                'running': dict(self.running), 'totals': dict(self.totals),
                'active_after_disconnect': dict(self.active_after_disconnect),
                'last_control': self.last_control}


state = State()
token = ''
executor: ThreadPoolExecutor
slots: asyncio.Semaphore


class Readiness:
    """One bounded, shared probe; HTTP timeouts cannot queue more DB work."""

    def __init__(self, pool):
        self.pool = pool
        self.in_flight = None
        self.checked_at = None
        self.ready = False

    def completed(self, future):
        try:
            self.ready = bool(future.result())
        except database.ERRORS:
            self.ready = False
        self.checked_at = time.monotonic()

    async def check(self):
        if (self.checked_at is None or
                time.monotonic() - self.checked_at >= HEALTH_CACHE_SECONDS):
            if self.in_flight is None or self.in_flight.done():
                self.in_flight = asyncio.get_running_loop().run_in_executor(
                    self.pool, database.readiness, DB)
                self.in_flight.add_done_callback(self.completed)
            try:
                await asyncio.wait_for(asyncio.shield(self.in_flight), HEALTH_TIMEOUT_SECONDS)
            except (asyncio.TimeoutError, *database.ERRORS):
                self.ready = False
                self.checked_at = time.monotonic()
        return self.ready


readiness: Readiness


async def control_loop() -> None:
    while True:
        await asyncio.sleep(.1)
        if time.monotonic() < state.next_control:
            continue
        state.next_control = time.monotonic() + 2
        waits, timeouts, rejected = state.fg_waits, state.fg_timeouts, state.report_rejections
        state.fg_waits, state.fg_timeouts, state.report_rejections = [], 0, 0
        p95 = percentile(waits, 0.95)
        action = (state.controller.update(p95, timeouts, rejected)
                  if state.mode == 'adaptive' else 'disabled')
        state.last_control = {'action': action, 'foreground_queue_p95_ms': p95,
                              'foreground_samples': len(waits), 'queue_timeouts': timeouts,
                              'report_rejections': rejected}


@asynccontextmanager
async def lifespan(app: FastAPI):
    global executor, slots, token, readiness
    RUNTIME.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    (RUNTIME / 'admin.token').write_text(token, encoding='utf-8')
    with contextlib.suppress(OSError):
        os.chmod(RUNTIME / 'admin.token', 0o600)
    await asyncio.to_thread(database.initialize, DB)
    executor = ThreadPoolExecutor(max_workers=WORKERS)
    slots = asyncio.Semaphore(WORKERS)
    health_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='readiness')
    readiness = Readiness(health_executor)
    task = asyncio.create_task(control_loop())
    try:
        yield
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        executor.shutdown(wait=True, cancel_futures=True)
        health_executor.shutdown(wait=True, cancel_futures=True)


app = FastAPI(title='Local Resource Defense Lab', lifespan=lifespan)


def require_admin(value: str | None) -> None:
    if not value or not secrets.compare_digest(value, token):
        raise HTTPException(403, 'local admin token required')


@app.get('/health')
async def health():
    ready = await readiness.check()
    ready = ready and not state.admin_busy
    return JSONResponse({'lab_id': LAB_ID, 'ready': ready, 'run_id': state.run_id,
                         'app_mode': state.mode, 'backend': database.BACKEND,
                         'probe_cache_seconds': HEALTH_CACHE_SECONDS},
                        status_code=200 if ready else 503,
                        headers={'Cache-Control': 'no-store'})


@app.get('/live')
async def live():
    return {'lab_id': LAB_ID, 'alive': True}


@app.get('/', response_class=HTMLResponse)
async def home():
    return (ROOT / 'index.html').read_text(encoding='utf-8')


@app.get('/ui.js')
async def ui_script():
    return Response((ROOT / 'ui.js').read_text(encoding='utf-8'),
                    media_type='text/javascript', headers={'Cache-Control': 'no-store'})


class Control(BaseModel):
    mode: Literal['off', 'fixed', 'adaptive']
    report_rounds: int = Field(default=40, ge=1, le=100)
    fixed_limit: int = Field(default=2, ge=1, le=3)


@app.post('/lab/reset')
async def reset(body: Control, x_lab_admin: str | None = Header(default=None)):
    global state
    require_admin(x_lab_admin)
    if sum(state.outstanding.values()) or state.admin_busy:
        raise HTTPException(409, 'work still active; wait for drain')
    state.admin_busy = True
    try:
        await asyncio.to_thread(database.reset, DB)
        new = State()
        new.mode, new.report_rounds = body.mode, body.report_rounds
        new.fixed_limit = body.fixed_limit
        state = new
    finally:
        state.admin_busy = False
    return state.snapshot()


@app.get('/lab/state')
async def snapshot(x_lab_admin: str | None = Header(default=None)):
    require_admin(x_lab_admin)
    return state.snapshot()


@app.get('/lab/events')
async def events(x_lab_admin: str | None = Header(default=None)):
    require_admin(x_lab_admin)
    return {'run_id': state.run_id, 'events': list(state.events), 'capacity': 4096,
            'total_events': state.total_events,
            'dropped_events': state.total_events - len(state.events)}


@app.get('/lab/audit')
async def audit(x_lab_admin: str | None = Header(default=None)):
    require_admin(x_lab_admin)
    if sum(state.outstanding.values()) or state.admin_busy:
        raise HTTPException(409, 'wait for idle before audit')
    state.admin_busy = True
    try:
        return await asyncio.to_thread(database.audit, DB)
    finally:
        state.admin_busy = False


@app.get('/lab/metadata')
async def metadata(x_lab_admin: str | None = Header(default=None)):
    require_admin(x_lab_admin)
    return {'lab_id': LAB_ID, 'rows': database.ROWS, 'workers': WORKERS,
            'max_outstanding': MAX_OUTSTANDING, 'queue_timeout_s': QUEUE_TIMEOUT,
            'sql_execution_timeout_s': 1.5, 'backend': database.BACKEND,
            'sqlite': sqlite3.sqlite_version if database.BACKEND == 'sqlite' else None,
            'versions': {x: importlib.metadata.version(x)
                         for x in ('fastapi', 'uvicorn', 'pydantic')},
            'notice': 'isolated synthetic resource-contention experiment; single application worker'}


async def work(kind: str, request: Request, request_id: str = '', product_id: int = 1):
    # State changes occur on one asyncio event loop; do not use multiple workers.
    event_id = request_id or secrets.token_hex(12)
    if state.admin_busy:
        state.event(kind, event_id, 'admission_rejected', reason='admin_reset')
        return JSONResponse({'ok': False, 'reason': 'admin_reset'}, status_code=503)
    state.totals[f'{kind}_received'] += 1
    limit = state.report_limit()
    if (kind == 'report' and limit is not None
            and state.outstanding[kind] >= limit):
        state.totals['report_policy_rejected'] += 1
        state.report_rejections += 1
        state.event(kind, event_id, 'admission_rejected', reason='report_concurrency_budget')
        return JSONResponse({'ok': False, 'reason': 'report_concurrency_budget'},
                            status_code=429, headers={'Retry-After': '1'})
    if sum(state.outstanding.values()) >= MAX_OUTSTANDING:
        state.totals[f'{kind}_safety_rejected'] += 1
        state.event(kind, event_id, 'admission_rejected', reason='lab_safety_cap')
        return JSONResponse({'ok': False, 'reason': 'lab_safety_cap'}, status_code=503)
    state.outstanding[kind] += 1
    owner = state
    cancellation = Cancellation()
    disconnected_at = None
    residual_counted = False
    worker_future = None
    cancel_task = None
    received = time.monotonic()
    acquired = False
    wait_ms = 0.0
    execution_start = None
    queue_exit_reason = 'handler_cancelled'
    owner.event(kind, event_id, 'accepted')

    def signal_cancellation():
        nonlocal cancel_task
        cancellation.requested.set()
        if cancel_task is None:
            async def send_signal():
                try:
                    await asyncio.to_thread(cancellation.cancel)
                except Exception as exc:
                    owner.event(kind, event_id, 'cancel_signal_error', detail=type(exc).__name__)

            cancel_task = asyncio.create_task(send_signal())
            owner.cancel_tasks.add(cancel_task)
            cancel_task.add_done_callback(owner.cancel_tasks.discard)

    async def watch_disconnect():
        nonlocal disconnected_at, residual_counted
        while not await request.is_disconnected():
            await asyncio.sleep(.02)
        disconnected_at = time.monotonic()
        owner.totals[f'{kind}_disconnected'] += 1
        if worker_future is not None and not worker_future.done():
            owner.active_after_disconnect[kind] += 1
            residual_counted = True
        owner.event(kind, event_id, 'http_disconnect_observed', executing=worker_future is not None)
        signal_cancellation()

    monitor = asyncio.create_task(watch_disconnect())
    acquisition = asyncio.create_task(slots.acquire())

    def worker_finished(future):
        owner.running[kind] -= 1
        owner.outstanding[kind] -= 1
        slots.release()
        residual_ms = None
        if residual_counted:
            owner.active_after_disconnect[kind] -= 1
        if disconnected_at is not None:
            residual_ms = round((time.monotonic()-disconnected_at)*1000, 3)
        error = future.exception()
        owner.event(kind, event_id, 'db_work_finished',
                    work_ms=round((time.monotonic()-execution_start)*1000, 3),
                    residual_after_disconnect_ms=residual_ms,
                    result='error' if error else 'completed')

    try:
        done, _ = await asyncio.wait({acquisition, monitor}, timeout=QUEUE_TIMEOUT,
                                     return_when=asyncio.FIRST_COMPLETED)
        acquired = acquisition in done and acquisition.result()
        if disconnected_at is not None:
            queue_exit_reason = 'client_disconnected'
            return JSONResponse({'ok': False, 'reason': 'client_disconnected'}, status_code=499)
        if not acquired:
            queue_exit_reason = 'queue_timeout'
            state.totals[f'{kind}_queue_timeout'] += 1
            if kind != 'report':
                state.fg_timeouts += 1
            return JSONResponse({'ok': False, 'reason': 'queue_timeout'}, status_code=503)
        state.running[kind] += 1
        wait_ms = (time.monotonic()-received)*1000
        if kind != 'report':
            state.fg_waits.append(wait_ms)
        execution_start = time.monotonic()
        owner.event(kind, event_id, 'db_work_started', queue_ms=round(wait_ms, 3))
        worker_future = asyncio.get_running_loop().run_in_executor(
            executor, database.execute, DB, kind, request_id, product_id,
            state.report_rounds, cancellation)
        worker_future.add_done_callback(worker_finished)
        result = await asyncio.shield(worker_future)
        state.totals[f'{kind}_completed'] += 1
        return JSONResponse(result, headers={
            'X-Lab-Queue-Ms': f'{wait_ms:.3f}',
            'X-Lab-Work-Ms': f'{(time.monotonic()-execution_start)*1000:.3f}'})
    except asyncio.CancelledError:
        # The worker callback, rather than the HTTP task, owns the execution permit.
        signal_cancellation()
        raise
    except WorkCancelled:
        return JSONResponse({'ok': False, 'reason': 'client_disconnected'}, status_code=499)
    except database.ERRORS as exc:
        state.totals[f'{kind}_work_error'] += 1
        return JSONResponse({'ok': False, 'reason': 'db_error_or_execution_limit',
                             'detail': str(exc)}, status_code=503)
    finally:
        acquisition.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await acquisition
        if worker_future is None:
            owner.event(kind, event_id, 'queue_exit', reason=queue_exit_reason)
            # A semaphore acquisition can finish as the handler is being cancelled.
            if not acquisition.cancelled() and acquisition.done() and acquisition.result():
                slots.release()
            owner.outstanding[kind] -= 1
        monitor.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await monitor


@app.get('/api/products')
async def products(request: Request, x_lab_request_id: EventRequestId = None):
    return await work('products', request, x_lab_request_id or '')


class Order(BaseModel):
    request_id: str = Field(min_length=1, max_length=80, pattern=r'^[a-zA-Z0-9_-]+$')
    product_id: int = Field(default=1, ge=1, le=20)
    expected_run_id: str | None = Field(default=None, min_length=16, max_length=16,
                                      pattern=r'^[a-f0-9]{16}$')


@app.post('/api/orders')
async def orders(body: Order, request: Request):
    if body.expected_run_id is not None and body.expected_run_id != state.run_id:
        return JSONResponse({'ok': False, 'reason': 'run_changed', 'run_id': state.run_id},
                            status_code=409)
    return await work('orders', request, body.request_id, body.product_id)


@app.get('/api/report')
async def report(request: Request, x_lab_request_id: EventRequestId = None):
    return await work('report', request, x_lab_request_id or '')


if __name__ == '__main__':
    import uvicorn
    uvicorn.run('server:app', host='127.0.0.1', port=8000, workers=1, access_log=False)
