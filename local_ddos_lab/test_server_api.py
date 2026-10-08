"""HTTP behavior against a disposable database, including lost acknowledgements."""
import asyncio
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import httpx

import database
import server


class DropFirstOrderAcknowledgement(httpx.AsyncBaseTransport):
    def __init__(self):
        self.inner = httpx.ASGITransport(app=server.app)
        self.dropped = False

    async def handle_async_request(self, request):
        response = await self.inner.handle_async_request(request)
        if request.url.path == '/api/orders' and not self.dropped:
            self.dropped = True
            await response.aread()
            raise httpx.ReadError('acknowledgement lost after commit', request=request)
        return response

    async def aclose(self):
        await self.inner.aclose()


class ServerApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.target = Path(self.temp_dir.name) / 'lab.sqlite'
        database.initialize(self.target)
        self.pool = ThreadPoolExecutor(max_workers=4)
        self.health_pool = ThreadPoolExecutor(max_workers=1)
        self.state = server.State()
        self.probe = server.Readiness(self.health_pool)
        self.patches = patch.multiple(server, state=self.state, DB=self.target,
                                      database=database, executor=self.pool,
                                      slots=asyncio.Semaphore(4), readiness=self.probe,
                                      token='test-admin', create=True)
        self.patches.start()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=server.app),
                                       base_url='http://test')

    async def asyncTearDown(self):
        await self.client.aclose()
        await asyncio.to_thread(self.pool.shutdown, wait=True)
        await asyncio.to_thread(self.health_pool.shutdown, wait=True)
        await asyncio.gather(*self.state.cancel_tasks, return_exceptions=True)
        await asyncio.sleep(0)
        self.patches.stop()
        self.temp_dir.cleanup()

    async def test_readiness_detects_db_failure_and_recovery_without_creating_db(self):
        initial = await self.client.get('/health')
        self.assertEqual(initial.status_code, 200)
        self.assertEqual(initial.json()['run_id'], self.state.run_id)
        self.assertEqual(initial.json()['app_mode'], 'off')
        self.assertEqual(initial.headers['cache-control'], 'no-store')
        backup = self.target.with_suffix('.backup')
        self.target.rename(backup)
        self.probe.checked_at -= server.HEALTH_CACHE_SECONDS
        failed = await self.client.get('/health')
        self.assertEqual(failed.status_code, 503)
        self.assertFalse(failed.json()['ready'])
        self.assertFalse(self.target.exists())
        with patch.object(database, 'readiness', side_effect=AssertionError('live must not probe')):
            self.assertEqual((await self.client.get('/live')).status_code, 200)
        backup.rename(self.target)
        self.probe.checked_at -= server.HEALTH_CACHE_SECONDS
        recovered = await self.client.get('/health')
        self.assertEqual(recovered.status_code, 200)
        self.assertTrue(recovered.json()['ready'])
        self.assertEqual(dict(self.state.totals), {})
        self.assertEqual(list(self.state.events), [])

    async def test_slow_probe_has_one_inflight_job_and_does_not_occupy_work_slots(self):
        release = threading.Event()

        def slow_probe(_):
            release.wait(2)
            return True

        try:
            with patch.object(database, 'readiness', side_effect=slow_probe) as probe:
                with patch.object(server, 'HEALTH_TIMEOUT_SECONDS', .02):
                    responses = await asyncio.wait_for(asyncio.gather(*[
                        self.client.get('/health') for _ in range(12)]), timeout=.5)
                    self.assertTrue(all(response.status_code == 503 for response in responses))
                    self.probe.checked_at -= server.HEALTH_CACHE_SECONDS
                    self.assertEqual((await self.client.get('/health')).status_code, 503)
                    self.assertEqual(probe.call_count, 1)
                    for _ in range(4):
                        await asyncio.wait_for(server.slots.acquire(), timeout=.1)
                    for _ in range(4):
                        server.slots.release()
                release.set()
                await asyncio.shield(self.probe.in_flight)
                await asyncio.sleep(0)
                self.assertTrue((await self.client.get('/health')).json()['ready'])
        finally:
            release.set()

    async def test_committed_order_with_lost_ack_retries_without_second_stock_decrement(self):
        payload = {'request_id': 'lost-ack-intent', 'product_id': 3,
                   'expected_run_id': self.state.run_id}
        async with httpx.AsyncClient(transport=DropFirstOrderAcknowledgement(),
                                     base_url='http://test') as client:
            with self.assertRaises(httpx.ReadError):
                await client.post('/api/orders', json=payload)
            self.assertEqual(database.audit(self.target)['stock_used'], 1)
            retried = await client.post('/api/orders', json=payload)
        self.assertEqual(retried.status_code, 200)
        self.assertTrue(retried.json()['persisted'])
        audit = database.audit(self.target)
        self.assertEqual(audit['stock_used'], 1)
        self.assertEqual(audit['committed_orders'], [
            {'request_id': 'lost-ack-intent', 'product_id': 3}])

    async def test_old_run_retry_is_rejected_after_reset_without_new_order(self):
        payload = {'request_id': 'old-run-intent', 'product_id': 2,
                   'expected_run_id': self.state.run_id}
        self.assertEqual((await self.client.post('/api/orders', json=payload)).status_code, 200)
        reset = await self.client.post('/lab/reset', headers={'X-Lab-Admin': 'test-admin'},
                                       json={'mode': 'fixed'})
        self.assertEqual(reset.status_code, 200)
        self.assertNotEqual(reset.json()['run_id'], payload['expected_run_id'])
        response = await self.client.post('/api/orders', json=payload)
        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.json()['reason'], 'run_changed')
        self.assertEqual(database.audit(self.target)['stock_used'], 0)
        health = await self.client.get('/health')
        self.assertEqual(health.json()['app_mode'], 'fixed')
        self.assertEqual(health.json()['run_id'], reset.json()['run_id'])

    async def test_get_request_ids_correlate_events_and_invalid_ids_do_no_work(self):
        self.state.report_rounds = 1
        for kind in ('products', 'report'):
            event_id = f'opaque_{kind}_0123456789'
            response = await self.client.get(f'/api/{kind}', headers={'X-Lab-Request-ID': event_id})
            self.assertEqual(response.status_code, 200)
            recorded = [event for event in self.state.events if event['request_id'] == event_id]
            self.assertEqual([event['event'] for event in recorded],
                             ['accepted', 'db_work_started', 'db_work_finished'])
            before = len(self.state.events)
            for bad in ('short', 'x' * 65, 'not allowed spaces', 'semi;colon_0123456789'):
                response = await self.client.get(f'/api/{kind}', headers={'X-Lab-Request-ID': bad})
                self.assertEqual(response.status_code, 422)
            self.assertEqual(len(self.state.events), before)

    async def test_request_ids_do_not_bypass_admission_limits(self):
        self.state.mode = 'fixed'
        self.state.outstanding['report'] = self.state.fixed_limit
        response = await self.client.get('/api/report', headers={
            'X-Lab-Request-ID': 'opaque_rejected_0123456789'})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(self.state.events[-1]['event'], 'admission_rejected')
        self.assertEqual(self.state.events[-1]['request_id'], 'opaque_rejected_0123456789')

    async def test_events_report_exact_truncation_counts(self):
        for i in range(4100):
            self.state.event('report', str(i), 'accepted')
        response = await self.client.get('/lab/events', headers={'X-Lab-Admin': 'test-admin'})
        body = response.json()
        self.assertEqual(body['total_events'], 4100)
        self.assertEqual(body['dropped_events'], 4)
        self.assertEqual(len(body['events']), 4096)


if __name__ == '__main__':
    unittest.main(verbosity=2)
