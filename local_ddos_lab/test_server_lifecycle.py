"""Exercise actual handler cleanup with controlled workers; no HTTP listener needed."""
import asyncio
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import server


class FakeRequest:
    def __init__(self):
        self.disconnected = False

    async def is_disconnected(self):
        return self.disconnected


class ServerLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.executor = ThreadPoolExecutor(max_workers=1)
        self.state = server.State()
        self.slots = asyncio.Semaphore(1)
        self.patches = patch.multiple(server, state=self.state, executor=self.executor,
                                      slots=self.slots, create=True)
        self.patches.start()
        self.tasks = []
        self.release_worker = threading.Event()
        self.worker_started = threading.Event()
        self.worker_cancellation = None

    async def asyncTearDown(self):
        self.release_worker.set()
        for task in self.tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await asyncio.to_thread(self.executor.shutdown, wait=True)
        await asyncio.gather(*self.state.cancel_tasks, return_exceptions=True)
        await asyncio.sleep(0)
        self.patches.stop()

    def controlled_worker(self, *args):
        self.worker_cancellation = args[-1]
        self.worker_started.set()
        if not self.release_worker.wait(3):
            raise RuntimeError('Test failed to release controlled worker')
        return {'ok': True, 'checksum': 1}

    async def until(self, condition):
        async def poll():
            while not condition():
                await asyncio.sleep(.005)
        await asyncio.wait_for(poll(), timeout=1)

    async def assert_exactly_one_available_permit(self):
        await asyncio.wait_for(self.slots.acquire(), timeout=.1)
        with self.assertRaises(asyncio.TimeoutError):
            await asyncio.wait_for(self.slots.acquire(), timeout=.03)
        self.slots.release()

    async def test_disconnect_keeps_slot_until_db_cleanup_finishes(self):
        request = FakeRequest()
        with patch.object(server.database, 'execute', self.controlled_worker):
            task = asyncio.create_task(server.work('report', request))
            self.tasks.append(task)
            await self.until(self.worker_started.is_set)
            request.disconnected = True
            await self.until(lambda: self.state.active_after_disconnect['report'] == 1)
            self.assertTrue(self.worker_cancellation.requested.is_set())
            self.assertEqual(self.state.running['report'], 1)
            self.assertEqual(self.state.outstanding['report'], 1)
            self.assertTrue(self.slots.locked())
            self.assertFalse(task.done())
            self.release_worker.set()
            await asyncio.wait_for(task, timeout=1)
            await self.until(lambda: self.state.outstanding['report'] == 0)
        self.assertEqual(self.state.running['report'], 0)
        self.assertEqual(self.state.active_after_disconnect['report'], 0)
        finish = [event for event in self.state.events if event['event'] == 'db_work_finished']
        self.assertEqual(len(finish), 1)
        self.assertGreater(finish[0]['residual_after_disconnect_ms'], 0)
        await self.assert_exactly_one_available_permit()

    async def test_disconnect_while_queued_does_not_start_db_or_release_another_slot(self):
        await self.slots.acquire()
        request = FakeRequest()
        with patch.object(server.database, 'execute') as execute:
            task = asyncio.create_task(server.work('report', request))
            self.tasks.append(task)
            await self.until(lambda: self.state.outstanding['report'] == 1)
            request.disconnected = True
            response = await asyncio.wait_for(task, timeout=1)
            self.assertEqual(response.status_code, 499)
            execute.assert_not_called()
        self.assertEqual(self.state.outstanding['report'], 0)
        self.assertEqual(self.state.running['report'], 0)
        self.assertEqual(self.state.active_after_disconnect['report'], 0)
        exits = [event for event in self.state.events if event['event'] == 'queue_exit']
        self.assertEqual([event['reason'] for event in exits], ['client_disconnected'])
        self.assertTrue(self.slots.locked())
        self.slots.release()
        await self.assert_exactly_one_available_permit()

    async def test_queue_timeout_records_terminal_event_and_keeps_existing_permit(self):
        await self.slots.acquire()
        with patch.object(server.database, 'execute') as execute:
            with patch.object(server, 'QUEUE_TIMEOUT', .02):
                response = await server.work('report', FakeRequest(), 'queued_0123456789')
            self.assertEqual(response.status_code, 503)
            execute.assert_not_called()
        self.assertEqual([event['event'] for event in self.state.events], ['accepted', 'queue_exit'])
        self.assertEqual(self.state.events[-1]['reason'], 'queue_timeout')
        self.assertEqual(self.state.outstanding['report'], 0)
        self.assertTrue(self.slots.locked())
        self.slots.release()
        await self.assert_exactly_one_available_permit()

    async def test_repeated_handler_cancellation_does_not_free_running_worker(self):
        request = FakeRequest()
        with patch.object(server.database, 'execute', self.controlled_worker):
            task = asyncio.create_task(server.work('report', request))
            self.tasks.append(task)
            await self.until(self.worker_started.is_set)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(self.worker_cancellation.requested.is_set())
            self.assertEqual(self.state.outstanding['report'], 1)
            self.assertEqual(self.state.running['report'], 1)
            self.assertTrue(self.slots.locked())
            self.release_worker.set()
            await self.until(lambda: self.state.outstanding['report'] == 0)
        self.assertEqual(self.state.running['report'], 0)
        self.assertEqual(self.state.active_after_disconnect['report'], 0)
        self.assertTrue(all(value >= 0 for value in self.state.outstanding.values()))
        await self.assert_exactly_one_available_permit()

    async def test_asgi_cancellation_sends_db_signal_once_and_retains_permit(self):
        request = FakeRequest()
        signal_called = threading.Event()
        signal_calls = []

        def cancel_callback():
            signal_calls.append(True)
            signal_called.set()

        def worker(*args):
            cancellation = args[-1]
            cancellation.bind(cancel_callback)
            try:
                return self.controlled_worker(*args)
            finally:
                cancellation.unbind()

        with patch.object(server.database, 'execute', worker):
            task = asyncio.create_task(server.work('report', request))
            self.tasks.append(task)
            await self.until(self.worker_started.is_set)
            task.cancel()
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            await self.until(signal_called.is_set)
            self.assertEqual(len(signal_calls), 1)
            self.assertEqual(self.state.running['report'], 1)
            self.assertEqual(self.state.outstanding['report'], 1)
            self.assertTrue(self.slots.locked())
            self.worker_cancellation.cancel()
            self.assertEqual(len(signal_calls), 1)
            self.release_worker.set()
            await self.until(lambda: self.state.outstanding['report'] == 0)
            await self.until(lambda: not self.state.cancel_tasks)
        await self.assert_exactly_one_available_permit()

    async def test_cancel_signal_error_is_recorded_without_releasing_db_permit(self):
        request = FakeRequest()

        def cancel_callback():
            raise ValueError('controlled cancellation failure')

        def worker(*args):
            cancellation = args[-1]
            cancellation.bind(cancel_callback)
            try:
                return self.controlled_worker(*args)
            finally:
                cancellation.unbind()

        with patch.object(server.database, 'execute', worker):
            task = asyncio.create_task(server.work('report', request))
            self.tasks.append(task)
            await self.until(self.worker_started.is_set)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            await self.until(lambda: any(event['event'] == 'cancel_signal_error'
                                        for event in self.state.events))
            self.assertTrue(self.slots.locked())
            self.assertEqual(self.state.running['report'], 1)
            self.release_worker.set()
            await self.until(lambda: self.state.outstanding['report'] == 0)
        await self.assert_exactly_one_available_permit()


if __name__ == '__main__':
    unittest.main(verbosity=2)
