"""Cooperative SQL cancellation; completion remains owned by the DB worker."""
import threading


class WorkCancelled(Exception):
    pass


class Cancellation:
    def __init__(self):
        self.requested = threading.Event()
        self.lock = threading.Lock()
        self.callback = None
        self.signal_sent = False

    def bind(self, callback):
        with self.lock:
            self.check()
            self.callback = callback

    def unbind(self):
        with self.lock:
            self.callback = None

    def check(self):
        if self.requested.is_set():
            raise WorkCancelled('client disconnected or request cancelled')

    def cancel(self):
        self.requested.set()
        with self.lock:
            if self.callback is not None and not self.signal_sent:
                self.signal_sent = True
                self.callback()
