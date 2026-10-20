"""
A minimal worker pool whose threads are daemons.

concurrent.futures.ThreadPoolExecutor joins its workers when the interpreter exits, so Ctrl+C on the dashboard
(or the end of a test run) would wait for LLM requests still in flight - potentially for their full network
timeout. These workers never block shutdown; a request still running when the process exits is simply dropped.
"""
from __future__ import annotations

import concurrent.futures
import queue
import threading


class DaemonPool:
    def __init__(self, workers: int, name: str = "llm"):
        self._q: queue.Queue = queue.Queue()
        self._threads = [threading.Thread(target=self._run, name=f"{name}_{k}", daemon=True) for k in range(max(1, workers))]
        for t in self._threads:
            t.start()

    def submit(self, fn, *args) -> concurrent.futures.Future:
        fut: concurrent.futures.Future = concurrent.futures.Future()
        self._q.put((fut, fn, args))
        return fut

    def _run(self) -> None:
        while True:
            item = self._q.get()
            if item is None:
                return
            fut, fn, args = item
            if not fut.set_running_or_notify_cancel():
                continue
            try:
                fut.set_result(fn(*args))
            except BaseException as e:  # noqa: BLE001 - delivered to whoever calls .result()
                fut.set_exception(e)

    def shutdown(self) -> None:
        """Cancel every queued task and let the workers exit once their current task ends (no waiting)."""
        while True:
            try:
                item = self._q.get_nowait()
            except queue.Empty:
                break
            if item is not None:
                item[0].cancel()
        for _ in self._threads:
            self._q.put(None)
