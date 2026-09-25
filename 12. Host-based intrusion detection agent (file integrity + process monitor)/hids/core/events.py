"""Thread-safe publish/subscribe event bus.

Engines publish (kind, payload) tuples; the GUI subscribes and pumps its queue
on a tkinter ``after`` timer. Queues are bounded: a slow subscriber drops new
events rather than blocking engine threads.
"""

import queue
import threading

_QUEUE_SIZE = 20000

# Event kinds
ALERT = "alert"
LOG = "log"
SCAN_STARTED = "scan_started"
SCAN_PROGRESS = "scan_progress"
SCAN_FINISHED = "scan_finished"
PROCESS_SNAPSHOT = "process_snapshot"
STATUS = "status"
UI_CALL = "ui_call"


class EventBus:
    def __init__(self):
        self._subs: list = []
        self._lock = threading.Lock()

    def subscribe(self):
        q = queue.Queue(maxsize=_QUEUE_SIZE)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q) -> None:
        with self._lock:
            if q in self._subs:
                self._subs.remove(q)

    def post(self, kind: str, payload) -> None:
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait((kind, payload))
            except queue.Full:
                # Drop rather than block a detection engine.
                pass
