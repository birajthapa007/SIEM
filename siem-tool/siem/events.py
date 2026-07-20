"""Core event model and pub/sub bus."""
import json
import queue
import threading
import time
from dataclasses import dataclass, field, asdict


@dataclass
class Event:
    ts: float
    source: str          # which ingestor / file produced it
    host: str = ""
    ip: str = ""
    user: str = ""
    event_type: str = "generic"
    severity: str = "info"       # info | low | medium | high | critical
    message: str = ""
    raw: str = ""
    meta: dict = field(default_factory=dict)

    def to_dict(self):
        d = asdict(self)
        d["kind"] = "event"
        return d


@dataclass
class Alert:
    ts: float
    rule: str
    severity: str
    title: str
    detail: str
    ip: str = ""
    user: str = ""
    count: int = 1
    id: int = 0
    acked: int = 0
    mitre: str = ""       # MITRE ATT&CK technique id(s), e.g. "T1110"
    geo: str = ""         # country of source IP if known

    def to_dict(self):
        d = asdict(self)
        d["kind"] = "alert"
        return d


class EventBus:
    """Fan-out pub/sub used to push live events/alerts to SSE clients."""

    def __init__(self):
        self._subs = set()
        self._lock = threading.Lock()

    def subscribe(self):
        q = queue.Queue(maxsize=1000)
        with self._lock:
            self._subs.add(q)
        return q

    def unsubscribe(self, q):
        with self._lock:
            self._subs.discard(q)

    def publish(self, obj):
        payload = json.dumps(obj.to_dict() if hasattr(obj, "to_dict") else obj)
        with self._lock:
            dead = []
            for q in self._subs:
                try:
                    q.put_nowait(payload)
                except queue.Full:
                    dead.append(q)
            for q in dead:
                self._subs.discard(q)


def now():
    return time.time()
