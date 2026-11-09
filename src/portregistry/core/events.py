"""In-process event bus bridging daemon worker threads to SSE subscribers.

Events are *hints* that committed state changed. Publishers call
:meth:`EventBus.publish` only after the corresponding database transaction has
committed. Subscribers (SSE streams) live on the ASGI event loop and receive
events through bounded asyncio queues. A subscriber that falls behind is marked
as overflowed and told to resynchronize by refetching authoritative state.
"""

from __future__ import annotations

import asyncio
import itertools
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)

#: Topics map to UI areas; clients refresh the matching views.
TOPICS = ("scan", "ports", "registry", "conflicts", "docker", "history", "daemon", "alerts")


@dataclass(frozen=True)
class BusEvent:
    seq: int
    topic: str
    type: str
    data: dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    def as_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "topic": self.topic,
            "type": self.type,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
        }


class Subscription:
    def __init__(self, loop: asyncio.AbstractEventLoop, maxsize: int) -> None:
        self.loop = loop
        self.queue: asyncio.Queue[BusEvent | None] = asyncio.Queue(maxsize=maxsize)
        self.overflowed = False

    def _deliver(self, event: BusEvent | None) -> None:
        # Runs on the subscriber's event loop.
        if event is None:
            # Shutdown sentinel must always get through.
            while self.queue.full():
                try:
                    self.queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
            self.queue.put_nowait(None)
            return
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            self.overflowed = True

    async def get(self, timeout: float) -> BusEvent | None | str:
        """Next event, ``None`` when the bus closed, or ``"timeout"``."""
        try:
            return await asyncio.wait_for(self.queue.get(), timeout=timeout)
        except TimeoutError:
            return "timeout"


class EventBus:
    def __init__(self, queue_size: int = 500) -> None:
        self._lock = threading.Lock()
        self._subscriptions: set[Subscription] = set()
        self._listeners: list[Callable[[BusEvent], None]] = []
        self._seq = itertools.count(1)
        self._last_seq = 0
        self._queue_size = queue_size
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def last_seq(self) -> int:
        return self._last_seq

    def subscribe(self) -> Subscription:
        """Create a subscription bound to the running event loop."""
        sub = Subscription(asyncio.get_running_loop(), self._queue_size)
        with self._lock:
            if self._closed:
                sub.queue.put_nowait(None)
            else:
                self._subscriptions.add(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            self._subscriptions.discard(sub)

    def add_listener(self, listener: Callable[[BusEvent], None]) -> None:
        """Synchronous listener called on the publishing thread (tests, logging)."""
        with self._lock:
            self._listeners.append(listener)

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscriptions)

    def publish(self, topic: str, type_: str, data: dict[str, Any] | None = None) -> BusEvent:
        event = BusEvent(seq=next(self._seq), topic=topic, type=type_, data=data or {})
        with self._lock:
            self._last_seq = event.seq
            subs = list(self._subscriptions)
            listeners = list(self._listeners)
        for sub in subs:
            try:
                sub.loop.call_soon_threadsafe(sub._deliver, event)
            except RuntimeError:
                # Subscriber loop already closed; drop it.
                self.unsubscribe(sub)
        for listener in listeners:
            try:
                listener(event)
            except Exception:  # pragma: no cover - defensive
                logger.exception("Event listener failed")
        return event

    def close(self) -> None:
        """Signal all subscribers to finish (daemon shutdown)."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            subs = list(self._subscriptions)
            self._subscriptions.clear()
        for sub in subs:
            try:
                sub.loop.call_soon_threadsafe(sub._deliver, None)
            except RuntimeError:
                pass
