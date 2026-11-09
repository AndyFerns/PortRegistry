"""Docker lifecycle event listener with reconnect + reconciliation.

Events are hints: each relevant container event requests a (debounced,
coalesced) inventory reconciliation. After every (re)connect a full
reconciliation is requested too, because events may have been missed while
disconnected. Periodic inventory reconciliation remains the recovery mechanism.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from typing import Any

from portregistry.discovery.docker.provider import iter_events

logger = logging.getLogger(__name__)

RELEVANT_ACTIONS = frozenset(
    {
        "create",
        "start",
        "restart",
        "stop",
        "die",
        "kill",
        "destroy",
        "pause",
        "unpause",
        "rename",
        "update",
    }
)
MAX_BACKOFF = 60.0


class DockerEventListener:
    def __init__(
        self,
        stream_factory: Callable[[], Any],
        on_refresh: Callable[[str], None],
        *,
        initial_backoff: float = 1.0,
        max_backoff: float = MAX_BACKOFF,
    ) -> None:
        self._stream_factory = stream_factory
        self._on_refresh = on_refresh
        self._initial_backoff = initial_backoff
        self._max_backoff = max_backoff
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stream: Any = None
        self._lock = threading.Lock()
        self.connections = 0
        self.events_seen = 0

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="pr-docker-events", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        with self._lock:
            stream = self._stream
        if stream is not None:
            try:
                stream.close()
            except Exception:
                pass
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout)

    @property
    def stopped(self) -> bool:
        return self._stop.is_set()

    def _run(self) -> None:
        backoff = self._initial_backoff
        while not self._stop.is_set():
            try:
                stream = self._stream_factory()
                with self._lock:
                    self._stream = stream
                self.connections += 1
                if self.connections > 1:
                    logger.info("Reconnected to Docker event stream")
                # Missed events while disconnected: reconcile the full inventory.
                self._on_refresh("docker-events-connected")
                backoff = self._initial_backoff
                for event in iter_events(stream):
                    if self._stop.is_set():
                        break
                    action = str(event.get("Action") or event.get("status") or "").split(":", 1)[0]
                    if event.get("Type", "container") == "container" and action in RELEVANT_ACTIONS:
                        self.events_seen += 1
                        self._on_refresh(f"docker-event:{action}")
                if not self._stop.is_set():
                    raise ConnectionError("Docker event stream ended")
            except Exception as exc:
                if self._stop.is_set():
                    break
                logger.debug("Docker event stream unavailable: %s (retry in %.0fs)", exc, backoff)
                self._stop.wait(backoff)
                backoff = min(backoff * 2, self._max_backoff)
            finally:
                with self._lock:
                    stream, self._stream = self._stream, None
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass
