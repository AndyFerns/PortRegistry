"""The daemon's composition root.

An :class:`Application` instance is created exactly once by the daemon
lifecycle (never at import time) and registered with :func:`set_application`.
Django views reach daemon state (event bus, scheduler, provider status) through
:func:`get_application`.
"""

from __future__ import annotations

import secrets
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from portregistry import __version__
from portregistry.config import Config
from portregistry.core.events import EventBus


class SchedulerHandle(Protocol):
    def request_native_scan(self, protocol: str | None, port: int | None, trigger: str) -> Any: ...

    def get_ticket(self, ticket_id: int) -> Any: ...

    def request_docker_refresh(self, reason: str) -> None: ...

    def describe(self) -> dict[str, Any]: ...


@dataclass
class ProviderState:
    """Runtime health of one discovery provider."""

    name: str
    enabled: bool = True
    state: str = "unknown"  # ok | degraded | unavailable | disabled | unknown
    message: str = ""
    last_attempt: datetime | None = None
    last_success: datetime | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def update(self, state: str, message: str = "", **details: Any) -> bool:
        """Update; returns True when the state value changed."""
        changed = state != self.state
        now = datetime.now(UTC)
        self.state = state
        self.message = message
        self.last_attempt = now
        if state == "ok":
            self.last_success = now
        self.details.update(details)
        return changed

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "enabled": self.enabled,
            "state": self.state,
            "message": self.message,
            "last_attempt": self.last_attempt.isoformat() if self.last_attempt else None,
            "last_success": self.last_success.isoformat() if self.last_success else None,
            "details": self.details,
        }


class OneTimeLinks:
    """Single-use, short-lived browser login nonces held only in daemon memory."""

    def __init__(self, ttl_seconds: float = 60.0) -> None:
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._nonces: dict[str, float] = {}

    def issue(self) -> str:
        nonce = secrets.token_urlsafe(32)
        with self._lock:
            now = time.monotonic()
            self._nonces = {k: v for k, v in self._nonces.items() if v > now}
            self._nonces[nonce] = now + self._ttl
        return nonce

    def consume(self, nonce: str) -> bool:
        with self._lock:
            expiry = self._nonces.pop(nonce, None)
        return expiry is not None and expiry > time.monotonic()

    @property
    def ttl(self) -> float:
        return self._ttl


class ActionNonces:
    """Single-use, short-lived confirmation codes bound to a payload (daemon memory only).

    Used by process control: the first request returns a code bound to one exact
    process (and stop mode); the second request must present it within ``ttl``
    seconds. Codes are consumed on first use, whether or not the action proceeds.
    """

    def __init__(self, ttl_seconds: float = 30.0, max_pending: int = 20) -> None:
        self._ttl = ttl_seconds
        self._max = max_pending
        self._lock = threading.Lock()
        self._codes: dict[str, tuple[float, Any]] = {}

    def _prune(self, now: float) -> None:
        self._codes = {k: v for k, v in self._codes.items() if v[0] > now}

    def issue(self, payload: Any) -> str | None:
        """Return a new code, or None when too many codes are pending."""
        with self._lock:
            now = time.monotonic()
            self._prune(now)
            if len(self._codes) >= self._max:
                return None
            code = secrets.token_urlsafe(24)
            self._codes[code] = (now + self._ttl, payload)
        return code

    def consume(self, code: str) -> tuple[str, Any]:
        """Pop a code. Returns (status, payload); status is ok, expired or unknown."""
        with self._lock:
            entry = self._codes.pop(code, None) if code else None
        if entry is None:
            return "unknown", None
        expiry, payload = entry
        if expiry <= time.monotonic():
            return "expired", payload
        return "ok", payload

    def pending(self) -> int:
        with self._lock:
            self._prune(time.monotonic())
            return len(self._codes)

    @property
    def ttl(self) -> float:
        return self._ttl


@dataclass
class Application:
    config: Config
    token: str
    machine_uuid: uuid.UUID
    bus: EventBus = field(default_factory=EventBus)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    version: str = __version__
    scheduler: SchedulerHandle | None = None
    links: OneTimeLinks = field(default_factory=OneTimeLinks)
    native_provider: ProviderState = field(default_factory=lambda: ProviderState("native"))
    docker_provider: ProviderState = field(default_factory=lambda: ProviderState("docker"))
    platform_info: dict[str, Any] = field(default_factory=dict)
    shutting_down: bool = False
    #: False during daemon startup until both initial native and Docker discovery
    #: have run, so conflicts are not computed from a half-initialised state.
    conflicts_ready: bool = True
    #: Alert webhook dispatcher (daemon.alerts.AlertDispatcher) when configured.
    alerts: Any = None
    #: Process-control confirmation codes (30 s, single use).
    control_codes: ActionNonces = field(default_factory=ActionNonces)
    #: Recent process-stop operations (services.process_control.OperationLog).
    stop_operations: Any = None
    _shutdown_callback: Callable[[], None] | None = None

    def set_shutdown_callback(self, callback: Callable[[], None]) -> None:
        self._shutdown_callback = callback

    def request_shutdown(self) -> bool:
        if self._shutdown_callback is None:
            return False
        self._shutdown_callback()
        return True

    @property
    def uptime_seconds(self) -> float:
        return (datetime.now(UTC) - self.started_at).total_seconds()

    @property
    def stale_after_seconds(self) -> float:
        d = self.config.discovery
        return d.native_interval * d.stale_after_factor + 5


_application: Application | None = None
_app_lock = threading.Lock()


def set_application(app: Application | None) -> None:
    global _application
    with _app_lock:
        _application = app


def get_application() -> Application:
    app = _application
    if app is None:
        raise RuntimeError(
            "PortRegistry application is not initialised. "
            "Django views must run inside the daemon (portregistry daemon run)."
        )
    return app


def has_application() -> bool:
    return _application is not None
