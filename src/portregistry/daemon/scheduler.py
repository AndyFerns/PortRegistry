"""Single-threaded job scheduler owned by the daemon.

One worker thread runs every job, so native scans, Docker reconciliations and
maintenance never overlap. Manual scan requests are coalesced: while a request
is pending, further requests merge into it; a request that arrives while a scan
covering its scope is running is attached to that scan.

The scheduler is created and started only by the daemon lifecycle - never at
import time or from Django app initialization.
"""

from __future__ import annotations

import itertools
import logging
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from portregistry.core.types import ScanScope

logger = logging.getLogger(__name__)

MAX_TICKETS = 200
DOCKER_DEBOUNCE_SECONDS = 1.0


@dataclass
class ScanTicket:
    id: int
    scope: ScanScope
    trigger: str
    status: str = "queued"  # queued | running | done | failed | skipped
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    scan_id: int | None = None
    result: dict[str, Any] | None = None
    error: str | None = None
    coalesced: int = 0

    @property
    def finished(self) -> bool:
        return self.status in ("done", "failed", "skipped")

    def as_dict(self) -> dict[str, Any]:
        return {
            "ticket": self.id,
            "status": self.status,
            "trigger": self.trigger,
            "scope": {
                "protocols": sorted(p.value for p in self.scope.protocols),
                "port": self.scope.port,
            },
            "scan_id": self.scan_id,
            "coalesced_requests": self.coalesced,
            "result": self.result,
            "error": self.error,
        }


NativeRunner = Callable[[ScanScope, str], Any]
DockerRunner = Callable[[str], Any]
MaintenanceRunner = Callable[[], Any]


class Scheduler:
    def __init__(
        self,
        *,
        native_runner: NativeRunner,
        native_interval: float,
        docker_runner: DockerRunner | None = None,
        docker_interval: float | None = None,
        maintenance_runner: MaintenanceRunner | None = None,
        maintenance_interval: float = 3600.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._native_runner = native_runner
        self._native_interval = native_interval
        self._docker_runner = docker_runner
        self._docker_interval = docker_interval
        self._maintenance_runner = maintenance_runner
        self._maintenance_interval = maintenance_interval
        self._clock = clock

        self._cond = threading.Condition()
        self._thread: threading.Thread | None = None
        self._stopping = False
        self._ids = itertools.count(1)
        self._tickets: OrderedDict[int, ScanTicket] = OrderedDict()
        self._pending: ScanTicket | None = None
        self._running_job: str | None = None
        self._running_ticket: ScanTicket | None = None

        now = clock()
        self._next_native = now + native_interval
        self._next_docker = now + (docker_interval or 0)
        self._next_maintenance = now + 60.0
        self._docker_requested_at: float | None = None
        self._docker_reason = ""
        self._last_native_ticket: ScanTicket | None = None

    # ------------------------------------------------------------ lifecycle

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("Scheduler already started")
        self._thread = threading.Thread(target=self._loop, name="pr-scheduler", daemon=True)
        self._thread.start()
        logger.info(
            "Scheduler started (native every %ss%s)",
            self._native_interval,
            f", docker every {self._docker_interval}s" if self._docker_runner else "",
        )

    def stop(self, timeout: float = 15.0) -> bool:
        """Stop scheduling; waits for a running job to finish. Returns True if joined."""
        with self._cond:
            self._stopping = True
            if self._pending is not None:
                self._pending.status = "skipped"
                self._pending.error = "daemon shutting down"
                self._pending = None
            self._cond.notify_all()
        thread = self._thread
        if thread is None or thread is threading.current_thread():
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def signal_stop(self) -> None:
        """Non-blocking stop request (used from signal handlers)."""
        with self._cond:
            self._stopping = True
            self._cond.notify_all()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and not self._stopping

    # ------------------------------------------------------------- requests

    def _remember(self, ticket: ScanTicket) -> None:
        self._tickets[ticket.id] = ticket
        while len(self._tickets) > MAX_TICKETS:
            self._tickets.popitem(last=False)

    def request_native_scan(
        self, protocol: str | None = None, port: int | None = None, trigger: str = "manual"
    ) -> ScanTicket:
        scope = ScanScope.build(protocol, port)
        with self._cond:
            running = self._running_ticket
            if (
                running is not None
                and not running.finished
                and running.scope.merge(scope) == running.scope
            ):
                running.coalesced += 1
                return running
            if self._pending is not None:
                self._pending.scope = self._pending.scope.merge(scope)
                self._pending.coalesced += 1
                return self._pending
            ticket = ScanTicket(id=next(self._ids), scope=scope, trigger=trigger)
            self._remember(ticket)
            if self._stopping:
                ticket.status = "skipped"
                ticket.error = "daemon shutting down"
                return ticket
            self._pending = ticket
            self._cond.notify_all()
            return ticket

    def get_ticket(self, ticket_id: int) -> ScanTicket | None:
        with self._cond:
            return self._tickets.get(ticket_id)

    def request_docker_refresh(self, reason: str) -> None:
        if self._docker_runner is None:
            return
        with self._cond:
            if self._docker_requested_at is None:
                self._docker_requested_at = self._clock()
                self._docker_reason = reason
            self._cond.notify_all()

    def wait_for(self, ticket: ScanTicket, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        with self._cond:
            while not ticket.finished:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._cond.wait(remaining)
        return True

    def describe(self) -> dict[str, Any]:
        now = self._clock()
        with self._cond:
            last = self._last_native_ticket
            return {
                "running": self.running,
                "current_job": self._running_job,
                "native_interval": self._native_interval,
                "docker_interval": self._docker_interval if self._docker_runner else None,
                "next_native_in": max(0.0, round(self._next_native - now, 1)),
                "next_docker_in": (
                    max(0.0, round(self._next_docker - now, 1)) if self._docker_runner else None
                ),
                "pending_manual_scan": self._pending.id if self._pending else None,
                "last_native_ticket": last.as_dict() if last else None,
            }

    # ----------------------------------------------------------------- loop

    def _pick_job(self, now: float) -> tuple[str, ScanTicket | None] | None:
        if self._pending is not None:
            ticket = self._pending
            self._pending = None
            return "native", ticket
        if now >= self._next_native:
            ticket = ScanTicket(id=next(self._ids), scope=ScanScope.build(), trigger="scheduled")
            self._remember(ticket)
            return "native", ticket
        if self._docker_runner is not None:
            requested = self._docker_requested_at
            if requested is not None and now - requested >= DOCKER_DEBOUNCE_SECONDS:
                return "docker", None
            if now >= self._next_docker:
                return "docker", None
        if self._maintenance_runner is not None and now >= self._next_maintenance:
            return "maintenance", None
        return None

    def _seconds_until_next(self, now: float) -> float:
        candidates = [self._next_native - now]
        if self._docker_runner is not None:
            candidates.append(self._next_docker - now)
            if self._docker_requested_at is not None:
                candidates.append(self._docker_requested_at + DOCKER_DEBOUNCE_SECONDS - now)
        if self._maintenance_runner is not None:
            candidates.append(self._next_maintenance - now)
        return max(0.05, min(candidates))

    def _loop(self) -> None:
        while True:
            with self._cond:
                job = None
                while not self._stopping:
                    now = self._clock()
                    job = self._pick_job(now)
                    if job is not None:
                        break
                    self._cond.wait(timeout=min(self._seconds_until_next(now), 1.0))
                if self._stopping or job is None:
                    break
                name, ticket = job
                self._running_job = name
                if ticket is not None:
                    ticket.status = "running"
                    ticket.started_at = time.time()
                    self._running_ticket = ticket
            try:
                self._run(name, ticket)
            finally:
                with self._cond:
                    self._running_job = None
                    self._running_ticket = None
                    self._cond.notify_all()
        logger.info("Scheduler stopped")

    def _run(self, name: str, ticket: ScanTicket | None) -> None:
        if name == "native" and ticket is not None:
            try:
                summary = self._native_runner(ticket.scope, ticket.trigger)
                if summary is None:
                    ticket.status = "skipped"
                    ticket.error = "another scan was already running"
                else:
                    ticket.scan_id = getattr(summary, "scan_id", None)
                    as_dict = getattr(summary, "as_dict", None)
                    ticket.result = as_dict() if callable(as_dict) else None
                    ticket.status = "done"
            except Exception as exc:
                logger.exception("Native scan job failed")
                ticket.status = "failed"
                ticket.error = f"{exc.__class__.__name__}: {exc}"
            finally:
                ticket.finished_at = time.time()
                self._last_native_ticket = ticket
                if ticket.scope.is_full:
                    self._next_native = self._clock() + self._native_interval
        elif name == "docker" and self._docker_runner is not None:
            reason = self._docker_reason or "scheduled"
            self._docker_requested_at = None
            self._docker_reason = ""
            try:
                self._docker_runner(reason)
            except Exception:
                logger.exception("Docker reconciliation job failed")
            finally:
                self._next_docker = self._clock() + (self._docker_interval or 30.0)
        elif name == "maintenance" and self._maintenance_runner is not None:
            try:
                self._maintenance_runner()
            except Exception:
                logger.exception("Maintenance job failed")
            finally:
                self._next_maintenance = self._clock() + self._maintenance_interval
