"""Shared fixtures.

Django is configured by pytest-django (DJANGO_SETTINGS_MODULE in pyproject).
The SQLite test database is in-memory; tests never touch the user's real
PortRegistry data directory for database state.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest

from portregistry.core.types import (
    Family,
    NativeScanResult,
    ProcessInfo,
    Protocol,
    RawSocket,
    ScanScope,
    SocketState,
)

TEST_TOKEN = "test-token-0123456789"


@pytest.fixture
def app(tmp_path):
    """A registered daemon Application (token auth, in-memory bus, idle scheduler)."""
    from portregistry.config import parse_config
    from portregistry.core.application import Application, set_application
    from portregistry.daemon.scheduler import Scheduler
    from portregistry.paths import AppPaths

    paths = AppPaths(tmp_path / "config", tmp_path / "data", tmp_path / "logs")
    application = Application(
        config=parse_config({}, paths), token=TEST_TOKEN, machine_uuid=uuid.uuid4()
    )
    # Scheduler is constructed but never started: requests queue deterministically.
    application.scheduler = Scheduler(
        native_runner=lambda scope, trigger: None, native_interval=3600
    )
    application.docker_provider.enabled = False
    application.docker_provider.update("disabled", "disabled in tests")
    set_application(application)
    yield application
    set_application(None)


@pytest.fixture
def machine(db):
    from portregistry.django_app.models import Machine

    return Machine.objects.create(
        uuid=uuid.uuid4(), hostname="testhost", os_name="TestOS", is_local=True, online=True
    )


def raw_tcp(port: int, pid: int | None, address: str = "0.0.0.0") -> RawSocket:
    family = Family.IPV6 if ":" in address else Family.IPV4
    return RawSocket(Protocol.TCP, family, address, port, SocketState.LISTEN, pid)


def raw_udp(port: int, pid: int | None, address: str = "0.0.0.0") -> RawSocket:
    family = Family.IPV6 if ":" in address else Family.IPV4
    return RawSocket(Protocol.UDP, family, address, port, SocketState.BOUND, pid)


def pinfo(pid: int, name: str = "server", create_time: float | None = 1000.0, **kw) -> ProcessInfo:
    return ProcessInfo(
        pid=pid,
        name=name,
        exe=kw.pop("exe", f"/usr/bin/{name}"),
        create_time=create_time,
        cmdline=kw.pop("cmdline", [name]),
        cwd=kw.pop("cwd", "/srv"),
        **kw,
    )


def scan_result(
    sockets: list[RawSocket],
    processes: list[ProcessInfo] | None = None,
    *,
    complete: bool = True,
    scope: ScanScope | None = None,
    error: str | None = None,
    enumerated_pids: frozenset[int] | None = None,
) -> NativeScanResult:
    now = datetime.now(UTC)
    return NativeScanResult(
        provider="fake",
        scope=scope or ScanScope.build(),
        started_at=now - timedelta(milliseconds=5),
        finished_at=now,
        sockets=sockets,
        processes={p.pid: p for p in (processes or [])},
        complete=complete,
        enumerated_pids=enumerated_pids,
        error=error,
    )
