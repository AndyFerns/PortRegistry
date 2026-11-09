"""End-to-end daemon lifecycle with real subprocesses, a temp home and a free port.

Covers: detached start, health, duplicate start rejection (both the CLI check
and the OS-level lock), real discovery of a controlled TCP+UDP socket through
the API, registry writes, graceful API shutdown, and persistence across restart.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time

import pytest

from portregistry.client import ApiClient
from portregistry.config import read_token
from portregistry.daemon import control
from portregistry.exceptions import DaemonAlreadyRunningError, DaemonNotRunningError
from portregistry.paths import get_paths

pytestmark = pytest.mark.slow


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("PORTREGISTRY_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("PORTREGISTRY_PORT", str(free_port()))
    paths = get_paths()
    yield paths
    try:
        control.stop_daemon(paths=paths, force=True, timeout=20)
    except DaemonNotRunningError:
        pass


def client_for(status: dict) -> ApiClient:
    return ApiClient(status["url"], read_token(get_paths()))


def test_daemon_lifecycle_and_persistence(isolated_home):
    paths = isolated_home
    status = control.start_daemon(paths=paths, timeout=60)
    assert status["running"] and status["healthy"]

    # Duplicate startup is rejected by the CLI pre-check...
    with pytest.raises(DaemonAlreadyRunningError):
        control.start_daemon(paths=paths, timeout=10)
    # ...and by the OS-level single-instance lock in a second foreground daemon.
    second = subprocess.run(
        [sys.executable, "-m", "portregistry", "daemon", "run", "--quiet"],
        env=os.environ.copy(),
        capture_output=True,
        timeout=60,
    )
    assert second.returncode == 3

    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(("127.0.0.1", 0))
    tcp.listen()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    tcp_port, udp_port = tcp.getsockname()[1], udp.getsockname()[1]
    try:
        with client_for(status) as api:
            assert api.health()["status"] == "ok"
            machine_uuid = api.get("status/")["machine"]["uuid"]
            ticket = api.post("discovery/scan/", {})
            for _ in range(200):
                ticket = api.get(f"discovery/scan/{ticket['ticket']}/")
                if ticket["status"] in ("done", "failed", "skipped"):
                    break
                time.sleep(0.1)
            assert ticket["status"] == "done"
            mine = [
                p for p in api.list_all("ports/", q=str(os.getpid())) if p["pid"] == os.getpid()
            ]
            found = {(p["protocol"], p["port"]) for p in mine}
            assert ("tcp", tcp_port) in found and ("udp", udp_port) in found
            assert all(p["process"]["identity_complete"] for p in mine)

            api.post("services/", {"name": "pytest", "expected_executable": "python"})
            created = api.post("reservations/", {"port": tcp_port, "service": "pytest"})
            # Owned by this python process -> matches the service, no mismatch.
            assert not [c for c in created["conflicts"] if c["type"] == "service_mismatch"]
    finally:
        tcp.close()
        udp.close()

    stopped = control.stop_daemon(paths=paths, timeout=30)
    assert stopped["stopped"] and stopped["graceful"]
    assert not control.daemon_status(paths)["running"]

    status = control.start_daemon(paths=paths, timeout=60)
    with client_for(status) as api:
        assert api.get("status/")["machine"]["uuid"] == machine_uuid
        assert [s["name"] for s in api.list_all("services/")] == ["pytest"]
        reservation = api.list_all("reservations/", status="all")[0]
        assert reservation["port"] == tcp_port
        types = {e["type"] for e in api.list_all("history/")}
        assert {
            "machine.online",
            "machine.offline",
            "service.created",
            "reservation.created",
        } <= types
    control.stop_daemon(paths=paths, timeout=30)
