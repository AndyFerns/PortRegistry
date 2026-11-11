"""Live process control against real, disposable child processes started by the test.

Only processes spawned here are ever stopped. They are plain console Python
processes owned by the test user: on Windows they have no window, so the
method must be labelled "immediate"; on POSIX it is a graceful SIGTERM.
"""

from __future__ import annotations

import subprocess
import sys
import time

import psutil
import pytest

from portregistry.django_app.models import Event, ProcessInstance
from portregistry.services import process_control as pc
from portregistry.services.process_os import PsutilProcessOs
from portregistry.services.reconcile import apply_native_scan, begin_scan
from tests.conftest import pinfo, raw_tcp, scan_result
from tests.control_fakes import enable_control

pytestmark = pytest.mark.django_db

#: The real interpreter (on Windows the venv python.exe is a launcher with a child).
PYTHON = getattr(sys, "_base_executable", sys.executable) or sys.executable
SLEEPER = "import time; time.sleep(120)"
PARENT = (
    "import subprocess, sys, time;"
    f"subprocess.Popen([sys.executable, '-c', {SLEEPER!r}]);"
    "time.sleep(120)"
)


@pytest.fixture
def spawned():
    procs: list[subprocess.Popen] = []

    def spawn(code: str) -> subprocess.Popen:
        proc = subprocess.Popen([PYTHON, "-c", code])
        procs.append(proc)
        return proc

    yield spawn
    for proc in procs:  # safety net: never leave test processes behind
        try:
            for child in psutil.Process(proc.pid).children(recursive=True):
                child.kill()
        except psutil.Error:
            pass
        if proc.poll() is None:
            proc.kill()
        proc.wait(10)


@pytest.fixture
def live(app, monkeypatch):
    enable_control(app, grace_seconds=5)
    monkeypatch.setattr(pc, "RUN_IN_BACKGROUND", False)
    os_ = PsutilProcessOs()
    monkeypatch.setattr(pc, "default_os", lambda: os_)
    return os_


def observe_real(machine, pid: int, port: int) -> ProcessInstance:
    real = psutil.Process(pid)
    info = pinfo(
        pid, real.name(), create_time=real.create_time(), username=real.username(), exe=real.exe()
    )
    result = scan_result([raw_tcp(port, pid)], [info])
    scan = begin_scan(machine, kind="native", trigger="t", provider="fake", scope=result.scope)
    apply_native_scan(machine, scan, result)
    return ProcessInstance.objects.get(pid=pid, active=True)


def expected_method() -> str:
    return "immediate" if sys.platform == "win32" else "graceful"


def test_stop_real_child_process(app, machine, live, spawned):
    child = spawned(SLEEPER)
    time.sleep(0.3)
    proc = observe_real(machine, child.pid, 39001)
    issued = pc.request_stop(proc.pk, actor="cli")
    assert issued["assessment"]["method"] == expected_method()
    op = pc.confirm_stop(issued["code"], pid=str(child.pid), actor="cli")
    assert op["outcome"] == "stopped", op
    assert child.wait(10) is not None
    event = Event.objects.get(type="process.stopped")
    assert event.details["method"] == expected_method() and event.details["actor"] == "cli"


def test_stop_real_process_tree_children_first(app, machine, live, spawned):
    parent = spawned(PARENT)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and not psutil.Process(parent.pid).children():
        time.sleep(0.1)
    descendants = psutil.Process(parent.pid).children(recursive=True)
    assert descendants
    proc = observe_real(machine, parent.pid, 39002)
    data = pc.preview(proc.pk, mode="tree")
    assert data["allowed"], data["reasons"]
    assert data["stop_order"][-1] == parent.pid
    assert set(data["stop_order"]) == {parent.pid, *(d.pid for d in descendants)}
    depths = [m["depth"] for m in data["members"]]
    assert depths == sorted(depths, reverse=True)  # children first
    op = pc.confirm_stop(pc.request_stop(proc.pk, mode="tree")["code"], pid=parent.pid)
    assert op["outcome"] == "stopped", op
    assert op["members"][-1]["pid"] == parent.pid
    assert parent.wait(10) is not None
    for d in descendants:
        assert not d.is_running()


def test_real_daemon_process_is_protected(app, machine, live):
    import os

    me = psutil.Process(os.getpid())
    result = scan_result(
        [raw_tcp(39003, me.pid)],
        [pinfo(me.pid, me.name(), create_time=me.create_time(), username=me.username())],
    )
    scan = begin_scan(machine, kind="native", trigger="t", provider="fake", scope=result.scope)
    apply_native_scan(machine, scan, result)
    proc = ProcessInstance.objects.get(pid=me.pid)
    data = pc.preview(proc.pk)
    assert not data["allowed"] and "PortRegistry daemon itself" in data["reasons"][0]


def test_identity_check_through_os_handle_rejects_wrong_create_time(spawned):
    from portregistry.services.process_os import IdentityChanged

    child = spawned(SLEEPER)
    time.sleep(0.2)
    real_ct = psutil.Process(child.pid).create_time()
    with pytest.raises(IdentityChanged):
        PsutilProcessOs().open(child.pid, real_ct - 5)
    handle = PsutilProcessOs().open(child.pid, real_ct)
    try:
        assert handle.wait(0) is False
    finally:
        handle.close()
