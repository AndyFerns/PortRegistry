"""Scheduler, single-instance lock and event bus (no database)."""

import asyncio
import os
import subprocess
import sys
import threading
import time

import psutil
import pytest

from portregistry.core.events import EventBus
from portregistry.core.types import Protocol
from portregistry.daemon.lock import (
    DaemonLock,
    current_process_state,
    read_state,
    state_process_alive,
)
from portregistry.daemon.scheduler import Scheduler
from portregistry.exceptions import DaemonAlreadyRunningError

# ------------------------------------------------------------------- scheduler


class Summary:
    def __init__(self, scan_id):
        self.scan_id = scan_id

    def as_dict(self):
        return {"scan_id": self.scan_id}


def test_manual_requests_coalesce_while_pending():
    sched = Scheduler(native_runner=lambda s, t: Summary(1), native_interval=3600)
    first = sched.request_native_scan("tcp", None)
    second = sched.request_native_scan("udp", None)
    third = sched.request_native_scan(None, 8080)
    assert first is second is third
    assert first.coalesced == 2
    assert first.scope.protocols == frozenset({Protocol.TCP, Protocol.UDP})
    assert first.scope.port is None


def test_scheduler_runs_jobs_serially_and_never_overlaps():
    running = threading.Lock()
    overlaps = []
    calls = []

    def runner(scope, trigger):
        if not running.acquire(blocking=False):
            overlaps.append(trigger)
            return None
        try:
            calls.append(trigger)
            time.sleep(0.05)
            return Summary(len(calls))
        finally:
            running.release()

    sched = Scheduler(native_runner=runner, native_interval=0.1)
    sched.start()
    try:
        tickets = [sched.request_native_scan(None, None) for _ in range(5)]
        assert sched.wait_for(tickets[-1], 5)
        time.sleep(0.4)  # let a few scheduled scans run too
    finally:
        assert sched.stop(5)
    assert not overlaps
    assert "manual" in calls and "scheduled" in calls
    assert tickets[-1].status == "done" and tickets[-1].scan_id is not None


def test_failed_job_does_not_kill_scheduler():
    attempts = []

    def runner(scope, trigger):
        attempts.append(trigger)
        if len(attempts) == 1:
            raise RuntimeError("provider exploded")
        return Summary(2)

    sched = Scheduler(native_runner=runner, native_interval=3600)
    sched.start()
    try:
        t1 = sched.request_native_scan()
        assert sched.wait_for(t1, 5)
        assert t1.status == "failed" and "exploded" in t1.error
        t2 = sched.request_native_scan()
        assert sched.wait_for(t2, 5)
        assert t2.status == "done"
    finally:
        sched.stop(5)


def test_docker_refresh_requests_are_debounced():
    docker_calls = []
    sched = Scheduler(
        native_runner=lambda s, t: Summary(1),
        native_interval=3600,
        docker_runner=lambda reason: docker_calls.append(reason),
        docker_interval=3600,
    )
    sched.start()
    try:
        for _ in range(10):
            sched.request_docker_refresh("docker-event:start")
        time.sleep(1.6)
    finally:
        sched.stop(5)
    assert docker_calls == ["docker-event:start"]


def test_stop_skips_pending_requests():
    sched = Scheduler(native_runner=lambda s, t: Summary(1), native_interval=3600)
    ticket = sched.request_native_scan()
    sched.stop()
    assert ticket.status == "skipped"
    assert sched.request_native_scan().status == "skipped"


# ------------------------------------------------------------------------ lock


def test_lock_prevents_second_instance(tmp_path):
    first = DaemonLock(tmp_path / "daemon.lock", tmp_path / "daemon.json")
    first.acquire()
    first.write_state(current_process_state("127.0.0.1", 8765, "test"))
    second = DaemonLock(tmp_path / "daemon.lock", tmp_path / "daemon.json")
    with pytest.raises(DaemonAlreadyRunningError, match="already running"):
        second.acquire()
    first.release()
    assert read_state(tmp_path / "daemon.json") is None
    second.acquire()  # lock is free again
    second.release()


def test_stale_state_file_is_ignored_and_replaced(tmp_path):
    state_path = tmp_path / "daemon.json"
    state_path.write_text(
        f'{{"pid": {os.getpid()}, "create_time": 1.0, "host": "127.0.0.1", "port": 1}}'
    )
    assert not state_process_alive(read_state(state_path))  # same PID, wrong creation time
    lock = DaemonLock(tmp_path / "daemon.lock", state_path)
    lock.acquire()
    assert read_state(state_path) is None
    lock.release()


def test_current_process_state_is_alive():
    assert state_process_alive(current_process_state("127.0.0.1", 1, "x"))


@pytest.mark.skipif(sys.platform == "win32", reason="zombie processes are POSIX-only")
def test_exited_unreaped_child_is_not_alive():
    """A daemon that exited but was not yet reaped by its parent must count as stopped."""
    child = subprocess.Popen([sys.executable, "-c", "pass"])
    proc = psutil.Process(child.pid)
    state = {"pid": child.pid, "create_time": proc.create_time()}
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            if proc.status() == psutil.STATUS_ZOMBIE:
                break
        except psutil.NoSuchProcess:
            break
        time.sleep(0.05)
    assert not state_process_alive(state)
    child.poll()  # already reaped by state_process_alive; must not raise


# ------------------------------------------------------------------- event bus


def test_event_bus_delivers_and_closes():
    async def scenario():
        bus = EventBus()
        sub = bus.subscribe()
        thread = threading.Thread(target=lambda: bus.publish("ports", "ports.changed", {"n": 1}))
        thread.start()
        thread.join()
        event = await sub.get(1)
        assert event.topic == "ports" and event.data == {"n": 1}
        assert await sub.get(0.05) == "timeout"
        bus.close()
        assert await sub.get(1) is None
        assert bus.closed

    asyncio.run(scenario())


def test_event_bus_overflow_marks_subscriber():
    async def scenario():
        bus = EventBus(queue_size=2)
        sub = bus.subscribe()
        for i in range(5):
            bus.publish("scan", "scan.completed", {"i": i})
        await asyncio.sleep(0.01)
        assert sub.overflowed
        bus.close()
        # Shutdown sentinel still gets through a full queue.
        items = []
        for _ in range(3):
            item = await sub.get(1)
            items.append(item)
            if item is None:
                break
        assert items[-1] is None

    asyncio.run(scenario())
