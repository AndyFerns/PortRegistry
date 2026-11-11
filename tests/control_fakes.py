"""Fake OS adapter and helpers for process-control tests (no real processes touched)."""

from __future__ import annotations

import dataclasses

from portregistry.config import ControlConfig
from portregistry.services.process_os import (
    AccessDenied,
    IdentityChanged,
    LiveProcess,
    ProcessGone,
)

ME = "alice"
DAEMON_PID = 900


class FakeOpened:
    def __init__(self, os_: FakeOs, pid: int) -> None:
        self.os, self.pid = os_, pid

    def send(self, method: str) -> None:
        self.os.sent.append((self.pid, method))
        behaviour = self.os.behaviour.get(self.pid, "exit")
        if behaviour == "exit" or (behaviour == "ignore" and method != "graceful"):
            self.os.alive.discard(self.pid)

    def wait(self, timeout: float) -> bool:
        return self.pid not in self.os.alive

    def close(self) -> None:
        self.os.closed.append(self.pid)


class FakeOs:
    def __init__(self, platform: str = "linux", elevated: bool = False) -> None:
        self.platform = platform
        self.elevated = elevated
        self.procs: dict[int, LiveProcess] = {}
        self.alive: set[int] = set()
        self.windows: set[int] = set()
        self.services: frozenset[int] = frozenset()
        self.behaviour: dict[int, str] = {}
        self.sent: list[tuple[int, str]] = []
        self.closed: list[int] = []
        # The daemon (pid 900) was started by a shell (pid 899).
        self.add(899, "bash", ppid=1, create_time=10.0)
        self.add(DAEMON_PID, "python", ppid=899, create_time=20.0)
        self.add(1, "systemd", user="root", uid=0, ppid=0, create_time=1.0)

    def add(
        self,
        pid: int,
        name: str,
        *,
        user: str | None = ME,
        uid: int | None = 1000,
        ppid: int | None = DAEMON_PID - 1,
        create_time: float = 1000.0,
        cmdline: tuple[str, ...] | None = None,
        cwd: str = "/srv",
    ) -> LiveProcess:
        proc = LiveProcess(
            pid=pid,
            create_time=create_time,
            name=name,
            exe=f"/usr/bin/{name}",
            cmdline=cmdline if cmdline is not None else (name, "--serve"),
            username=user,
            uid=uid,
            ppid=ppid,
            cwd=cwd,
        )
        self.procs[pid] = proc
        self.alive.add(pid)
        return proc

    def lookup(self, pid: int) -> LiveProcess | None:
        return self.procs.get(pid) if pid in self.alive else None

    def descendants(self, pid: int) -> list[int]:
        found: list[int] = []
        frontier = [pid]
        while frontier:
            parent = frontier.pop()
            for child in self.procs.values():
                if child.ppid == parent and child.pid in self.alive and child.pid != parent:
                    found.append(child.pid)
                    frontier.append(child.pid)
        return found

    def has_visible_window(self, pid: int) -> bool:
        return pid in self.windows

    def service_pids(self) -> frozenset[int]:
        return self.services

    def daemon_pid(self) -> int:
        return DAEMON_PID

    def is_elevated(self) -> bool | None:
        return self.elevated

    def open(self, pid: int, create_time: float) -> FakeOpened:
        if self.behaviour.get(pid) == "deny":
            raise AccessDenied(pid)
        live = self.lookup(pid)
        if live is None:
            raise ProcessGone(pid)
        if not live.matches(create_time):
            raise IdentityChanged(pid)
        return FakeOpened(self, pid)


def enable_control(app, *, allow_other_users: bool = False, elevated: bool = False, **kw):
    app.config = dataclasses.replace(
        app.config,
        control=ControlConfig(enabled=True, allow_other_users=allow_other_users, **kw),
    )
    app.platform_info = {"elevated": elevated}
    return app
