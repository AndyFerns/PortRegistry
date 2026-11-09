"""Deterministic fakes for psutil and Docker used across the test-suite."""

from __future__ import annotations

import socket
from collections import namedtuple
from contextlib import contextmanager
from typing import Any

import psutil

Addr = namedtuple("Addr", "ip port")
SConn = namedtuple("SConn", "fd family type laddr raddr status pid")
PConn = namedtuple("PConn", "fd family type laddr raddr status")


def tcp_listen(ip: str, port: int, pid: int | None, family: int = socket.AF_INET) -> SConn:
    return SConn(-1, family, socket.SOCK_STREAM, Addr(ip, port), (), "LISTEN", pid)


def tcp_established(ip: str, port: int, pid: int | None) -> SConn:
    return SConn(
        -1,
        socket.AF_INET,
        socket.SOCK_STREAM,
        Addr(ip, port),
        Addr("1.2.3.4", 443),
        "ESTABLISHED",
        pid,
    )


def udp_bound(ip: str, port: int, pid: int | None, family: int = socket.AF_INET) -> SConn:
    return SConn(-1, family, socket.SOCK_DGRAM, Addr(ip, port), (), "NONE", pid)


class FakeProcess:
    """Mimics psutil.Process. ``fields`` values may be exceptions to raise."""

    def __init__(self, pid: int, fields: dict[str, Any], connections: Any = None) -> None:
        self.pid = pid
        self._fields = fields
        self._connections = connections

    @contextmanager
    def oneshot(self):
        yield

    def _get(self, name: str) -> Any:
        value = self._fields.get(name)
        if isinstance(value, BaseException):
            raise value
        if isinstance(value, type) and issubclass(value, BaseException):
            raise value(self.pid)
        return value

    def create_time(self) -> float:
        return self._get("create_time")

    def name(self) -> str:
        return self._get("name")

    def exe(self) -> str:
        return self._get("exe")

    def ppid(self) -> int:
        return self._get("ppid")

    def username(self) -> str:
        return self._get("username")

    def cmdline(self) -> list[str]:
        return self._get("cmdline")

    def cwd(self) -> str:
        return self._get("cwd")

    def environ(self) -> dict[str, str]:  # pragma: no cover - must never be called
        raise AssertionError("PortRegistry must never read process environment variables")

    def net_connections(self, kind: str = "inet") -> list[PConn]:
        if isinstance(self._connections, BaseException):
            raise self._connections
        return list(self._connections or [])


class FakePsutil:
    """Module-like fake exposing the subset of psutil used by the provider."""

    AccessDenied = psutil.AccessDenied
    NoSuchProcess = psutil.NoSuchProcess
    ZombieProcess = psutil.ZombieProcess

    def __init__(
        self,
        connections: list[SConn] | BaseException,
        processes: dict[int, dict[str, Any]] | None = None,
        per_process_connections: dict[int, Any] | None = None,
    ) -> None:
        self._connections = connections
        self._processes = processes or {}
        self._per_process = per_process_connections or {}
        self.environ_calls = 0

    def net_connections(self, kind: str = "inet") -> list[SConn]:
        if isinstance(self._connections, BaseException):
            raise self._connections
        return list(self._connections)

    def Process(self, pid: int) -> FakeProcess:  # noqa: N802 - mirrors psutil API
        if pid not in self._processes:
            raise psutil.NoSuchProcess(pid)
        return FakeProcess(pid, self._processes[pid], self._per_process.get(pid))

    def process_iter(self):
        pids = sorted(set(self._processes) | set(self._per_process))
        for pid in pids:
            yield FakeProcess(pid, self._processes.get(pid, {}), self._per_process.get(pid))


def proc_fields(
    name: str = "server",
    create_time: float = 1_700_000_000.123,
    exe: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "name": name,
        "create_time": create_time,
        "exe": exe or f"/usr/bin/{name}",
        "ppid": 1,
        "username": "tester",
        "cmdline": [name, "--serve"],
        "cwd": "/srv",
    }
    fields.update(extra)
    return fields
