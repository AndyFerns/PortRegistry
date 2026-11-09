"""Resolve process metadata for a PID with per-field partial-failure handling.

Each field is read independently so that one ``AccessDenied`` does not hide the
fields that are readable. A process that exits while being inspected is
recorded as ``exited`` rather than raising. Environment variables are never
read, and command lines are never executed.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from types import ModuleType
from typing import Any

import psutil

from portregistry.core.types import IssueKind, ProcessInfo

logger = logging.getLogger(__name__)

MAX_CMDLINE_ARGS = 64
MAX_ARG_LENGTH = 1024
MAX_CMDLINE_TOTAL = 4096


def _truncate_cmdline(cmdline: list[str]) -> list[str]:
    result: list[str] = []
    total = 0
    for arg in cmdline[:MAX_CMDLINE_ARGS]:
        arg = str(arg)[:MAX_ARG_LENGTH]
        if total + len(arg) > MAX_CMDLINE_TOTAL:
            result.append("…")
            break
        result.append(arg)
        total += len(arg)
    if len(cmdline) > MAX_CMDLINE_ARGS and (not result or result[-1] != "…"):
        result.append("…")
    return result


class ProcessResolver:
    def __init__(
        self,
        *,
        collect_cmdline: bool = True,
        collect_username: bool = True,
        collect_cwd: bool = True,
        psutil_module: ModuleType | Any = psutil,
    ) -> None:
        self._ps = psutil_module
        self._collect_cmdline = collect_cmdline
        self._collect_username = collect_username
        self._collect_cwd = collect_cwd

    def _read(self, info: ProcessInfo, field: str, getter: Callable[[], Any]) -> Any:
        ps = self._ps
        try:
            return getter()
        except ps.ZombieProcess:
            info.errors[field] = IssueKind.ZOMBIE.value
        except ps.NoSuchProcess:
            info.exited = True
            info.errors[field] = IssueKind.PROCESS_EXITED.value
        except ps.AccessDenied:
            info.errors[field] = IssueKind.ACCESS_DENIED.value
        except (OSError, ValueError, RuntimeError) as exc:
            info.errors[field] = f"{IssueKind.UNAVAILABLE.value}: {exc.__class__.__name__}"
        return None

    def _read_fields(self, info: ProcessInfo, proc: Any) -> None:
        info.create_time = self._read(info, "create_time", proc.create_time)
        info.name = self._read(info, "name", proc.name)
        if info.exited:
            return
        info.exe = self._read(info, "exe", proc.exe) or None
        info.ppid = self._read(info, "ppid", proc.ppid)
        if self._collect_username:
            info.username = self._read(info, "username", proc.username)
        if self._collect_cmdline:
            cmdline = self._read(info, "cmdline", proc.cmdline)
            if cmdline is not None:
                info.cmdline = _truncate_cmdline(list(cmdline))
        if self._collect_cwd:
            info.cwd = self._read(info, "cwd", proc.cwd) or None

    def resolve(self, pid: int) -> ProcessInfo:
        info = ProcessInfo(pid=pid)
        ps = self._ps
        try:
            proc = ps.Process(pid)
        except ps.NoSuchProcess:
            info.exited = True
            info.errors["process"] = IssueKind.PROCESS_EXITED.value
            return info
        except ps.AccessDenied:
            info.errors["process"] = IssueKind.ACCESS_DENIED.value
            return info
        except (OSError, ValueError) as exc:
            info.errors["process"] = f"{IssueKind.UNAVAILABLE.value}: {exc.__class__.__name__}"
            return info

        try:
            ctx = proc.oneshot()
            ctx.__enter__()
        except Exception:  # pragma: no cover - oneshot is an optimisation only
            ctx = None
        try:
            self._read_fields(info, proc)
        finally:
            if ctx is not None:
                try:
                    ctx.__exit__(None, None, None)
                except Exception:  # pragma: no cover
                    pass
        if info.exited:
            # Never attach metadata from a process that vanished mid-read to a
            # stable identity: creation time may belong to a reused PID.
            info.create_time = None
        return info
