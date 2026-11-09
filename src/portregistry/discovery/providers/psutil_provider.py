"""psutil-based native discovery (primary provider on all platforms).

``psutil.net_connections()`` is used when permitted. On systems where it
requires elevated privileges (notably macOS for other users' processes), the
provider falls back to enumerating sockets process by process. That fallback is
inherently incomplete, so the scan is marked *partial* and only the PIDs whose
sockets were fully read are treated as authoritative for absence.

Privileges are never elevated automatically.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from types import ModuleType
from typing import Any

import psutil

from portregistry.core.types import (
    IssueKind,
    NativeScanResult,
    ProcessInfo,
    Protocol,
    ProviderIssue,
    ScanScope,
)
from portregistry.discovery.normalizer import normalize_connections
from portregistry.discovery.process_resolver import ProcessResolver
from portregistry.discovery.project import ProjectDetector

logger = logging.getLogger(__name__)

PROVIDER_NAME = "psutil"


@dataclass(frozen=True)
class _ConnWithPid:
    """Adapter giving per-process ``pconn`` tuples a ``pid`` attribute."""

    family: Any
    type: Any
    laddr: Any
    raddr: Any
    status: Any
    pid: int


def _kind_for(scope: ScanScope) -> str:
    if scope.protocols == frozenset({Protocol.TCP}):
        return "tcp"
    if scope.protocols == frozenset({Protocol.UDP}):
        return "udp"
    return "inet"


class PsutilProvider:
    name = PROVIDER_NAME

    def __init__(self, resolver: ProcessResolver, psutil_module: ModuleType | Any = psutil) -> None:
        self._ps = psutil_module
        self._resolver = resolver

    def _enumerate_per_process(
        self, kind: str, issues: list[ProviderIssue]
    ) -> tuple[list[Any], frozenset[int]]:
        ps = self._ps
        connections: list[Any] = []
        enumerated: set[int] = set()
        denied = 0
        for proc in ps.process_iter():
            pid = proc.pid
            try:
                conns = proc.net_connections(kind=kind)
            except ps.AccessDenied:
                denied += 1
                continue
            except (ps.NoSuchProcess, ps.ZombieProcess):
                continue
            except OSError as exc:
                issues.append(
                    ProviderIssue(PROVIDER_NAME, IssueKind.ERROR, f"pid {pid}: {exc}", pid)
                )
                continue
            enumerated.add(pid)
            for c in conns:
                connections.append(_ConnWithPid(c.family, c.type, c.laddr, c.raddr, c.status, pid))
        if denied:
            issues.append(
                ProviderIssue(
                    PROVIDER_NAME,
                    IssueKind.ACCESS_DENIED,
                    f"Socket list unavailable for {denied} processes (insufficient privileges); "
                    "their endpoints are not visible.",
                )
            )
        return connections, frozenset(enumerated)

    def scan(self, scope: ScanScope) -> NativeScanResult:
        ps = self._ps
        started = datetime.now(UTC)
        issues: list[ProviderIssue] = []
        kind = _kind_for(scope)
        enumerated_pids: frozenset[int] | None = None
        complete = True
        try:
            try:
                raw: Iterable[Any] = ps.net_connections(kind=kind)
            except ps.AccessDenied:
                logger.info(
                    "psutil.net_connections() requires elevated privileges here; "
                    "falling back to per-process enumeration (partial visibility)."
                )
                issues.append(
                    ProviderIssue(
                        PROVIDER_NAME,
                        IssueKind.ACCESS_DENIED,
                        "System-wide socket table is not readable without elevated privileges; "
                        "using per-process enumeration (partial scan).",
                    )
                )
                raw, enumerated_pids = self._enumerate_per_process(kind, issues)
                complete = False
            sockets = normalize_connections(raw, scope)
        except Exception as exc:  # unexpected provider failure: report, never crash
            logger.exception("Native discovery failed")
            return NativeScanResult(
                provider=PROVIDER_NAME,
                scope=scope,
                started_at=started,
                finished_at=datetime.now(UTC),
                complete=False,
                issues=issues,
                error=f"{exc.__class__.__name__}: {exc}",
            )

        processes: dict[int, ProcessInfo] = {}
        projects = ProjectDetector()  # per-scan cache of cwd -> project
        for pid in sorted({s.pid for s in sockets if s.pid is not None}):
            info = self._resolver.resolve(pid)
            project = projects.detect(info.cwd)
            if project is not None:
                info.project_name, info.project_root = project.name, project.root
            processes[pid] = info
            if info.exited:
                issues.append(
                    ProviderIssue(
                        PROVIDER_NAME,
                        IssueKind.PROCESS_EXITED,
                        f"Process {pid} exited during the scan; ownership is unresolved.",
                        pid,
                    )
                )
            elif info.errors:
                fields = ", ".join(sorted(info.errors))
                kinds = {v.split(":", 1)[0] for v in info.errors.values()}
                kind_value = (
                    IssueKind.ACCESS_DENIED
                    if IssueKind.ACCESS_DENIED.value in kinds
                    else IssueKind.UNAVAILABLE
                )
                issues.append(
                    ProviderIssue(
                        PROVIDER_NAME,
                        kind_value,
                        f"Process {pid}: metadata unavailable ({fields}).",
                        pid,
                    )
                )

        unknown = sum(1 for s in sockets if s.pid is None)
        if unknown:
            issues.append(
                ProviderIssue(
                    PROVIDER_NAME,
                    IssueKind.OWNER_UNKNOWN,
                    f"{unknown} endpoints have no owning PID reported by the OS "
                    "(often requires elevated privileges).",
                )
            )

        return NativeScanResult(
            provider=PROVIDER_NAME,
            scope=scope,
            started_at=started,
            finished_at=datetime.now(UTC),
            sockets=sockets,
            processes=processes,
            complete=complete,
            enumerated_pids=enumerated_pids,
            issues=issues,
        )
