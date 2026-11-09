"""Plain data types shared by discovery providers, reconciliation and the conflict engine.

Nothing in this module touches Django, the network or the operating system.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class Family(StrEnum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"


class SocketState(StrEnum):
    LISTEN = "LISTEN"  # TCP listening socket
    BOUND = "BOUND"  # UDP socket bound to a local port (UDP has no LISTEN state)


class ScanStatus(StrEnum):
    RUNNING = "running"
    COMPLETE = "complete"  # socket enumeration was complete for the requested scope
    PARTIAL = "partial"  # enumeration incomplete (e.g. per-process fallback); not authoritative
    FAILED = "failed"


class IssueKind(StrEnum):
    ACCESS_DENIED = "access_denied"
    PROCESS_EXITED = "process_exited"
    ZOMBIE = "zombie"
    UNAVAILABLE = "unavailable"
    OWNER_UNKNOWN = "owner_unknown"
    ERROR = "error"


@dataclass(frozen=True)
class ScanScope:
    """What a scan was asked to observe. Absence is only authoritative inside the scope."""

    protocols: frozenset[Protocol] = frozenset({Protocol.TCP, Protocol.UDP})
    port: int | None = None

    def matches(self, protocol: str, port: int) -> bool:
        if Protocol(protocol) not in self.protocols:
            return False
        return self.port is None or self.port == port

    @property
    def is_full(self) -> bool:
        return self.port is None and self.protocols == frozenset({Protocol.TCP, Protocol.UDP})

    def describe(self) -> str:
        protos = ",".join(sorted(p.value for p in self.protocols))
        return protos if self.port is None else f"{protos} port {self.port}"

    def merge(self, other: ScanScope) -> ScanScope:
        """Smallest scope covering both (used when coalescing scan requests)."""
        port = self.port if self.port == other.port else None
        return ScanScope(protocols=self.protocols | other.protocols, port=port)

    @classmethod
    def build(cls, protocol: str | None = None, port: int | None = None) -> ScanScope:
        protocols = (
            frozenset({Protocol(protocol)}) if protocol else frozenset({Protocol.TCP, Protocol.UDP})
        )
        return cls(protocols=protocols, port=port)


@dataclass(frozen=True)
class RawSocket:
    """A normalized, locally bound endpoint as observed by a provider."""

    protocol: Protocol
    family: Family
    address: str
    port: int
    state: SocketState
    pid: int | None


@dataclass
class ProcessInfo:
    """Process metadata resolved for one PID during one scan.

    ``errors`` maps a field name to the reason it could not be read. Process
    environment variables are never collected.
    """

    pid: int
    name: str | None = None
    exe: str | None = None
    cmdline: list[str] | None = None
    username: str | None = None
    ppid: int | None = None
    cwd: str | None = None
    create_time: float | None = None
    exited: bool = False
    errors: dict[str, str] = field(default_factory=dict)
    project_name: str | None = None
    project_root: str | None = None

    @property
    def identity_complete(self) -> bool:
        return self.create_time is not None and not self.exited

    @property
    def restricted(self) -> bool:
        return any(reason == IssueKind.ACCESS_DENIED for reason in self.errors.values())


@dataclass(frozen=True)
class ProviderIssue:
    provider: str
    kind: IssueKind
    message: str
    pid: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "kind": self.kind.value,
            "message": self.message,
            "pid": self.pid,
        }


@dataclass
class NativeScanResult:
    """Result of one native discovery pass, produced without any database access."""

    provider: str
    scope: ScanScope
    started_at: datetime
    finished_at: datetime
    sockets: list[RawSocket] = field(default_factory=list)
    processes: dict[int, ProcessInfo] = field(default_factory=dict)
    # True when socket enumeration covered the whole scope (absence is authoritative).
    complete: bool = False
    # When the per-process fallback was used: PIDs whose sockets were fully enumerated.
    enumerated_pids: frozenset[int] | None = None
    issues: list[ProviderIssue] = field(default_factory=list)
    error: str | None = None

    @property
    def status(self) -> ScanStatus:
        if self.error is not None:
            return ScanStatus.FAILED
        return ScanStatus.COMPLETE if self.complete else ScanStatus.PARTIAL

    @property
    def duration_ms(self) -> int:
        return int((self.finished_at - self.started_at).total_seconds() * 1000)

    def is_absence_authoritative(self, protocol: str, port: int, pid: int | None) -> bool:
        """May a previously active socket that was not observed be marked absent?"""
        if self.error is not None or not self.scope.matches(protocol, port):
            return False
        if self.complete:
            return True
        return self.enumerated_pids is not None and pid is not None and pid in self.enumerated_pids


# --------------------------------------------------------------------------- Docker


@dataclass(frozen=True)
class DockerPortInfo:
    """One container port. ``host_port`` is None for exposed-but-unpublished ports."""

    container_port: int
    protocol: Protocol
    host_ip: str | None = None
    host_port: int | None = None

    @property
    def published(self) -> bool:
        return self.host_port is not None

    @property
    def key(self) -> str:
        return f"{self.container_port}/{self.protocol.value}|{self.host_ip or '-'}|{self.host_port or '-'}"


@dataclass(frozen=True)
class DockerImageInfo:
    image_id: str
    repository: str | None
    tag: str | None
    digest: str | None = None


@dataclass
class DockerContainerInfo:
    container_id: str
    name: str
    image: DockerImageInfo
    image_ref: str
    status: str
    created_at: datetime | None = None
    started_at: datetime | None = None
    labels: dict[str, str] = field(default_factory=dict)
    networks: dict[str, Any] = field(default_factory=dict)
    ports: list[DockerPortInfo] = field(default_factory=list)


@dataclass
class DockerInventoryResult:
    started_at: datetime
    finished_at: datetime
    available: bool
    containers: list[DockerContainerInfo] = field(default_factory=list)
    error: str | None = None
    server_version: str | None = None

    @property
    def status(self) -> ScanStatus:
        return ScanStatus.COMPLETE if self.available and self.error is None else ScanStatus.FAILED

    @property
    def duration_ms(self) -> int:
        return int((self.finished_at - self.started_at).total_seconds() * 1000)
