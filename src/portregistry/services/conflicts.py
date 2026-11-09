"""Conflict engine: pure functions over an immutable snapshot.

No Django, network or OS access happens here, so the engine is testable in
isolation. :mod:`portregistry.services.conflict_store` builds snapshots from the
database and persists findings.

Conflict types
--------------
``occupied_reservation``
    An active reservation's endpoint is bound by something whose ownership is
    either not associated with a service or cannot be verified.
``service_mismatch``
    The reservation belongs to a service with an expected executable / working
    directory / container, and the observed owner does not match it.
``overlapping_reservation``
    Two active reservations overlap (same protocol and port, overlapping bind
    addresses). Exact duplicates are titled "Duplicate reservation".
``unregistered_listener``
    An observed endpoint is not covered by any reservation (informational).
``missing_expected_service``
    A service's reservation has no observed listener. Only *definite* after a
    complete, fresh scan of that protocol; otherwise *potential*.
``incomplete_discovery``
    The last scan failed, was partial or is stale; owners are unresolved; or
    Docker discovery is unavailable. Absence is never reported as certain then.

Every finding carries severity (error/warning/info), certainty
(definite/potential), a title, an explanation and structured evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from portregistry.core.addresses import (
    ANY_ADDRESS,
    Overlap,
    OverlapResult,
    endpoint_overlap,
    format_endpoint,
)


class ConflictType(StrEnum):
    OCCUPIED_RESERVATION = "occupied_reservation"
    SERVICE_MISMATCH = "service_mismatch"
    OVERLAPPING_RESERVATION = "overlapping_reservation"
    UNREGISTERED_LISTENER = "unregistered_listener"
    MISSING_EXPECTED_SERVICE = "missing_expected_service"
    INCOMPLETE_DISCOVERY = "incomplete_discovery"


SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}

DOCKER_PREFIX = "docker:"
#: Host processes that hold published Docker ports on behalf of containers.
DOCKER_PROXY_NAMES = frozenset(
    {
        "docker-proxy",
        "dockerd",
        "rootlesskit",
        "com.docker.backend",
        "com.docker.vpnkit",
        "vpnkit",
        "vpnkit-bridge",
        "wslrelay",
    }
)


# --------------------------------------------------------------------- snapshot


@dataclass(frozen=True)
class SocketView:
    id: int
    protocol: str
    family: str
    address: str
    port: int
    pid: int | None = None
    process_id: int | None = None
    process_name: str | None = None
    exe: str | None = None
    cwd: str | None = None
    metadata_restricted: bool = False

    @property
    def owner_label(self) -> str:
        if self.process_name:
            return f"{self.process_name} (pid {self.pid})"
        if self.pid is not None:
            return f"pid {self.pid} (process metadata unavailable)"
        return "an unknown process (owner not reported by the OS)"

    @property
    def endpoint(self) -> str:
        return format_endpoint(self.protocol, self.address, self.port)


@dataclass(frozen=True)
class ReservationView:
    id: int
    protocol: str
    bind_address: str
    port: int
    service_id: int | None = None
    description: str = ""

    @property
    def endpoint(self) -> str:
        return format_endpoint(self.protocol, self.bind_address, self.port)

    @property
    def label(self) -> str:
        if self.id:
            return f"reservation #{self.id} ({self.endpoint})"
        return f"the proposed reservation ({self.endpoint})"


@dataclass(frozen=True)
class ServiceView:
    id: int
    name: str
    expected_executable: str = ""
    expected_working_directory: str = ""

    @property
    def has_expectations(self) -> bool:
        return bool(self.expected_executable.strip() or self.expected_working_directory.strip())


@dataclass(frozen=True)
class DockerMappingView:
    id: int
    container_db_id: int
    container_id: str
    container_name: str
    image_ref: str
    protocol: str
    host_ip: str
    host_port: int
    container_port: int

    @property
    def label(self) -> str:
        host = self.host_ip or "0.0.0.0"
        return (
            f"container {self.container_name} ({self.image_ref}) publishing "
            f"{format_endpoint(self.protocol, host, self.host_port)} -> "
            f"{self.container_port}/{self.protocol}"
        )


@dataclass(frozen=True)
class DiscoveryView:
    native_status: str | None = None  # complete | partial | failed | None (never ran)
    native_message: str = ""
    complete_protocols: frozenset[str] = frozenset()
    last_complete_age: float | None = None  # seconds since last complete full scan
    stale_after: float = 35.0
    unknown_owner_count: int = 0
    restricted_process_count: int = 0
    docker_enabled: bool = False
    docker_state: str = "disabled"  # ok | degraded | unavailable | disabled | unknown
    docker_message: str = ""

    @property
    def stale(self) -> bool:
        return self.last_complete_age is None or self.last_complete_age > self.stale_after

    def protocol_authoritative(self, protocol: str) -> bool:
        return not self.stale and protocol in self.complete_protocols

    @property
    def docker_reliable(self) -> bool:
        return not self.docker_enabled or self.docker_state == "ok"


@dataclass
class Snapshot:
    sockets: list[SocketView] = field(default_factory=list)
    reservations: list[ReservationView] = field(default_factory=list)
    services: dict[int, ServiceView] = field(default_factory=dict)
    docker_mappings: list[DockerMappingView] = field(default_factory=list)
    discovery: DiscoveryView = field(default_factory=DiscoveryView)


@dataclass(frozen=True)
class Finding:
    fingerprint: str
    type: ConflictType
    severity: str
    certainty: str
    title: str
    explanation: str
    evidence: dict[str, Any] = field(default_factory=dict)
    protocol: str = ""
    port: int | None = None
    address: str = ""
    reservation_id: int | None = None
    related_reservation_id: int | None = None
    service_id: int | None = None
    socket_id: int | None = None
    process_id: int | None = None

    def sort_key(self) -> tuple[int, str, int, str]:
        return (
            SEVERITY_ORDER.get(self.severity, 9),
            self.type.value,
            self.port or 0,
            self.fingerprint,
        )


# --------------------------------------------------------------------- matching


def _norm_path(path: str) -> str:
    return path.strip().replace("\\", "/").rstrip("/").lower()


def _base(name: str) -> str:
    base = _norm_path(name).rsplit("/", 1)[-1]
    return base[:-4] if base.endswith(".exe") else base


def executable_matches(expected: str, exe: str | None, name: str | None) -> bool | None:
    """Does an observed process match the expected executable?

    Returns None when it cannot be determined (no expectation, or metadata
    unavailable). Full paths are compared when the expectation contains a path
    separator; otherwise base names are compared. Comparison is
    case-insensitive and ignores a trailing ``.exe``.
    """
    expected = expected.strip()
    if not expected or expected.lower().startswith(DOCKER_PREFIX):
        return None
    if "/" in expected or "\\" in expected:
        if exe:
            return _norm_path(expected) == _norm_path(exe)
        if name and _base(name) != _base(expected):
            return False
        return None
    candidates = {_base(v) for v in (exe, name) if v}
    if not candidates:
        return None
    return _base(expected) in candidates


def directory_matches(expected: str, cwd: str | None) -> bool | None:
    expected = expected.strip()
    if not expected or not cwd:
        return None
    return _norm_path(expected) == _norm_path(cwd)


def _docker_expectation(service: ServiceView) -> str | None:
    value = service.expected_executable.strip()
    if value.lower().startswith(DOCKER_PREFIX):
        return value[len(DOCKER_PREFIX) :].strip().lower() or None
    return None


def docker_mapping_matches(service: ServiceView, mapping: DockerMappingView) -> bool | None:
    """Match a service against a container publishing the reserved port."""
    wanted = _docker_expectation(service)
    image_repo = mapping.image_ref.rsplit(":", 1)[0].lower() if mapping.image_ref else ""
    names = {
        mapping.container_name.lower(),
        mapping.container_id[:12].lower(),
        mapping.image_ref.lower(),
        image_repo,
        image_repo.rsplit("/", 1)[-1],
    } - {""}
    if wanted is not None:
        return wanted in names
    if service.expected_executable.strip():
        # Native expectation: accept a container whose name/image matches the program name.
        return _base(service.expected_executable) in names
    return None


def is_docker_proxy(sock: SocketView) -> bool:
    for value in (sock.process_name, sock.exe):
        if value and _base(value) in DOCKER_PROXY_NAMES:
            return True
    return False


def match_service_socket(
    service: ServiceView, sock: SocketView, docker_matches: bool
) -> tuple[bool | None, list[str]]:
    """Combine executable / working-directory / docker expectations for one socket."""
    reasons: list[str] = []
    if _docker_expectation(service) is not None:
        if is_docker_proxy(sock):
            if docker_matches:
                return True, ["socket is held by the Docker port proxy for the expected container"]
            return None, ["socket is held by a Docker port proxy; container not identified"]
        reasons.append(
            f"expected container '{service.expected_executable}' but the endpoint is owned by "
            f"{sock.owner_label}"
        )
        return False, reasons

    exe_result = executable_matches(service.expected_executable, sock.exe, sock.process_name)
    dir_result = directory_matches(service.expected_working_directory, sock.cwd)
    if service.expected_executable.strip():
        if exe_result is False:
            reasons.append(
                f"expected executable '{service.expected_executable}', observed "
                f"'{sock.exe or sock.process_name or 'unknown'}'"
            )
        elif exe_result is None:
            reasons.append("executable of the owning process could not be read")
    if service.expected_working_directory.strip():
        if dir_result is False:
            reasons.append(
                f"expected working directory '{service.expected_working_directory}', "
                f"observed '{sock.cwd}'"
            )
        elif dir_result is None:
            reasons.append("working directory of the owning process could not be read")
    if exe_result is False or dir_result is False:
        return False, reasons
    if exe_result is True or dir_result is True:
        return True, reasons
    return None, reasons


# ----------------------------------------------------------------------- engine


def _certainty(levels: list[Overlap]) -> str:
    return "definite" if Overlap.DEFINITE in levels else "potential"


def _cap(text: str) -> str:
    return text[:1].upper() + text[1:]


def _unique(items: Any) -> list[str]:
    """De-duplicate while preserving order (IPv4 and IPv6 sockets often repeat reasons)."""
    return list(dict.fromkeys(items))


def _occupant_evidence(sock: SocketView, ov: OverlapResult) -> dict[str, Any]:
    return {
        "kind": "socket",
        "socket_id": sock.id,
        "endpoint": sock.endpoint,
        "pid": sock.pid,
        "process_id": sock.process_id,
        "process": sock.process_name,
        "exe": sock.exe,
        "overlap": ov.level.value,
        "overlap_reason": ov.reason,
    }


def _docker_evidence(mapping: DockerMappingView, ov: OverlapResult) -> dict[str, Any]:
    return {
        "kind": "docker",
        "container_id": mapping.container_id[:12],
        "container": mapping.container_name,
        "image": mapping.image_ref,
        "host": format_endpoint(mapping.protocol, mapping.host_ip or "0.0.0.0", mapping.host_port),
        "container_port": f"{mapping.container_port}/{mapping.protocol}",
        "overlap": ov.level.value,
        "overlap_reason": ov.reason,
    }


def reservation_findings(
    res: ReservationView,
    snap: Snapshot,
) -> list[Finding]:
    findings: list[Finding] = []
    sock_occ = [
        (s, ov)
        for s in snap.sockets
        if (
            ov := endpoint_overlap(
                res.protocol, res.bind_address, res.port, s.protocol, s.address, s.port
            )
        )
    ]
    dock_occ = [
        (m, ov)
        for m in snap.docker_mappings
        if (
            ov := endpoint_overlap(
                res.protocol,
                res.bind_address,
                res.port,
                m.protocol,
                m.host_ip or "0.0.0.0",
                m.host_port,
            )
        )
    ]
    service = snap.services.get(res.service_id) if res.service_id is not None else None
    common: dict[str, Any] = {
        "protocol": res.protocol,
        "port": res.port,
        "address": res.bind_address,
        "reservation_id": res.id or None,
        "service_id": service.id if service else None,
    }

    if not sock_occ and not dock_occ:
        if service is not None:
            findings.append(_missing_service_finding(res, service, snap.discovery, common))
        return findings

    def _potential(ov: OverlapResult) -> str:
        return " (potential: dual-stack)" if ov.level is Overlap.POTENTIAL else ""

    occupants_desc = [f"{s.owner_label} on {s.endpoint}{_potential(ov)}" for s, ov in sock_occ] + [
        f"{m.label}{_potential(ov)}" for m, ov in dock_occ
    ]
    evidence_occupants = [_occupant_evidence(s, ov) for s, ov in sock_occ] + [
        _docker_evidence(m, ov) for m, ov in dock_occ
    ]
    first_sock = sock_occ[0][0] if sock_occ else None
    common["socket_id"] = first_sock.id if first_sock else None
    common["process_id"] = first_sock.process_id if first_sock else None
    advisory = "Reservations are advisory: PortRegistry does not stop other programs from binding."

    if service is None:
        levels = [ov.level for _, ov in sock_occ] + [ov.level for _, ov in dock_occ]
        certainty = _certainty(levels)
        potential_note = (
            ""
            if certainty == "definite"
            else " The overlap depends on IPv6 dual-stack settings, so it may not be a real clash."
        )
        findings.append(
            Finding(
                fingerprint=f"occupied:{res.id}",
                type=ConflictType.OCCUPIED_RESERVATION,
                severity="warning",
                certainty=certainty,
                title=f"Reserved {res.endpoint} is in use",
                explanation=(
                    f"{_cap(res.label)} has no associated service, but the endpoint is "
                    f"currently bound by {'; '.join(occupants_desc)}.{potential_note} {advisory}"
                ),
                evidence={"reservation": res.endpoint, "occupants": evidence_occupants},
                **common,
            )
        )
        return findings

    docker_any_match = any(docker_mapping_matches(service, m) for m, _ in dock_occ)
    mismatches: list[tuple[dict[str, Any], Overlap, list[str]]] = []
    unverifiable: list[tuple[dict[str, Any], Overlap, list[str]]] = []
    for sock, ov in sock_occ:
        result, reasons = match_service_socket(service, sock, docker_any_match)
        if result is False:
            mismatches.append((_occupant_evidence(sock, ov), ov.level, reasons))
        elif result is None:
            unverifiable.append((_occupant_evidence(sock, ov), ov.level, reasons))
    for mapping, ov in dock_occ:
        result = docker_mapping_matches(service, mapping)
        if result is False:
            mismatches.append(
                (
                    _docker_evidence(mapping, ov),
                    ov.level,
                    [f"published by {mapping.label}, which does not match the service"],
                )
            )
        elif result is None:
            unverifiable.append(
                (_docker_evidence(mapping, ov), ov.level, [f"published by {mapping.label}"])
            )

    expected = {
        "expected_executable": service.expected_executable or None,
        "expected_working_directory": service.expected_working_directory or None,
    }
    if mismatches:
        certainty = _certainty([lvl for _, lvl, _ in mismatches])
        reason_text = "; ".join(_unique(r for _, _, rs in mismatches for r in rs))
        findings.append(
            Finding(
                fingerprint=f"mismatch:{res.id}",
                type=ConflictType.SERVICE_MISMATCH,
                severity="error" if certainty == "definite" else "warning",
                certainty=certainty,
                title=f"{res.endpoint} is not owned by service '{service.name}'",
                explanation=(
                    f"{_cap(res.label)} belongs to service '{service.name}', but the "
                    f"observed owner does not match: {reason_text}. {advisory}"
                ),
                evidence={
                    "service": service.name,
                    **expected,
                    "observed": [e for e, _, _ in mismatches],
                },
                **common,
            )
        )
    elif unverifiable:
        certainty = _certainty([lvl for _, lvl, _ in unverifiable])
        if service.has_expectations or _docker_expectation(service):
            severity = "warning"
            explanation = (
                f"{_cap(res.label)} belongs to service '{service.name}' and is in use, but "
                f"ownership could not be verified: "
                f"{'; '.join(_unique(r for _, _, rs in unverifiable for r in rs))}. This usually means "
                "process metadata is restricted by OS permissions."
            )
            certainty = "potential"
        else:
            severity = "info"
            explanation = (
                f"{_cap(res.label)} belongs to service '{service.name}' and is in use by "
                f"{'; '.join(occupants_desc)}. The service has no expected executable or working "
                "directory, so PortRegistry cannot tell whether this is the right program. "
                "Add an expected executable to enable verification."
            )
        findings.append(
            Finding(
                fingerprint=f"occupied:{res.id}",
                type=ConflictType.OCCUPIED_RESERVATION,
                severity=severity,
                certainty=certainty,
                title=f"Ownership of {res.endpoint} not verified for '{service.name}'",
                explanation=explanation,
                evidence={
                    "service": service.name,
                    **expected,
                    "occupants": [e for e, _, _ in unverifiable],
                },
                **common,
            )
        )
    return findings


def _missing_service_finding(
    res: ReservationView,
    service: ServiceView,
    discovery: DiscoveryView,
    common: dict[str, Any],
) -> Finding:
    wants_docker = _docker_expectation(service) is not None
    authoritative = discovery.protocol_authoritative(res.protocol) and (
        not wants_docker or discovery.docker_reliable
    )
    if authoritative:
        return Finding(
            fingerprint=f"missing:{res.id}",
            type=ConflictType.MISSING_EXPECTED_SERVICE,
            severity="warning",
            certainty="definite",
            title=f"Service '{service.name}' is not listening on {res.endpoint}",
            explanation=(
                f"{_cap(res.label)} belongs to service '{service.name}', but no "
                f"{res.protocol.upper()} endpoint overlapping it was observed in the latest "
                "complete discovery scan."
            ),
            evidence={"service": service.name, "reservation": res.endpoint},
            **common,
        )
    why = []
    if discovery.native_status is None:
        why.append("no discovery scan has completed yet")
    elif discovery.stale:
        why.append("discovery data is stale")
    elif res.protocol not in discovery.complete_protocols:
        why.append(f"the last {res.protocol.upper()} scan was {discovery.native_status}")
    if wants_docker and not discovery.docker_reliable:
        why.append(f"Docker discovery is {discovery.docker_state}")
    return Finding(
        fingerprint=f"missing:{res.id}",
        type=ConflictType.MISSING_EXPECTED_SERVICE,
        severity="info",
        certainty="potential",
        title=f"Service '{service.name}' may not be listening on {res.endpoint}",
        explanation=(
            f"No listener was observed for {res.label}, but absence is not certain because "
            f"{' and '.join(why) or 'discovery was incomplete'}."
        ),
        evidence={"service": service.name, "reservation": res.endpoint, "reasons": why},
        **common,
    )


def overlap_findings(reservations: list[ReservationView]) -> list[Finding]:
    findings: list[Finding] = []
    ordered = sorted(reservations, key=lambda r: r.id)
    for i, a in enumerate(ordered):
        for b in ordered[i + 1 :]:
            ov = endpoint_overlap(
                a.protocol, a.bind_address, a.port, b.protocol, b.bind_address, b.port
            )
            if not ov:
                continue
            duplicate = a.bind_address == b.bind_address and a.service_id == b.service_id
            same_service = a.service_id is not None and a.service_id == b.service_id
            if duplicate:
                title = f"Duplicate reservation for {a.endpoint}"
                severity = "warning"
            elif same_service:
                title = f"Redundant reservations for {a.endpoint} and {b.endpoint}"
                severity = "info"
            else:
                title = f"Overlapping reservations {a.endpoint} and {b.endpoint}"
                severity = "warning" if ov.level is Overlap.DEFINITE else "info"
            findings.append(
                Finding(
                    fingerprint=f"overlap:{a.id}:{b.id}",
                    type=ConflictType.OVERLAPPING_RESERVATION,
                    severity=severity,
                    certainty="definite" if ov.level is Overlap.DEFINITE else "potential",
                    title=title,
                    explanation=(
                        f"{_cap(a.label)} and {b.label} claim overlapping endpoints: {ov.reason}."
                    ),
                    evidence={
                        "reservations": [
                            {"id": a.id, "endpoint": a.endpoint, "service_id": a.service_id},
                            {"id": b.id, "endpoint": b.endpoint, "service_id": b.service_id},
                        ],
                        "overlap": ov.level.value,
                        "duplicate": duplicate,
                    },
                    protocol=a.protocol,
                    port=a.port,
                    address=a.bind_address,
                    reservation_id=a.id or None,
                    related_reservation_id=b.id or None,
                    service_id=a.service_id,
                )
            )
    return findings


def unregistered_findings(snap: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    for sock in snap.sockets:
        covered = any(
            endpoint_overlap(
                r.protocol, r.bind_address, r.port, sock.protocol, sock.address, sock.port
            )
            for r in snap.reservations
        )
        if covered:
            continue
        verb = "listening on" if sock.protocol == "tcp" else "bound to"
        findings.append(
            Finding(
                fingerprint=f"unregistered:socket:{sock.id}",
                type=ConflictType.UNREGISTERED_LISTENER,
                severity="info",
                certainty="definite",
                title=f"Unregistered listener {sock.endpoint}",
                explanation=(
                    f"{sock.owner_label[0].upper()}{sock.owner_label[1:]} is {verb} {sock.endpoint}, "
                    "but no reservation covers this endpoint."
                ),
                evidence={
                    "occupant": _occupant_evidence(sock, OverlapResult(Overlap.DEFINITE, ""))
                },
                protocol=sock.protocol,
                port=sock.port,
                address=sock.address,
                socket_id=sock.id,
                process_id=sock.process_id,
            )
        )
    return findings


def discovery_findings(d: DiscoveryView) -> list[Finding]:
    findings: list[Finding] = []

    def add(key: str, severity: str, title: str, explanation: str, **evidence: Any) -> None:
        findings.append(
            Finding(
                fingerprint=f"incomplete:{key}",
                type=ConflictType.INCOMPLETE_DISCOVERY,
                severity=severity,
                certainty="potential",
                title=title,
                explanation=explanation,
                evidence=evidence,
            )
        )

    if d.native_status is None:
        add(
            "native:none",
            "warning",
            "No native discovery has completed yet",
            "Endpoint data is not available until the first scan finishes.",
        )
    elif d.native_status == "failed":
        add(
            "native:failed",
            "warning",
            "Latest native discovery failed",
            f"The most recent scan failed ({d.native_message or 'unknown error'}). The last known "
            "state is shown; endpoints are not assumed to have disappeared.",
            message=d.native_message,
        )
    elif d.native_status == "partial":
        add(
            "native:partial",
            "warning",
            "Native discovery is partial",
            "Not all sockets could be enumerated (insufficient privileges). Endpoints that were "
            "not observed are kept as last known rather than marked absent.",
        )
    if d.native_status is not None and d.stale:
        age = "never" if d.last_complete_age is None else f"{int(d.last_complete_age)}s ago"
        add(
            "native:stale",
            "warning",
            "Discovery data is stale",
            f"The last complete scan was {age} (threshold {int(d.stale_after)}s). Displayed data "
            "may not reflect the current machine state.",
            last_complete_age=d.last_complete_age,
        )
    if d.unknown_owner_count or d.restricted_process_count:
        add(
            "native:resolution",
            "info",
            "Partial process resolution",
            f"{d.unknown_owner_count} endpoints have no owning process reported and "
            f"{d.restricted_process_count} processes have restricted metadata. Running with "
            "elevated privileges gives fuller visibility; PortRegistry never elevates automatically.",
            unknown_owner_count=d.unknown_owner_count,
            restricted_process_count=d.restricted_process_count,
        )
    if d.docker_enabled and d.docker_state in ("unavailable", "degraded"):
        add(
            "docker",
            "info",
            f"Docker discovery {d.docker_state}",
            f"{d.docker_message or 'Docker is not reachable.'} Container port mappings may be "
            "missing or out of date; native discovery is unaffected.",
            docker_state=d.docker_state,
        )
    return findings


def detect_conflicts(snap: Snapshot) -> list[Finding]:
    findings: list[Finding] = []
    for res in snap.reservations:
        findings.extend(reservation_findings(res, snap))
    findings.extend(overlap_findings(snap.reservations))
    findings.extend(unregistered_findings(snap))
    findings.extend(discovery_findings(snap.discovery))
    return sorted(findings, key=Finding.sort_key)


def check_candidate(candidate: ReservationView, snap: Snapshot) -> list[Finding]:
    """Findings a not-yet-saved reservation (id 0) would produce. Used for dry runs."""
    findings = reservation_findings(candidate, snap)
    findings.extend(
        f
        for f in overlap_findings([candidate, *snap.reservations])
        if f.reservation_id is None or f.related_reservation_id is None
    )
    return sorted(findings, key=Finding.sort_key)


__all__ = [
    "ANY_ADDRESS",
    "ConflictType",
    "DiscoveryView",
    "DockerMappingView",
    "Finding",
    "ReservationView",
    "ServiceView",
    "Snapshot",
    "SocketView",
    "check_candidate",
    "detect_conflicts",
    "executable_matches",
]
