"""Reconcile native discovery results with persisted observed state.

Correctness rules:

* Results are collected before this module is called; the reconciliation
  itself runs in one short write transaction.
* Unchanged endpoints only get ``last_seen``/``last_scan`` bumped (bulk update);
  no history event is written for an unchanged polling cycle.
* Previously active endpoints are only marked absent when the scan was
  authoritative for their protocol/port scope (and, for per-process fallback
  scans, for their PID). Failed or partial scans never imply disappearance.
* Process identity is machine + PID + creation time. A process whose creation
  time is unknown gets an *incomplete* identity that is never merged with a
  later process reusing the PID.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from django.utils import timezone

from portregistry.core.addresses import format_endpoint
from portregistry.core.identity import (
    incomplete_process_key,
    process_identity_hash,
    process_key,
    socket_key,
)
from portregistry.core.types import NativeScanResult, ProcessInfo, ScanScope, ScanStatus
from portregistry.django_app.models import DiscoveryScan, Machine, ProcessInstance, Socket
from portregistry.services.db import write_transaction
from portregistry.services.history import (
    EventSpec,
    last_event_time,
    mark_noise,
    notify,
    record_events,
)

logger = logging.getLogger(__name__)

MAX_STORED_ISSUES = 100


@dataclass
class NativeReconcileSummary:
    scan_id: int
    status: str
    socket_count: int = 0
    process_count: int = 0
    appeared: int = 0
    disappeared: int = 0
    owner_changed: int = 0
    processes_appeared: int = 0
    processes_disappeared: int = 0
    resolution_failures: int = 0
    unknown_owners: int = 0
    baseline: bool = False
    message: str = ""
    preserved: int = 0  # previously active sockets kept because absence was not authoritative

    @property
    def changed(self) -> bool:
        return bool(
            self.appeared
            or self.disappeared
            or self.owner_changed
            or self.processes_appeared
            or self.processes_disappeared
            or self.baseline
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "socket_count": self.socket_count,
            "process_count": self.process_count,
            "appeared": self.appeared,
            "disappeared": self.disappeared,
            "owner_changed": self.owner_changed,
            "processes_appeared": self.processes_appeared,
            "processes_disappeared": self.processes_disappeared,
            "resolution_failures": self.resolution_failures,
            "unknown_owners": self.unknown_owners,
            "preserved": self.preserved,
            "baseline": self.baseline,
            "message": self.message,
        }


def begin_scan(
    machine: Machine,
    *,
    kind: str,
    trigger: str,
    provider: str,
    scope: ScanScope | None = None,
) -> DiscoveryScan:
    with write_transaction():
        return DiscoveryScan.objects.create(
            machine=machine,
            kind=kind,
            trigger=trigger,
            provider=provider,
            scope_protocols=",".join(sorted(p.value for p in scope.protocols)) if scope else "",
            scope_port=scope.port if scope else None,
            status=ScanStatus.RUNNING.value,
            started_at=timezone.now(),
        )


def fail_interrupted_scans(machine: Machine) -> int:
    """Mark scans left 'running' by an unclean shutdown as failed."""
    with write_transaction():
        return DiscoveryScan.objects.filter(machine=machine, status="running").update(
            status="failed",
            finished_at=timezone.now(),
            message="Interrupted (daemon stopped before the scan finished).",
        )


def _process_summary(proc: ProcessInstance | None, pid: int | None) -> dict[str, Any]:
    if proc is None:
        return {"pid": pid, "process": None}
    return {
        "pid": proc.pid,
        "process": proc.name or None,
        "process_id": proc.pk,
        "identity": proc.identity_key,
    }


def _socket_details(sock: Socket, proc: ProcessInstance | None) -> dict[str, Any]:
    return {
        "socket_id": sock.pk,
        "protocol": sock.protocol,
        "family": sock.family,
        "address": sock.address,
        "port": sock.port,
        "state": sock.state,
        **_process_summary(proc, sock.pid),
    }


def _owner_label(proc: ProcessInstance | None, pid: int | None) -> str:
    if proc is not None:
        return f"{proc.name or '?'} (pid {proc.pid})"
    if pid is not None:
        return f"pid {pid} (unresolved)"
    return "unknown process"


_PROCESS_FIELDS = (
    "name",
    "exe",
    "username",
    "ppid",
    "cwd",
    "cmdline",
    "project_name",
    "project_root",
)


def _apply_process_metadata(proc: ProcessInstance, info: ProcessInfo) -> list[str]:
    """Update metadata from a fresh observation; never erase known values."""
    changed: list[str] = []
    values = {
        "name": info.name,
        "exe": info.exe,
        "username": info.username,
        "ppid": info.ppid,
        "cwd": info.cwd,
        "cmdline": info.cmdline,
        "project_name": info.project_name,
        "project_root": info.project_root,
    }
    for field_name in _PROCESS_FIELDS:
        new = values[field_name]
        if new in (None, ""):
            continue
        if getattr(proc, field_name) != new:
            setattr(proc, field_name, new)
            changed.append(field_name)
    errors = dict(info.errors)
    if proc.metadata_errors != errors:
        proc.metadata_errors = errors
        changed.append("metadata_errors")
    return changed


def _new_process(
    machine: Machine, info: ProcessInfo, key: str, now: datetime, complete: bool
) -> ProcessInstance:
    started_at = (
        datetime.fromtimestamp(info.create_time, tz=UTC) if info.create_time is not None else None
    )
    return ProcessInstance(
        machine=machine,
        identity_key=key,
        identity_hash=(
            process_identity_hash(machine.uuid, info.pid, info.create_time)
            if complete and info.create_time is not None
            else ""
        ),
        identity_complete=complete,
        pid=info.pid,
        create_time=info.create_time if complete else None,
        started_at=started_at if complete else None,
        name=info.name or "",
        exe=info.exe or "",
        cmdline=info.cmdline,
        username=info.username or "",
        ppid=info.ppid,
        cwd=info.cwd or "",
        project_name=info.project_name or "",
        project_root=info.project_root or "",
        metadata_errors=dict(info.errors),
        first_seen=now,
        last_seen=now,
        active=True,
    )


def apply_native_scan(
    machine: Machine, scan: DiscoveryScan, result: NativeScanResult
) -> NativeReconcileSummary:
    """Persist one native scan result. Runs in a single short write transaction."""
    now = timezone.now()
    summary = NativeReconcileSummary(scan_id=scan.pk, status=result.status.value)
    issues = [i.as_dict() for i in result.issues[:MAX_STORED_ISSUES]]

    with write_transaction():
        previous = (
            DiscoveryScan.objects.filter(machine=machine, kind="native")
            .exclude(pk=scan.pk)
            .exclude(status="running")
            .order_by("-started_at", "-id")
            .first()
        )
        events: list[EventSpec] = []

        if result.error is not None:
            summary.message = result.error
            _finish_scan(scan, result, summary, issues, now)
            events.extend(_status_transition_events(previous, scan))
            record_events(machine, events, now)
            return summary

        baseline = (
            not DiscoveryScan.objects.filter(
                machine=machine, kind="native", status__in=["complete", "partial"]
            )
            .exclude(pk=scan.pk)
            .exists()
        )
        summary.baseline = baseline

        # ---------------------------------------------------------- processes
        complete_keys: dict[int, str] = {}
        for pid, info in result.processes.items():
            if info.identity_complete and info.create_time is not None:
                complete_keys[pid] = process_key(pid, info.create_time)
        existing = {
            p.identity_key: p
            for p in ProcessInstance.objects.filter(
                machine=machine, identity_key__in=list(complete_keys.values())
            )
        }
        incomplete_active = list(
            ProcessInstance.objects.filter(
                machine=machine,
                active=True,
                identity_complete=False,
                pid__in=[p for p, i in result.processes.items() if not i.identity_complete],
            )
        )
        proc_by_pid: dict[int, ProcessInstance] = {}
        new_processes: list[ProcessInstance] = []
        reactivated: list[ProcessInstance] = []
        touch_proc_ids: list[int] = []

        for pid, info in result.processes.items():
            if info.exited:
                continue  # ownership unresolved; socket keyed by pid
            if pid in complete_keys:
                key = complete_keys[pid]
                proc = existing.get(key)
                if proc is None:
                    proc = _new_process(machine, info, key, now, complete=True)
                    new_processes.append(proc)
                else:
                    changed = _apply_process_metadata(proc, info)
                    if not proc.active:
                        proc.active = True
                        proc.ended_at = None
                        reactivated.append(proc)
                        changed += ["active", "ended_at"]
                    if changed:
                        proc.last_seen = now
                        proc.save(update_fields=[*set(changed), "last_seen"])
                    else:
                        touch_proc_ids.append(proc.pk)
            else:
                proc = next(
                    (p for p in incomplete_active if p.pid == pid and p.name == (info.name or "")),
                    None,
                )
                if proc is None:
                    proc = _new_process(
                        machine, info, incomplete_process_key(pid), now, complete=False
                    )
                    new_processes.append(proc)
                else:
                    touch_proc_ids.append(proc.pk)
            proc_by_pid[pid] = proc

        if new_processes:
            ProcessInstance.objects.bulk_create(new_processes)
        if touch_proc_ids:
            ProcessInstance.objects.filter(pk__in=touch_proc_ids).update(last_seen=now)

        # ------------------------------------------------------------ sockets
        observed: dict[str, tuple[Any, ProcessInstance | None]] = {}
        for raw in result.sockets:
            proc = proc_by_pid.get(raw.pid) if raw.pid is not None else None
            if proc is not None:
                owner = proc.identity_key
            elif raw.pid is not None:
                owner = f"pid:{raw.pid}"
            else:
                owner = "unknown"
            key = socket_key(raw.protocol, raw.family, raw.address, raw.port, owner)
            observed[key] = (raw, proc)

        active_sockets = {
            s.key: s
            for s in Socket.objects.filter(machine=machine, active=True).select_related("process")
        }
        known = {s.key: s for s in Socket.objects.filter(machine=machine, key__in=list(observed))}

        appeared: list[tuple[Socket, ProcessInstance | None]] = []
        disappeared: list[tuple[Socket, ProcessInstance | None]] = []
        touch_socket_ids: list[int] = []
        new_sockets: list[Socket] = []

        for key, (raw, proc) in observed.items():
            sock = known.get(key)
            if sock is None:
                sock = Socket(
                    machine=machine,
                    process=proc,
                    key=key,
                    protocol=raw.protocol.value,
                    family=raw.family.value,
                    address=raw.address,
                    port=raw.port,
                    state=raw.state.value,
                    pid=raw.pid,
                    active=True,
                    first_seen=now,
                    last_seen=now,
                    first_scan=scan,
                    last_scan=scan,
                )
                new_sockets.append(sock)
                appeared.append((sock, proc))
            elif not sock.active:
                sock.active = True
                sock.ended_at = None
                sock.last_seen = now
                sock.last_scan = scan
                sock.process = proc
                sock.save(update_fields=["active", "ended_at", "last_seen", "last_scan", "process"])
                appeared.append((sock, proc))
            else:
                touch_socket_ids.append(sock.pk)

        if new_sockets:
            Socket.objects.bulk_create(new_sockets)
        if touch_socket_ids:
            Socket.objects.filter(pk__in=touch_socket_ids).update(last_seen=now, last_scan=scan)

        for key, sock in active_sockets.items():
            if key in observed:
                continue
            if result.is_absence_authoritative(sock.protocol, sock.port, sock.pid):
                sock.active = False
                sock.ended_at = now
                sock.save(update_fields=["active", "ended_at"])
                disappeared.append((sock, sock.process))
            else:
                summary.preserved += 1

        # ----------------------------------------------- process active state
        active_owner_ids = set(
            Socket.objects.filter(machine=machine, active=True, process__isnull=False).values_list(
                "process_id", flat=True
            )
        )
        gone = list(
            ProcessInstance.objects.filter(machine=machine, active=True).exclude(
                pk__in=active_owner_ids
            )
        )
        for proc in gone:
            proc.active = False
            proc.ended_at = now
        if gone:
            ProcessInstance.objects.bulk_update(gone, ["active", "ended_at"])

        # ------------------------------------------------------------- events
        summary.appeared = len(appeared)
        summary.disappeared = len(disappeared)
        summary.processes_appeared = len(new_processes) + len(reactivated)
        summary.processes_disappeared = len(gone)
        summary.socket_count = len(observed)
        summary.process_count = len(proc_by_pid)
        summary.resolution_failures = sum(
            1 for i in result.processes.values() if i.errors or i.exited
        )
        summary.unknown_owners = sum(1 for s in result.sockets if s.pid is None)

        if baseline:
            events.append(
                EventSpec(
                    "discovery.baseline",
                    f"Initial discovery recorded {summary.socket_count} endpoints owned by "
                    f"{summary.process_count} processes",
                    entity_type="scan",
                    entity_id=scan.pk,
                    details={"socket_count": summary.socket_count},
                )
            )
        else:
            noise = _NoiseClassifier(machine, now)
            events.extend(_endpoint_events(appeared, disappeared, summary, noise))
            noisy_by_proc: dict[int, list[bool]] = defaultdict(list)
            for sock, owner in [*appeared, *disappeared]:
                if owner is not None:
                    noisy_by_proc[owner.pk].append(noise.is_noise(sock, owner))
            for proc in [*new_processes, *reactivated]:
                flags = noisy_by_proc.get(proc.pk, [])
                events.append(
                    EventSpec(
                        "process.appeared",
                        f"{proc.name or '?'} (pid {proc.pid}) started owning endpoints",
                        entity_type="process",
                        entity_id=proc.pk,
                        details={
                            "pid": proc.pid,
                            "name": proc.name,
                            "exe": proc.exe,
                            "identity_complete": proc.identity_complete,
                        },
                        noise=bool(flags) and all(flags),
                    )
                )
            for proc in gone:
                flags = noisy_by_proc.get(proc.pk, [])
                flapped = noise.flapped("process", proc.pk, "process.appeared")
                events.append(
                    EventSpec(
                        "process.disappeared",
                        f"{proc.name or '?'} (pid {proc.pid}) no longer owns any observed endpoint",
                        entity_type="process",
                        entity_id=proc.pk,
                        details={"pid": proc.pid, "name": proc.name},
                        noise=flapped or (bool(flags) and all(flags)),
                    )
                )

        _finish_scan(scan, result, summary, issues, now)
        events.extend(_status_transition_events(previous, scan))
        record_events(machine, events, now)

    notify("scan", "scan.completed", summary.as_dict())
    if summary.changed:
        notify("ports", "ports.changed", {"scan_id": scan.pk})
    return summary


class _NoiseClassifier:
    """Decides which history events are churn (hidden by default, purged sooner).

    * UDP sockets on the OS ephemeral range (client sockets of browsers, DNS...).
    * Endpoints matched by an ignore rule with ``quiet_history``.
    * Flapping: an endpoint/process that goes away within ``flap_window_seconds``
      of appearing; its earlier "appeared" event is marked as noise too.
    """

    def __init__(self, machine: Machine, now: datetime) -> None:
        from portregistry.services.ignore_rules import active_rule_views, noise_settings

        settings = noise_settings()
        self.rules = [r for r in active_rule_views(machine) if r.quiet_history]
        self.ephemeral = settings.ephemeral
        self.window = settings.flap_window_seconds
        self.now = now

    def is_noise(self, sock: Socket, proc: ProcessInstance | None) -> bool:
        if (
            self.ephemeral is not None
            and sock.protocol == "udp"
            and self.ephemeral[0] <= sock.port <= self.ephemeral[1]
        ):
            return True
        return any(
            rule.matches(
                protocol=sock.protocol,
                port=sock.port,
                address=sock.address,
                process_name=proc.name if proc else None,
                exe=proc.exe if proc else None,
            )
            for rule in self.rules
        )

    def flapped(self, entity_type: str, entity_id: int, appear_type: str) -> bool:
        if self.window <= 0:
            return False
        appeared_at = last_event_time(entity_type, entity_id, appear_type)
        if appeared_at is None or (self.now - appeared_at).total_seconds() > self.window:
            return False
        mark_noise(entity_type, entity_id, appear_type, appeared_at)
        return True


def _endpoint_events(
    appeared: list[tuple[Socket, ProcessInstance | None]],
    disappeared: list[tuple[Socket, ProcessInstance | None]],
    summary: NativeReconcileSummary,
    noise: _NoiseClassifier | None = None,
) -> list[EventSpec]:
    """Endpoint events, pairing disappear+appear of the same endpoint as an owner change."""
    events: list[EventSpec] = []
    gone_by_endpoint: dict[tuple[str, str, str, int], list[tuple[Socket, Any]]] = defaultdict(list)
    for sock, proc in disappeared:
        gone_by_endpoint[(sock.protocol, sock.family, sock.address, sock.port)].append((sock, proc))

    for sock, proc in appeared:
        endpoint = (sock.protocol, sock.family, sock.address, sock.port)
        label = format_endpoint(sock.protocol, sock.address, sock.port)
        previous_owners = gone_by_endpoint.get(endpoint)
        if previous_owners:
            old_sock, old_proc = previous_owners.pop(0)
            summary.owner_changed += 1
            events.append(
                EventSpec(
                    "endpoint.owner_changed",
                    f"{label} owner changed from {_owner_label(old_proc, old_sock.pid)} "
                    f"to {_owner_label(proc, sock.pid)}",
                    severity="warning",
                    entity_type="socket",
                    entity_id=sock.pk,
                    details={
                        **_socket_details(sock, proc),
                        "previous_socket_id": old_sock.pk,
                        "previous": _process_summary(old_proc, old_sock.pid),
                    },
                    noise=bool(
                        noise and noise.is_noise(sock, proc) and noise.is_noise(old_sock, old_proc)
                    ),
                )
            )
            continue
        events.append(
            EventSpec(
                "endpoint.appeared",
                f"{label} opened by {_owner_label(proc, sock.pid)}",
                entity_type="socket",
                entity_id=sock.pk,
                details=_socket_details(sock, proc),
                noise=bool(noise and noise.is_noise(sock, proc)),
            )
        )
    for remaining in gone_by_endpoint.values():
        for sock, proc in remaining:
            events.append(
                EventSpec(
                    "endpoint.disappeared",
                    f"{format_endpoint(sock.protocol, sock.address, sock.port)} closed "
                    f"(was {_owner_label(proc, sock.pid)})",
                    entity_type="socket",
                    entity_id=sock.pk,
                    details=_socket_details(sock, proc),
                    noise=bool(
                        noise
                        and (
                            noise.is_noise(sock, proc)
                            or noise.flapped("socket", sock.pk, "endpoint.appeared")
                        )
                    ),
                )
            )
    # Owner changes counted separately; keep appeared/disappeared as pure counts.
    summary.appeared -= summary.owner_changed
    summary.disappeared -= summary.owner_changed
    return events


def _finish_scan(
    scan: DiscoveryScan,
    result: NativeScanResult,
    summary: NativeReconcileSummary,
    issues: list[dict[str, Any]],
    now: datetime,
) -> None:
    scan.status = result.status.value
    scan.finished_at = now
    scan.duration_ms = result.duration_ms
    scan.socket_count = summary.socket_count
    scan.process_count = len(result.processes)
    scan.resolved_process_count = sum(
        1 for i in result.processes.values() if not i.exited and i.name
    )
    scan.resolution_failures = summary.resolution_failures
    scan.unknown_owner_count = summary.unknown_owners
    scan.appeared_count = summary.appeared
    scan.disappeared_count = summary.disappeared
    scan.errors = issues
    scan.message = summary.message
    scan.save()


def _status_transition_events(
    previous: DiscoveryScan | None, scan: DiscoveryScan
) -> list[EventSpec]:
    """Record scan health only when it changes, not on every failing poll."""
    prev_status = previous.status if previous else None
    if prev_status == scan.status:
        return []
    if prev_status is None and scan.status == "complete":
        return []
    healthy = scan.status == "complete"
    if healthy:
        summary = f"Native discovery recovered (previous scan was {prev_status})"
    elif scan.status == "partial":
        summary = "Native discovery is partial: some sockets could not be enumerated"
    else:
        summary = f"Native discovery failed: {scan.message or 'unknown error'}"
    return [
        EventSpec(
            "scan.status_changed",
            summary,
            severity="info" if healthy else "warning",
            entity_type="scan",
            entity_id=scan.pk,
            details={"previous": prev_status, "current": scan.status, "message": scan.message},
        )
    ]
