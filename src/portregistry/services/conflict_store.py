"""Build conflict-engine snapshots from the database and persist findings."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from django.db.models import Q, QuerySet
from django.utils import timezone

from portregistry.core.application import get_application, has_application
from portregistry.django_app.models import (
    Conflict,
    DiscoveryScan,
    DockerPortMapping,
    Machine,
    PortReservation,
    Service,
    Socket,
)
from portregistry.services.conflicts import (
    DiscoveryView,
    DockerMappingView,
    Finding,
    ReservationView,
    ServiceView,
    Snapshot,
    SocketView,
    check_candidate,
    detect_conflicts,
)
from portregistry.services.db import write_transaction
from portregistry.services.history import EventSpec, notify, record_events

logger = logging.getLogger(__name__)

DEFAULT_STALE_AFTER = 35.0
#: Types that do not get conflict.detected/resolved history events: unregistered
#: listeners are numerous (endpoint events already cover them), and discovery
#: health has its own scan.status_changed / docker.(un)available events.
_QUIET_TYPES = {"unregistered_listener", "incomplete_discovery"}


def build_discovery_view(machine: Machine) -> DiscoveryView:
    finished = DiscoveryScan.objects.filter(machine=machine, kind="native").exclude(
        status="running"
    )
    latest_full = finished.filter(scope_port__isnull=True).order_by("-started_at", "-id").first()
    last_complete = (
        finished.filter(status="complete", scope_port__isnull=True, scope_protocols="tcp,udp")
        .order_by("-started_at", "-id")
        .first()
    )
    complete_protocols: frozenset[str] = frozenset()
    if latest_full is not None and latest_full.status == "complete":
        complete_protocols = frozenset(p for p in latest_full.scope_protocols.split(",") if p)
    age = None
    if last_complete is not None and last_complete.finished_at is not None:
        age = (timezone.now() - last_complete.finished_at).total_seconds()

    unknown = latest_full.unknown_owner_count if latest_full else 0
    restricted = latest_full.resolution_failures if latest_full else 0

    stale_after = DEFAULT_STALE_AFTER
    docker_enabled = False
    docker_state = "disabled"
    docker_message = ""
    if has_application():
        app = get_application()
        stale_after = app.stale_after_seconds
        docker_enabled = app.docker_provider.enabled
        docker_state = app.docker_provider.state if docker_enabled else "disabled"
        docker_message = app.docker_provider.message
    return DiscoveryView(
        native_status=latest_full.status if latest_full else None,
        native_message=latest_full.message if latest_full else "",
        complete_protocols=complete_protocols,
        last_complete_age=age,
        stale_after=stale_after,
        unknown_owner_count=unknown,
        restricted_process_count=restricted,
        docker_enabled=docker_enabled,
        docker_state=docker_state,
        docker_message=docker_message,
    )


def socket_view(sock: Socket) -> SocketView:
    proc = sock.process
    return SocketView(
        id=sock.pk,
        protocol=sock.protocol,
        family=sock.family,
        address=sock.address,
        port=sock.port,
        pid=sock.pid,
        process_id=proc.pk if proc else None,
        process_name=(proc.name or None) if proc else None,
        exe=(proc.exe or None) if proc else None,
        cwd=(proc.cwd or None) if proc else None,
        metadata_restricted=bool(proc and proc.metadata_errors),
    )


def reservation_view(res: PortReservation) -> ReservationView:
    return ReservationView(
        id=res.pk or 0,
        protocol=res.protocol,
        bind_address=res.bind_address,
        port=res.port,
        service_id=res.service_id,
        description=res.description,
    )


def service_view(service: Service) -> ServiceView:
    return ServiceView(
        id=service.pk,
        name=service.name,
        expected_executable=service.expected_executable,
        expected_working_directory=service.expected_working_directory,
    )


def build_snapshot(machine: Machine) -> Snapshot:
    sockets = [
        socket_view(s)
        for s in Socket.objects.filter(machine=machine, active=True).select_related("process")
    ]
    reservations = [
        reservation_view(r)
        for r in PortReservation.objects.filter(machine=machine, status="active").order_by("id")
    ]
    services = {s.pk: service_view(s) for s in Service.objects.filter(machine=machine)}
    mappings = [
        DockerMappingView(
            id=m.pk,
            container_db_id=m.container_id,
            container_id=m.container.container_id,
            container_name=m.container.name,
            image_ref=m.container.image_ref,
            protocol=m.protocol,
            host_ip=m.host_ip,
            host_port=m.host_port,
            container_port=m.container_port,
        )
        for m in DockerPortMapping.objects.filter(
            container__machine=machine,
            container__present=True,
            container__status="running",
            active=True,
            host_port__isnull=False,
        ).select_related("container")
        if m.host_port is not None
    ]
    from portregistry.services.ignore_rules import active_rule_views, noise_settings

    return Snapshot(
        sockets=sockets,
        reservations=reservations,
        services=services,
        docker_mappings=mappings,
        discovery=build_discovery_view(machine),
        ignore_rules=active_rule_views(machine),
        ephemeral=noise_settings().ephemeral,
    )


@dataclass
class RefreshSummary:
    active: int
    detected: int
    resolved: int


_UPDATABLE = (
    "severity",
    "certainty",
    "title",
    "explanation",
    "evidence",
    "protocol",
    "port",
    "address",
)


def _finding_fields(f: Finding) -> dict[str, Any]:
    return {
        "type": f.type.value,
        "severity": f.severity,
        "certainty": f.certainty,
        "title": f.title[:300],
        "explanation": f.explanation,
        "evidence": f.evidence,
        "protocol": f.protocol,
        "port": f.port,
        "address": f.address,
        "reservation_id": f.reservation_id,
        "related_reservation_id": f.related_reservation_id,
        "service_id": f.service_id,
        "socket_id": f.socket_id,
        "process_id": f.process_id,
    }


def refresh_conflicts(machine: Machine) -> RefreshSummary:
    """Recompute findings and persist the difference.

    The snapshot is read inside the writer lock so that it is consistent with
    concurrent registry mutations; only database work happens here.
    """
    now = timezone.now()
    with write_transaction():
        findings = detect_conflicts(build_snapshot(machine))
        by_fp = {f.fingerprint: f for f in findings}
        existing = {c.fingerprint: c for c in Conflict.objects.filter(machine=machine, active=True)}
        events: list[EventSpec] = []
        detected = resolved = 0

        to_create = []
        unchanged_ids: list[int] = []
        for fp, finding in by_fp.items():
            fields = _finding_fields(finding)
            row = existing.get(fp)
            if row is None:
                to_create.append(
                    Conflict(
                        machine=machine, fingerprint=fp, first_seen=now, last_seen=now, **fields
                    )
                )
                detected += 1
                if finding.type.value not in _QUIET_TYPES:
                    events.append(
                        EventSpec(
                            "conflict.detected",
                            finding.title,
                            severity="warning" if finding.severity != "info" else "info",
                            entity_type="conflict",
                            entity_id=fp,
                            details={
                                "type": finding.type.value,
                                "severity": finding.severity,
                                "certainty": finding.certainty,
                                "explanation": finding.explanation,
                                "reservation_id": finding.reservation_id,
                                "service_id": finding.service_id,
                            },
                        )
                    )
            else:
                changed = [k for k, v in fields.items() if getattr(row, k) != v]
                if not changed:
                    unchanged_ids.append(row.pk)
                    continue
                row.last_seen = now
                for k in changed:
                    setattr(row, k, fields[k])
                row.save(update_fields=[*changed, "last_seen"])
        if to_create:
            Conflict.objects.bulk_create(to_create)
        if unchanged_ids:
            Conflict.objects.filter(pk__in=unchanged_ids).update(last_seen=now)

        for fp, row in existing.items():
            if fp in by_fp:
                continue
            row.active = False
            row.resolved_at = now
            row.save(update_fields=["active", "resolved_at"])
            resolved += 1
            if row.type not in _QUIET_TYPES:
                events.append(
                    EventSpec(
                        "conflict.resolved",
                        f"Resolved: {row.title}",
                        entity_type="conflict",
                        entity_id=fp,
                        details={
                            "type": row.type,
                            "severity": row.severity,
                            "certainty": row.certainty,
                            "reservation_id": row.reservation_id,
                            "service_id": row.service_id,
                        },
                    )
                )
        record_events(machine, events, now)
        active = len(by_fp)
    if detected or resolved:
        notify("conflicts", "conflicts.changed", {"detected": detected, "resolved": resolved})
    return RefreshSummary(active=active, detected=detected, resolved=resolved)


def active_conflicts(
    machine: Machine | None = None,
    *,
    type_: str | None = None,
    severity: str | None = None,
    min_severity: str | None = None,
    certainty: str | None = None,
    reservation_id: int | None = None,
    service_id: int | None = None,
) -> QuerySet[Conflict]:
    qs = Conflict.objects.filter(active=True)
    if machine is not None:
        qs = qs.filter(machine=machine)
    if type_:
        qs = qs.filter(type=type_)
    if severity:
        qs = qs.filter(severity=severity)
    if min_severity == "warning":
        qs = qs.filter(severity__in=["error", "warning"])
    elif min_severity == "error":
        qs = qs.filter(severity="error")
    if certainty:
        qs = qs.filter(certainty=certainty)
    if reservation_id is not None:
        qs = qs.filter(Q(reservation_id=reservation_id) | Q(related_reservation_id=reservation_id))
    if service_id is not None:
        qs = qs.filter(service_id=service_id)
    return qs.select_related("reservation", "service", "socket", "process")


def check_reservation_candidate(machine: Machine, candidate: ReservationView) -> list[Finding]:
    """Dry-run conflict check for a reservation that has not been saved."""
    snap = build_snapshot(machine)
    if candidate.id:
        snap.reservations = [r for r in snap.reservations if r.id != candidate.id]
        candidate = ReservationView(
            id=0,
            protocol=candidate.protocol,
            bind_address=candidate.bind_address,
            port=candidate.port,
            service_id=candidate.service_id,
            description=candidate.description,
        )
    return check_candidate(candidate, snap)
