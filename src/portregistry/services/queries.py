"""Read-side queries shared by the API and the GUI."""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from django.db.models import Count, Q, QuerySet
from django.utils import timezone

from portregistry.core.addresses import Overlap, address_overlap
from portregistry.core.application import Application
from portregistry.django_app.models import (
    Conflict,
    DiscoveryScan,
    DockerContainer,
    DockerPortMapping,
    Event,
    Machine,
    PortReservation,
    ProcessInstance,
    Service,
    Socket,
)
from portregistry.services.conflict_store import build_discovery_view
from portregistry.services.validation import Errors

PORT_ORDERINGS = {
    "port": ("port", "protocol", "address"),
    "-port": ("-port", "protocol", "address"),
    "protocol": ("protocol", "port"),
    "address": ("address", "port"),
    "process": ("process__name", "port"),
    "pid": ("pid", "port"),
    "first_seen": ("first_seen",),
    "-first_seen": ("-first_seen",),
    "last_seen": ("-last_seen",),
}


def _bool_param(value: str | None, default: bool | None) -> bool | None:
    if value is None or value == "":
        return default
    lowered = value.lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off"):
        return False
    if lowered == "all":
        return None
    return default


def resolve_machine(value: str | None) -> Machine | None:
    if not value:
        return None
    qs = Machine.objects.all()
    match = qs.filter(hostname__iexact=value).first()
    if match is None:
        try:
            match = qs.filter(uuid=value).first()
        except Exception:
            match = None
    return match


def ports_queryset(params: dict[str, str]) -> QuerySet[Socket]:
    """Filter endpoints. ``params`` is an untrusted mapping (query string or form)."""
    errors = Errors()
    qs = Socket.objects.select_related("process", "machine")
    active = _bool_param(params.get("active"), True)
    if active is not None:
        qs = qs.filter(active=active)
    if params.get("port"):
        try:
            qs = qs.filter(port=int(params["port"]))
        except ValueError:
            errors.add("port", "Port must be an integer.")
    protocol = (params.get("protocol") or "").lower()
    if protocol:
        if protocol not in ("tcp", "udp"):
            errors.add("protocol", "Protocol must be 'tcp' or 'udp'.")
        else:
            qs = qs.filter(protocol=protocol)
    family = (params.get("family") or "").lower()
    if family:
        if family not in ("ipv4", "ipv6"):
            errors.add("family", "Family must be 'ipv4' or 'ipv6'.")
        else:
            qs = qs.filter(family=family)
    if params.get("state"):
        qs = qs.filter(state=params["state"].upper())
    if params.get("address"):
        qs = qs.filter(address=params["address"].strip())
    if params.get("pid"):
        try:
            qs = qs.filter(pid=int(params["pid"]))
        except ValueError:
            errors.add("pid", "PID must be an integer.")
    if params.get("process_id"):
        try:
            qs = qs.filter(process_id=int(params["process_id"]))
        except ValueError:
            errors.add("process_id", "Must be an integer.")
    if params.get("machine"):
        machine = resolve_machine(params["machine"])
        if machine is None:
            errors.add("machine", "Unknown machine.")
        else:
            qs = qs.filter(machine=machine)
    q = (params.get("q") or "").strip()
    if q:
        cond = (
            Q(address__icontains=q)
            | Q(process__name__icontains=q)
            | Q(process__exe__icontains=q)
            | Q(process__username__icontains=q)
        )
        if q.isdigit() and len(q) <= 10:
            # Port prefix ("80" finds 80, 8080...) or exact PID.
            cond |= Q(port__startswith=q) | Q(pid=int(q))
        qs = qs.filter(cond)
    ordering = params.get("ordering") or "port"
    if ordering not in PORT_ORDERINGS:
        errors.add("ordering", f"Ordering must be one of {', '.join(PORT_ORDERINGS)}.")
    errors.raise_if_any("Invalid filter.")
    return qs.order_by(*PORT_ORDERINGS.get(ordering, PORT_ORDERINGS["port"]))


class IgnoreClassifier:
    """Explains why an endpoint is not reported as an unregistered listener."""

    def __init__(self, machine: Machine | None = None) -> None:
        from portregistry.services.ignore_rules import active_rule_views, noise_settings

        machine = machine or Machine.objects.filter(is_local=True).first()
        self.rules = active_rule_views(machine) if machine else []
        self.ephemeral = noise_settings().ephemeral

    def reason(self, sock: Socket) -> str | None:
        if not sock.active:
            return None
        if (
            self.ephemeral
            and sock.protocol == "udp"
            and self.ephemeral[0] <= sock.port <= self.ephemeral[1]
        ):
            return "ephemeral UDP port"
        proc = sock.process
        for rule in self.rules:
            if rule.suppress_conflicts and rule.matches(
                protocol=sock.protocol,
                port=sock.port,
                address=sock.address,
                process_name=proc.name if proc else None,
                exe=proc.exe if proc else None,
            ):
                return f"known: {rule.name}"
        return None


def processes_queryset(params: dict[str, str]) -> QuerySet[ProcessInstance]:
    qs = ProcessInstance.objects.select_related("machine").annotate(
        active_socket_count=Count("sockets", filter=Q(sockets__active=True))
    )
    active = _bool_param(params.get("active"), True)
    if active is not None:
        qs = qs.filter(active=active)
    if params.get("pid"):
        try:
            qs = qs.filter(pid=int(params["pid"]))
        except ValueError as exc:
            from portregistry.exceptions import ValidationError

            raise ValidationError("Invalid filter.", {"pid": ["PID must be an integer."]}) from exc
    q = (params.get("q") or "").strip()
    if q:
        cond = Q(name__icontains=q) | Q(exe__icontains=q) | Q(username__icontains=q)
        if q.isdigit():
            cond |= Q(pid=int(q))
        qs = qs.filter(cond)
    return qs.order_by("name", "pid")


def docker_index(machine: Machine | None = None) -> dict[tuple[str, int], list[DockerPortMapping]]:
    """Published mappings of present containers indexed by (protocol, host_port)."""
    qs = DockerPortMapping.objects.filter(
        active=True, host_port__isnull=False, container__present=True
    ).select_related("container")
    if machine is not None:
        qs = qs.filter(container__machine=machine)
    index: dict[tuple[str, int], list[DockerPortMapping]] = defaultdict(list)
    for mapping in qs:
        if mapping.host_port is not None:
            index[(mapping.protocol, mapping.host_port)].append(mapping)
    return index


def docker_matches_for(
    sock: Socket, index: dict[tuple[str, int], list[DockerPortMapping]]
) -> list[DockerPortMapping]:
    result = []
    for mapping in index.get((sock.protocol, sock.port), []):
        try:
            if (
                address_overlap(mapping.host_ip or "0.0.0.0", sock.address).level
                is not Overlap.NONE
            ):
                result.append(mapping)
        except ValueError:
            continue
    return result


def reservations_covering(sock: Socket) -> list[PortReservation]:
    candidates = PortReservation.objects.filter(
        machine_id=sock.machine_id, status="active", protocol=sock.protocol, port=sock.port
    ).select_related("service")
    covering = []
    for res in candidates:
        try:
            if address_overlap(res.bind_address, sock.address).level is not Overlap.NONE:
                covering.append(res)
        except ValueError:
            continue
    return covering


def latest_scan(machine: Machine, kind: str = "native") -> DiscoveryScan | None:
    return (
        DiscoveryScan.objects.filter(machine=machine, kind=kind)
        .exclude(status="running")
        .order_by("-started_at", "-id")
        .first()
    )


def last_successful_scan(machine: Machine, kind: str = "native") -> DiscoveryScan | None:
    return (
        DiscoveryScan.objects.filter(machine=machine, kind=kind, status="complete")
        .order_by("-started_at", "-id")
        .first()
    )


def _age(dt: datetime | None) -> float | None:
    return None if dt is None else round((timezone.now() - dt).total_seconds(), 1)


def freshness(machine: Machine, app: Application | None) -> dict[str, Any]:
    view = build_discovery_view(machine)
    last = latest_scan(machine)
    ok = last_successful_scan(machine)
    return {
        "last_scan_at": last.finished_at.isoformat() if last and last.finished_at else None,
        "last_scan_status": last.status if last else None,
        "last_scan_id": last.pk if last else None,
        "last_success_at": ok.finished_at.isoformat() if ok and ok.finished_at else None,
        "last_success_age_seconds": _age(ok.finished_at) if ok else None,
        "stale": view.stale,
        "stale_after_seconds": view.stale_after,
        "complete_protocols": sorted(view.complete_protocols),
        "unknown_owner_count": view.unknown_owner_count,
        "restricted_process_count": view.restricted_process_count,
    }


def dashboard_summary(machine: Machine, app: Application | None = None) -> dict[str, Any]:
    sockets = Socket.objects.filter(machine=machine, active=True)
    by_proto = {
        row["protocol"]: row["n"] for row in sockets.values("protocol").annotate(n=Count("id"))
    }
    by_family = {
        row["family"]: row["n"] for row in sockets.values("family").annotate(n=Count("id"))
    }
    conflicts = Conflict.objects.filter(machine=machine, active=True)
    by_sev = {
        row["severity"]: row["n"] for row in conflicts.values("severity").annotate(n=Count("id"))
    }
    by_type = {row["type"]: row["n"] for row in conflicts.values("type").annotate(n=Count("id"))}
    containers = DockerContainer.objects.filter(machine=machine, present=True)
    return {
        "endpoints": {
            "total": sum(by_proto.values()),
            "tcp": by_proto.get("tcp", 0),
            "udp": by_proto.get("udp", 0),
            "ipv4": by_family.get("ipv4", 0),
            "ipv6": by_family.get("ipv6", 0),
            "unique_ports": sockets.values("port").distinct().count(),
            "unresolved_owner": sockets.filter(process__isnull=True).count(),
        },
        "processes": ProcessInstance.objects.filter(machine=machine, active=True).count(),
        "services": Service.objects.filter(machine=machine).count(),
        "reservations": {
            "active": PortReservation.objects.filter(machine=machine, status="active").count(),
            "released": PortReservation.objects.filter(machine=machine, status="released").count(),
            "attention": PortReservation.objects.filter(
                machine=machine, status="active", conflicts__active=True
            )
            .exclude(conflicts__severity="info")
            .distinct()
            .count(),
        },
        "conflicts": {
            "error": by_sev.get("error", 0),
            "warning": by_sev.get("warning", 0),
            "info": by_sev.get("info", 0),
            "by_type": by_type,
            "actionable": by_sev.get("error", 0) + by_sev.get("warning", 0),
        },
        "containers": {
            "present": containers.count(),
            "running": containers.filter(status="running").count(),
        },
        "events_24h": Event.objects.filter(
            machine=machine, timestamp__gte=timezone.now() - timedelta(hours=24)
        ).count(),
        "freshness": freshness(machine, app),
    }


def status_payload(app: Application, machine: Machine) -> dict[str, Any]:
    from portregistry.django_app.api.serializers import machine_dict, scan_dict

    last = latest_scan(machine)
    last_docker = latest_scan(machine, "docker")
    return {
        "daemon": {
            "version": app.version,
            "pid": os.getpid(),
            "started_at": app.started_at.isoformat(),
            "uptime_seconds": round(app.uptime_seconds, 1),
            "host": app.config.daemon.host,
            "port": app.config.daemon.port,
            "base_url": app.config.base_url,
            "shutting_down": app.shutting_down,
            "sse_subscribers": app.bus.subscriber_count,
        },
        "machine": machine_dict(machine),
        "scheduler": app.scheduler.describe() if app.scheduler else None,
        "providers": {
            "native": app.native_provider.as_dict(),
            "docker": app.docker_provider.as_dict(),
        },
        "discovery": {
            "last_native_scan": scan_dict(last) if last else None,
            "last_docker_scan": scan_dict(last_docker) if last_docker else None,
            **freshness(machine, app),
        },
        "platform": app.platform_info,
        "summary": dashboard_summary(machine, app),
        "config": {
            "native_interval": app.config.discovery.native_interval,
            "docker_enabled": app.config.discovery.docker_enabled,
            "docker_interval": app.config.discovery.docker_interval,
            "retention_days": app.config.history.retention_days,
            "collect_cmdline": app.config.discovery.collect_cmdline,
        },
    }
