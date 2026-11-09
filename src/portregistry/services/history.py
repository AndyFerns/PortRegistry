"""History (meaningful state changes) and post-commit event publication."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from django.db import transaction
from django.db.models import Count, Q, QuerySet
from django.utils import timezone

from portregistry.core.application import get_application, has_application
from portregistry.django_app.models import (
    Conflict,
    DiscoveryScan,
    DockerContainer,
    Event,
    Machine,
    ProcessInstance,
    Socket,
)
from portregistry.services.db import write_transaction

logger = logging.getLogger(__name__)

_TOPIC_BY_PREFIX = {
    "endpoint": "ports",
    "process": "ports",
    "scan": "scan",
    "discovery": "scan",
    "service": "registry",
    "reservation": "registry",
    "conflict": "conflicts",
    "container": "docker",
    "docker": "docker",
    "daemon": "daemon",
    "machine": "daemon",
}


def topic_for(event_type: str) -> str:
    return _TOPIC_BY_PREFIX.get(event_type.split(".", 1)[0], "history")


@dataclass
class EventSpec:
    type: str
    summary: str
    severity: str = "info"
    entity_type: str = ""
    entity_id: str | int = ""
    details: dict[str, Any] = field(default_factory=dict)


def notify(topic: str, type_: str, data: dict[str, Any] | None = None) -> None:
    """Publish a bus event after the current transaction commits (immediately if none)."""
    if not has_application():
        return
    bus = get_application().bus
    payload = dict(data or {})
    transaction.on_commit(lambda: bus.publish(topic, type_, payload))


def record_events(
    machine: Machine | None, specs: list[EventSpec], timestamp: datetime | None = None
) -> list[Event]:
    """Persist history events. Call inside the writer's transaction."""
    if not specs:
        return []
    ts = timestamp or timezone.now()
    rows = [
        Event(
            machine=machine,
            timestamp=ts,
            type=spec.type,
            severity=spec.severity,
            entity_type=spec.entity_type,
            entity_id=str(spec.entity_id),
            summary=spec.summary[:300],
            details=spec.details,
        )
        for spec in specs
    ]
    created = Event.objects.bulk_create(rows)
    topics: dict[str, list[str]] = {}
    for spec in specs:
        topics.setdefault(topic_for(spec.type), []).append(spec.type)
    for topic, types in topics.items():
        notify(topic, "history.recorded", {"types": sorted(set(types)), "count": len(types)})
    notify("history", "history.recorded", {"count": len(specs)})
    return created


def query_events(
    *,
    machine: Machine | None = None,
    type_prefix: str | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    severity: str | None = None,
    since: datetime | None = None,
    search: str | None = None,
) -> QuerySet[Event]:
    qs = Event.objects.all()
    if machine is not None:
        qs = qs.filter(machine=machine)
    if type_prefix:
        qs = qs.filter(type__startswith=type_prefix)
    if entity_type:
        qs = qs.filter(entity_type=entity_type)
    if entity_id:
        qs = qs.filter(entity_id=str(entity_id))
    if severity:
        qs = qs.filter(severity=severity)
    if since is not None:
        qs = qs.filter(timestamp__gte=since)
    if search:
        qs = qs.filter(Q(summary__icontains=search) | Q(type__icontains=search))
    return qs.order_by("-timestamp", "-id")


def event_type_counts(machine: Machine | None = None) -> dict[str, int]:
    qs = Event.objects.all() if machine is None else Event.objects.filter(machine=machine)
    return {row["type"]: row["n"] for row in qs.values("type").annotate(n=Count("id"))}


def cleanup(retention_days: int, now: datetime | None = None) -> dict[str, int]:
    """Delete history and inactive observations older than the retention window.

    User-defined services and reservations are never deleted here.
    """
    now = now or timezone.now()
    cutoff = now - timedelta(days=retention_days)
    counts: dict[str, int] = {}
    with write_transaction():
        counts["events"] = Event.objects.filter(timestamp__lt=cutoff).delete()[0]
        counts["conflicts"] = Conflict.objects.filter(
            active=False, resolved_at__lt=cutoff
        ).delete()[0]
        counts["sockets"] = Socket.objects.filter(active=False, ended_at__lt=cutoff).delete()[0]
        counts["processes"] = (
            ProcessInstance.objects.filter(active=False, ended_at__lt=cutoff)
            .filter(sockets__isnull=True)
            .delete()[0]
        )
        counts["containers"] = DockerContainer.objects.filter(
            present=False, removed_at__lt=cutoff
        ).delete()[0]
        # Keep the most recent scan of each kind so freshness is always known.
        keep_ids = []
        for kind in ("native", "docker"):
            latest = DiscoveryScan.objects.filter(kind=kind).order_by("-started_at").first()
            if latest:
                keep_ids.append(latest.pk)
        counts["scans"] = (
            DiscoveryScan.objects.filter(started_at__lt=cutoff).exclude(pk__in=keep_ids).delete()[0]
        )
    if any(counts.values()):
        logger.info("Retention cleanup removed %s", counts)
    return counts
