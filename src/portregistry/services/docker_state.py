"""Persist Docker inventory and track Docker provider availability."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from django.utils import timezone

from portregistry.core.addresses import format_endpoint
from portregistry.core.application import Application
from portregistry.core.types import DockerContainerInfo, DockerInventoryResult
from portregistry.discovery.docker.events import DockerEventListener
from portregistry.discovery.docker.provider import DockerProvider, docker_sdk_available
from portregistry.django_app.models import (
    DiscoveryScan,
    DockerContainer,
    DockerImage,
    DockerPortMapping,
    Machine,
)
from portregistry.services.conflict_store import refresh_conflicts
from portregistry.services.db import write_transaction
from portregistry.services.history import EventSpec, notify, record_events
from portregistry.services.reconcile import begin_scan

logger = logging.getLogger(__name__)


@dataclass
class DockerReconcileSummary:
    scan_id: int
    available: bool
    containers: int = 0
    appeared: int = 0
    disappeared: int = 0
    status_changed: int = 0
    error: str | None = None
    baseline: bool = False

    def as_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


def _mapping_label(info: DockerContainerInfo) -> list[str]:
    return [
        f"{format_endpoint(p.protocol.value, p.host_ip or '0.0.0.0', p.host_port)}"
        f" -> {p.container_port}/{p.protocol.value}"
        for p in info.ports
        if p.host_port is not None
    ]


def _upsert_image(machine: Machine, info: DockerContainerInfo, now: Any) -> DockerImage | None:
    if not info.image.image_id:
        return None
    image, created = DockerImage.objects.get_or_create(
        machine=machine,
        image_id=info.image.image_id,
        defaults={
            "repository": info.image.repository or "",
            "tag": info.image.tag or "",
            "digest": info.image.digest or "",
            "first_seen": now,
            "last_seen": now,
        },
    )
    if not created:
        image.last_seen = now
        if info.image.repository and not image.repository:
            image.repository = info.image.repository
            image.tag = info.image.tag or ""
        image.save()
    return image


def apply_docker_inventory(
    machine: Machine, scan: DiscoveryScan, result: DockerInventoryResult
) -> DockerReconcileSummary:
    now = timezone.now()
    summary = DockerReconcileSummary(scan_id=scan.pk, available=result.available)
    with write_transaction():
        scan.finished_at = now
        scan.duration_ms = result.duration_ms
        if not result.available:
            # Unavailable Docker never implies containers disappeared.
            scan.status = "failed"
            scan.message = result.error or "Docker unavailable"
            scan.save()
            summary.error = scan.message
            return summary

        baseline = (
            not DiscoveryScan.objects.filter(machine=machine, kind="docker", status="complete")
            .exclude(pk=scan.pk)
            .exists()
        )
        summary.baseline = baseline
        events: list[EventSpec] = []
        existing = {c.container_id: c for c in DockerContainer.objects.filter(machine=machine)}
        seen: set[str] = set()

        for info in result.containers:
            if not info.container_id:
                continue
            seen.add(info.container_id)
            image = _upsert_image(machine, info, now)
            row = existing.get(info.container_id)
            fields = {
                "name": info.name[:255],
                "image": image,
                "image_ref": info.image_ref[:255],
                "status": info.status[:32],
                "created_at_docker": info.created_at,
                "started_at": info.started_at,
                "labels": info.labels,
                "networks": info.networks,
            }
            if row is None:
                row = DockerContainer.objects.create(
                    machine=machine,
                    container_id=info.container_id,
                    present=True,
                    first_seen=now,
                    last_seen=now,
                    **fields,
                )
                summary.appeared += 1
                if not baseline:
                    events.append(
                        EventSpec(
                            "container.appeared",
                            f"Container {info.name} ({info.image_ref}) appeared [{info.status}]",
                            entity_type="container",
                            entity_id=info.container_id[:12],
                            details={
                                "name": info.name,
                                "image": info.image_ref,
                                "status": info.status,
                                "published": _mapping_label(info),
                            },
                        )
                    )
            else:
                old_status = row.status
                was_present = row.present
                for key, value in fields.items():
                    setattr(row, key, value)
                row.present = True
                row.removed_at = None
                row.last_seen = now
                row.save()
                if not was_present:
                    summary.appeared += 1
                    events.append(
                        EventSpec(
                            "container.appeared",
                            f"Container {info.name} reappeared [{info.status}]",
                            entity_type="container",
                            entity_id=info.container_id[:12],
                            details={"name": info.name, "status": info.status},
                        )
                    )
                elif old_status != info.status:
                    summary.status_changed += 1
                    events.append(
                        EventSpec(
                            "container.status_changed",
                            f"Container {info.name}: {old_status} -> {info.status}",
                            entity_type="container",
                            entity_id=info.container_id[:12],
                            details={
                                "name": info.name,
                                "previous": old_status,
                                "current": info.status,
                                "published": _mapping_label(info),
                            },
                        )
                    )
            # Port mappings
            current_keys = set()
            mapping_rows = {m.key: m for m in row.port_mappings.all()}
            for port in info.ports:
                current_keys.add(port.key)
                values = {
                    "container_port": port.container_port,
                    "protocol": port.protocol.value,
                    "host_ip": port.host_ip or "",
                    "host_port": port.host_port,
                    "active": True,
                }
                mapping = mapping_rows.get(port.key)
                if mapping is None:
                    DockerPortMapping.objects.create(container=row, key=port.key, **values)
                elif any(getattr(mapping, k) != v for k, v in values.items()):
                    for k, v in values.items():
                        setattr(mapping, k, v)
                    mapping.save()
            stale = [m.pk for k, m in mapping_rows.items() if k not in current_keys and m.active]
            if stale:
                DockerPortMapping.objects.filter(pk__in=stale).update(active=False)

        for container_id, row in existing.items():
            if container_id in seen or not row.present:
                continue
            row.present = False
            row.removed_at = now
            row.save(update_fields=["present", "removed_at"])
            row.port_mappings.update(active=False)
            summary.disappeared += 1
            events.append(
                EventSpec(
                    "container.disappeared",
                    f"Container {row.name} was removed",
                    entity_type="container",
                    entity_id=container_id[:12],
                    details={"name": row.name, "image": row.image_ref},
                )
            )

        if baseline and result.containers:
            events.append(
                EventSpec(
                    "docker.baseline",
                    f"Initial Docker inventory recorded {len(result.containers)} containers",
                    entity_type="scan",
                    entity_id=scan.pk,
                )
            )
        summary.containers = len(result.containers)
        scan.status = "complete"
        scan.container_count = summary.containers
        scan.appeared_count = summary.appeared
        scan.disappeared_count = summary.disappeared
        scan.message = f"Docker {result.server_version}" if result.server_version else ""
        scan.save()
        record_events(machine, events, now)
    if summary.appeared or summary.disappeared or summary.status_changed:
        notify("docker", "docker.changed", summary.as_dict())
    return summary


class DockerDiscoveryService:
    """Runs Docker inventory reconciliation and owns the event listener."""

    def __init__(self, app: Application, machine: Machine, provider: DockerProvider) -> None:
        self.app = app
        self.machine = machine
        self.provider = provider
        self.listener: DockerEventListener | None = None

    def reconcile(self, reason: str = "scheduled") -> DockerReconcileSummary:
        trigger = "event" if reason.startswith("docker-event") else reason[:16]
        scan = begin_scan(self.machine, kind="docker", trigger=trigger, provider="docker")
        result = self.provider.inventory()  # Docker API queried with no transaction open
        summary = apply_docker_inventory(self.machine, scan, result)
        state = self.app.docker_provider
        if result.available:
            changed = state.update(
                "ok",
                f"{summary.containers} containers",
                server_version=result.server_version,
            )
        else:
            changed = state.update("unavailable", result.error or "Docker unavailable")
        if changed:
            self._record_availability_change(result)
        if self.app.conflicts_ready:
            refresh_conflicts(self.machine)
        notify("docker", "docker.reconciled", {"available": result.available, "reason": reason})
        return summary

    def _record_availability_change(self, result: DockerInventoryResult) -> None:
        with write_transaction():
            if result.available:
                spec = EventSpec(
                    "docker.available",
                    f"Docker discovery available (engine {result.server_version or 'unknown'})",
                    entity_type="provider",
                    entity_id="docker",
                )
            else:
                spec = EventSpec(
                    "docker.unavailable",
                    f"Docker discovery unavailable: {result.error}",
                    severity="warning",
                    entity_type="provider",
                    entity_id="docker",
                    details={"error": result.error},
                )
            record_events(self.machine, [spec])

    def start_listener(self, request_refresh: Any) -> None:
        if not docker_sdk_available():
            return
        self.listener = DockerEventListener(self.provider.event_stream, request_refresh)
        self.listener.start()

    def stop(self) -> None:
        if self.listener is not None:
            self.listener.stop()
        self.provider.close()
