"""Explicit JSON representations of persisted entities."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from portregistry.core.addresses import format_endpoint
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
from portregistry.services.conflicts import Finding


def iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def machine_dict(m: Machine) -> dict[str, Any]:
    return {
        "uuid": str(m.uuid),
        "hostname": m.hostname,
        "os_name": m.os_name,
        "os_version": m.os_version,
        "os_detail": m.os_detail,
        "architecture": m.architecture,
        "is_local": m.is_local,
        "online": m.online,
        "created_at": iso(m.created_at),
        "last_seen": iso(m.last_seen),
    }


def process_summary(p: ProcessInstance | None) -> dict[str, Any] | None:
    if p is None:
        return None
    return {
        "id": p.pk,
        "pid": p.pid,
        "name": p.name,
        "exe": p.exe,
        "username": p.username,
        "identity_complete": p.identity_complete,
        "active": p.active,
    }


def process_dict(p: ProcessInstance, *, sockets: list[Socket] | None = None) -> dict[str, Any]:
    data = {
        "id": p.pk,
        "machine": str(p.machine.uuid) if p.machine_id else None,
        "pid": p.pid,
        "name": p.name,
        "exe": p.exe,
        "cmdline": p.cmdline,
        "username": p.username,
        "ppid": p.ppid,
        "cwd": p.cwd,
        "create_time": p.create_time,
        "started_at": iso(p.started_at),
        "identity_key": p.identity_key,
        "identity_hash": p.identity_hash,
        "identity_complete": p.identity_complete,
        "metadata_errors": p.metadata_errors,
        "first_seen": iso(p.first_seen),
        "last_seen": iso(p.last_seen),
        "active": p.active,
        "ended_at": iso(p.ended_at),
    }
    if hasattr(p, "active_socket_count"):
        data["active_socket_count"] = p.active_socket_count
    if sockets is not None:
        data["sockets"] = [socket_dict(s, include_process=False) for s in sockets]
    return data


def mapping_dict(m: DockerPortMapping, *, include_container: bool = False) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": m.pk,
        "container_port": m.container_port,
        "protocol": m.protocol,
        "host_ip": m.host_ip or None,
        "host_port": m.host_port,
        "published": m.published,
        "active": m.active,
    }
    if include_container:
        data["container"] = {
            "id": m.container.pk,
            "container_id": m.container.short_id,
            "name": m.container.name,
            "image": m.container.image_ref,
            "status": m.container.status,
        }
    return data


def socket_dict(
    s: Socket,
    *,
    include_process: bool = True,
    docker: list[DockerPortMapping] | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": s.pk,
        "machine": str(s.machine.uuid) if include_process and s.machine_id else None,
        "protocol": s.protocol,
        "family": s.family,
        "address": s.address,
        "port": s.port,
        "endpoint": format_endpoint(s.protocol, s.address, s.port),
        "state": s.state,
        "pid": s.pid,
        "owner_resolved": s.process_id is not None,
        "active": s.active,
        "first_seen": iso(s.first_seen),
        "last_seen": iso(s.last_seen),
        "ended_at": iso(s.ended_at),
        "last_scan_id": s.last_scan_id,
    }
    if include_process:
        data["process"] = process_summary(s.process)
    if docker is not None:
        data["docker"] = [mapping_dict(m, include_container=True) for m in docker]
    return data


def service_dict(s: Service) -> dict[str, Any]:
    data = {
        "id": s.pk,
        "machine": str(s.machine.uuid) if s.machine_id else None,
        "name": s.name,
        "description": s.description,
        "category": s.category,
        "expected_executable": s.expected_executable,
        "expected_working_directory": s.expected_working_directory,
        "documentation_url": s.documentation_url,
        "notes": s.notes,
        "created_at": iso(s.created_at),
        "updated_at": iso(s.updated_at),
    }
    if hasattr(s, "reservation_count"):
        data["active_reservation_count"] = s.reservation_count
    return data


def conflict_dict(c: Conflict) -> dict[str, Any]:
    return {
        "id": c.pk,
        "fingerprint": c.fingerprint,
        "type": c.type,
        "severity": c.severity,
        "certainty": c.certainty,
        "title": c.title,
        "explanation": c.explanation,
        "evidence": c.evidence,
        "protocol": c.protocol or None,
        "port": c.port,
        "address": c.address or None,
        "reservation_id": c.reservation_id,
        "related_reservation_id": c.related_reservation_id,
        "service_id": c.service_id,
        "socket_id": c.socket_id,
        "process_id": c.process_id,
        "active": c.active,
        "first_seen": iso(c.first_seen),
        "last_seen": iso(c.last_seen),
        "resolved_at": iso(c.resolved_at),
    }


def finding_dict(f: Finding) -> dict[str, Any]:
    return {
        "type": f.type.value,
        "severity": f.severity,
        "certainty": f.certainty,
        "title": f.title,
        "explanation": f.explanation,
        "evidence": f.evidence,
        "protocol": f.protocol or None,
        "port": f.port,
        "address": f.address or None,
        "related_reservation_id": f.related_reservation_id,
    }


def reservation_dict(r: PortReservation, conflicts: list[Conflict] | None = None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": r.pk,
        "machine": str(r.machine.uuid) if r.machine_id else None,
        "port": r.port,
        "protocol": r.protocol,
        "bind_address": r.bind_address,
        "endpoint": format_endpoint(r.protocol, r.bind_address, r.port),
        "status": r.status,
        "service": (
            {"id": r.service.pk, "name": r.service.name} if r.service_id and r.service else None
        ),
        "description": r.description,
        "created_at": iso(r.created_at),
        "updated_at": iso(r.updated_at),
        "released_at": iso(r.released_at),
        "advisory": True,
    }
    if conflicts is not None:
        data["conflicts"] = [conflict_dict(c) for c in conflicts]
        data["attention"] = r.status == "active" and any(c.severity != "info" for c in conflicts)
        data["display_status"] = "attention" if data["attention"] else r.status
    return data


def scan_dict(s: DiscoveryScan) -> dict[str, Any]:
    return {
        "id": s.pk,
        "kind": s.kind,
        "trigger": s.trigger,
        "provider": s.provider,
        "scope": {
            "protocols": [p for p in s.scope_protocols.split(",") if p],
            "port": s.scope_port,
        },
        "status": s.status,
        "started_at": iso(s.started_at),
        "finished_at": iso(s.finished_at),
        "duration_ms": s.duration_ms,
        "socket_count": s.socket_count,
        "process_count": s.process_count,
        "resolved_process_count": s.resolved_process_count,
        "resolution_failures": s.resolution_failures,
        "unknown_owner_count": s.unknown_owner_count,
        "container_count": s.container_count,
        "appeared": s.appeared_count,
        "disappeared": s.disappeared_count,
        "errors": s.errors,
        "message": s.message,
    }


def event_dict(e: Event) -> dict[str, Any]:
    return {
        "id": e.pk,
        "timestamp": iso(e.timestamp),
        "type": e.type,
        "severity": e.severity,
        "entity_type": e.entity_type or None,
        "entity_id": e.entity_id or None,
        "summary": e.summary,
        "details": e.details,
        "machine": str(e.machine.uuid) if e.machine_id and e.machine else None,
    }


def container_dict(c: DockerContainer, *, include_mappings: bool = True) -> dict[str, Any]:
    data: dict[str, Any] = {
        "id": c.pk,
        "container_id": c.container_id,
        "short_id": c.short_id,
        "name": c.name,
        "image": c.image_ref,
        "image_id": c.image.image_id if c.image_id and c.image else None,
        "image_repository": c.image.repository if c.image_id and c.image else None,
        "image_tag": c.image.tag if c.image_id and c.image else None,
        "status": c.status,
        "created_at": iso(c.created_at_docker),
        "started_at": iso(c.started_at),
        "labels": c.labels,
        "networks": c.networks,
        "present": c.present,
        "first_seen": iso(c.first_seen),
        "last_seen": iso(c.last_seen),
        "removed_at": iso(c.removed_at),
    }
    if include_mappings:
        data["ports"] = [mapping_dict(m) for m in c.port_mappings.all()]
    return data
