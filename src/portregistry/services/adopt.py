"""One-click adoption: turn an observed endpoint/process into a registered service.

PortRegistry already knows the executable, working directory, project and ports
of a running process; adopting pre-fills a service definition and reservations
from that knowledge. The proposal is a plain dict that the user may edit before
applying it.
"""

from __future__ import annotations

import re
from typing import Any

from portregistry.core.addresses import format_endpoint
from portregistry.core.well_known import category_for, label_for
from portregistry.django_app.models import (
    DockerPortMapping,
    Machine,
    ProcessInstance,
    Service,
    Socket,
)
from portregistry.exceptions import NotFoundError, ValidationError
from portregistry.services import registry, reservations
from portregistry.services.conflict_store import refresh_conflicts
from portregistry.services.db import write_transaction

_SLUG = re.compile(r"[^a-zA-Z0-9._ -]+")


def _clean_name(value: str) -> str:
    return _SLUG.sub("-", value).strip(" -._")[:100] or "service"


def _unique_name(machine: Machine, base: str) -> str:
    name = _clean_name(base)
    if not Service.objects.filter(machine=machine, name__iexact=name).exists():
        return name
    for i in range(2, 100):
        candidate = f"{name}-{i}"[:100]
        if not Service.objects.filter(machine=machine, name__iexact=candidate).exists():
            return candidate
    return f"{name}-{Service.objects.count() + 1}"


def _exe_basename(exe: str, name: str) -> str:
    if exe:
        return exe.replace("\\", "/").rsplit("/", 1)[-1]
    return name


def _docker_for(sock: Socket) -> DockerPortMapping | None:
    return (
        DockerPortMapping.objects.filter(
            active=True,
            host_port=sock.port,
            protocol=sock.protocol,
            container__present=True,
            container__machine_id=sock.machine_id,
        )
        .select_related("container")
        .first()
    )


def propose(*, socket_id: int | None = None, process_id: int | None = None) -> dict[str, Any]:
    """Build an editable proposal for a service from observed state."""
    sock: Socket | None = None
    proc: ProcessInstance | None = None
    if socket_id is not None:
        try:
            sock = Socket.objects.select_related("process", "machine").get(pk=socket_id)
        except Socket.DoesNotExist as exc:
            raise NotFoundError(f"Endpoint {socket_id} not found.") from exc
        proc = sock.process
    elif process_id is not None:
        try:
            proc = ProcessInstance.objects.select_related("machine").get(pk=process_id)
        except ProcessInstance.DoesNotExist as exc:
            raise NotFoundError(f"Process {process_id} not found.") from exc
    else:
        raise ValidationError(
            "Choose an endpoint or a process to adopt.", {"socket": ["Required."]}
        )

    machine = sock.machine if sock is not None else proc.machine  # type: ignore[union-attr]
    docker = _docker_for(sock) if sock is not None else None
    endpoints: list[Socket] = []
    if proc is not None:
        endpoints = list(proc.sockets.filter(active=True).order_by("port", "protocol"))
    elif sock is not None:
        endpoints = [sock]

    if docker is not None:
        labels = docker.container.labels or {}
        base = labels.get("com.docker.compose.service") or docker.container.name
        project = labels.get("com.docker.compose.project", "")
        name_hint = f"{project}-{base}" if project and project not in base else base
        expected_exe = f"docker:{docker.container.name}"
        cwd = ""
        source = f"Docker container {docker.container.name} ({docker.container.image_ref})"
    elif proc is not None:
        name_hint = proc.project_name or (proc.name or "service").removesuffix(".exe")
        expected_exe = _exe_basename(proc.exe, proc.name)
        cwd = proc.cwd if proc.project_name or proc.cwd else ""
        source = f"process {proc.name or '?'} (pid {proc.pid})"
    else:
        assert sock is not None
        name_hint = label_for(sock.port, sock.protocol) or f"port-{sock.port}"
        expected_exe = ""
        cwd = ""
        source = (
            f"endpoint {format_endpoint(sock.protocol, sock.address, sock.port)} (owner unknown)"
        )

    category = ""
    for ep in endpoints:
        category = category_for(ep.port, ep.protocol) or ""
        if category:
            break

    selected_ids = {sock.pk} if sock is not None and proc is None else {e.pk for e in endpoints}
    if sock is not None:
        selected_ids.add(sock.pk)
    description = f"Adopted from {source}."
    if proc is not None and proc.project_root:
        description += f" Project: {proc.project_root}"
    return {
        "source": source,
        "socket_id": sock.pk if sock is not None else None,
        "process_id": proc.pk if proc is not None else None,
        "service": {
            "name": _unique_name(machine, name_hint),
            "category": category,
            "description": description[:2000],
            "expected_executable": expected_exe[:500],
            "expected_working_directory": (cwd or "")[:500],
        },
        "endpoints": [
            {
                "socket_id": ep.pk,
                "endpoint": format_endpoint(ep.protocol, ep.address, ep.port),
                "protocol": ep.protocol,
                "port": ep.port,
                "bind_address": ep.address,
                "label": label_for(ep.port, ep.protocol),
                "selected": ep.pk in selected_ids,
            }
            for ep in endpoints
        ],
    }


def apply(machine: Machine, payload: dict[str, Any]) -> dict[str, Any]:
    """Create the service and selected reservations from an (edited) proposal.

    The service and its reservations are validated first; nothing is written if
    any part is invalid. Reservation bind addresses default to the observed
    address; ``reserve_any_address`` reserves ``*`` instead.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("service"), dict):
        raise ValidationError(
            "Expected {service: {...}, socket_ids: [...]}.", {"service": ["Required."]}
        )
    service_data = dict(payload["service"])
    socket_ids = payload.get("socket_ids", [])
    if not isinstance(socket_ids, list) or not all(
        isinstance(i, int) and not isinstance(i, bool) for i in socket_ids
    ):
        raise ValidationError(
            "Invalid endpoints.", {"socket_ids": ["Must be a list of endpoint ids."]}
        )
    any_address = bool(payload.get("reserve_any_address", False))

    cleaned_service = registry.validate_service_data(service_data, machine)
    sockets = list(Socket.objects.filter(pk__in=socket_ids, machine=machine))
    missing = set(socket_ids) - {s.pk for s in sockets}
    if missing:
        raise ValidationError(
            "Unknown endpoints.", {"socket_ids": [f"Not found: {sorted(missing)}"]}
        )
    reservation_payloads = []
    seen: set[tuple[str, str, int]] = set()
    for sock in sorted(sockets, key=lambda s: (s.port, s.protocol, s.address)):
        address = "*" if any_address else sock.address
        key = (sock.protocol, address, sock.port)
        if key in seen:
            continue
        seen.add(key)
        reservation_payloads.append(
            reservations.validate_reservation_data(
                {
                    "port": sock.port,
                    "protocol": sock.protocol,
                    "bind_address": address,
                    "description": f"Adopted from observed endpoint {format_endpoint(sock.protocol, sock.address, sock.port)}",
                },
                machine,
            )
        )

    from portregistry.django_app.models import PortReservation
    from portregistry.services.history import EventSpec, record_events
    from portregistry.services.registry import service_snapshot
    from portregistry.services.reservations import reservation_snapshot

    with write_transaction():
        service = Service.objects.create(machine=machine, **cleaned_service)
        created = [
            PortReservation.objects.create(
                machine=machine, service=service, status="active", **data
            )
            for data in reservation_payloads
        ]
        record_events(
            machine,
            [
                EventSpec(
                    "service.created",
                    f"Service '{service.name}' adopted with {len(created)} reservation(s)",
                    entity_type="service",
                    entity_id=service.pk,
                    details={**service_snapshot(service), "adopted": True},
                ),
                *[
                    EventSpec(
                        "reservation.created",
                        f"Reserved {format_endpoint(r.protocol, r.bind_address, r.port)} for '{service.name}'",
                        entity_type="reservation",
                        entity_id=r.pk,
                        details=reservation_snapshot(r),
                    )
                    for r in created
                ],
            ],
        )
    refresh_conflicts(machine)
    return {"service": service, "reservations": created}
