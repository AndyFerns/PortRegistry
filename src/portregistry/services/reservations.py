"""Advisory port reservations.

A reservation records intent to use a protocol/address/port. It never binds
the port and cannot prevent other programs from using it. Creating or updating
a reservation always succeeds when the input is valid; current occupancy and
overlaps are reported as conflicts rather than enforced.
"""

from __future__ import annotations

from typing import Any

from django.db.models import QuerySet
from django.utils import timezone

from portregistry.core.addresses import format_endpoint, normalize_bind_address
from portregistry.django_app.models import Conflict, Machine, PortReservation, Service
from portregistry.exceptions import NotFoundError, ValidationError
from portregistry.services.conflict_store import (
    active_conflicts,
    check_reservation_candidate,
    refresh_conflicts,
)
from portregistry.services.conflicts import Finding, ReservationView
from portregistry.services.db import write_transaction
from portregistry.services.history import EventSpec, record_events
from portregistry.services.validation import (
    Errors,
    clean_port,
    clean_protocol,
    clean_text,
    reject_unknown,
)

RESERVATION_FIELDS = {
    "port",
    "protocol",
    "bind_address",
    "service",
    "status",
    "description",
    "machine",
}
STATUSES = ("active", "released")


def reservation_snapshot(res: PortReservation) -> dict[str, Any]:
    return {
        "id": res.pk,
        "port": res.port,
        "protocol": res.protocol,
        "bind_address": res.bind_address,
        "status": res.status,
        "service_id": res.service_id,
        "service": res.service.name if res.service_id and res.service else None,
        "description": res.description,
    }


def _resolve_service(value: Any, machine: Machine, errors: Errors) -> Service | None:
    if value in (None, "", 0):
        return None
    qs = Service.objects.filter(machine=machine)
    if isinstance(value, bool):
        errors.add("service", "Service must be an id or a name.")
        return None
    if isinstance(value, int) or (isinstance(value, str) and value.strip().isdigit()):
        service = qs.filter(pk=int(value)).first()
    elif isinstance(value, str):
        service = qs.filter(name__iexact=value.strip()).first()
    else:
        errors.add("service", "Service must be an id or a name.")
        return None
    if service is None:
        errors.add("service", f"Service '{value}' does not exist on this machine.")
    return service


def validate_reservation_data(
    data: dict[str, Any],
    machine: Machine,
    *,
    partial: bool = False,
    creating: bool = True,
) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValidationError(
            "Expected a JSON object.", {"non_field_errors": ["Expected an object."]}
        )
    errors = Errors()
    reject_unknown(data, RESERVATION_FIELDS, errors)
    cleaned: dict[str, Any] = {}
    if "port" in data:
        port = clean_port(data["port"], errors)
        if port is not None:
            cleaned["port"] = port
    elif not partial:
        errors.add("port", "This field is required.")
    if "protocol" in data:
        protocol = clean_protocol(data["protocol"], errors)
        if protocol is not None:
            cleaned["protocol"] = protocol
    elif not partial:
        cleaned["protocol"] = "tcp"
    if "bind_address" in data or not partial:
        raw = data.get("bind_address")
        if raw is not None and not isinstance(raw, str):
            errors.add("bind_address", "Must be a string.")
        else:
            try:
                cleaned["bind_address"] = normalize_bind_address(raw)
            except ValueError:
                errors.add(
                    "bind_address",
                    "Enter an IPv4/IPv6 address, 0.0.0.0, :: or * (any address).",
                )
    if "service" in data:
        cleaned["service"] = _resolve_service(data["service"], machine, errors)
    if "status" in data:
        status = data["status"]
        if status not in STATUSES:
            errors.add("status", "Status must be 'active' or 'released'.")
        elif creating and status != "active":
            errors.add("status", "New reservations are always active.")
        else:
            cleaned["status"] = status
    description = clean_text(data, "description", errors, max_length=1000)
    if description is not None:
        cleaned["description"] = description
    if "machine" in data and str(data["machine"]) != str(machine.uuid):
        errors.add("machine", "Only the local machine is supported in this release.")
    errors.raise_if_any("Invalid reservation.")
    return cleaned


def list_reservations(
    machine: Machine | None = None,
    *,
    status: str | None = None,
    protocol: str | None = None,
    port: int | None = None,
    service_id: int | None = None,
) -> QuerySet[PortReservation]:
    qs = PortReservation.objects.select_related("service", "machine")
    if machine is not None:
        qs = qs.filter(machine=machine)
    if status and status != "all":
        qs = qs.filter(status=status)
    if protocol:
        qs = qs.filter(protocol=protocol)
    if port is not None:
        qs = qs.filter(port=port)
    if service_id is not None:
        qs = qs.filter(service_id=service_id)
    return qs.order_by("port", "protocol", "id")


def get_reservation(reservation_id: Any, machine: Machine | None = None) -> PortReservation:
    qs = PortReservation.objects.select_related("service", "machine")
    if machine is not None:
        qs = qs.filter(machine=machine)
    try:
        return qs.get(pk=int(reservation_id))
    except (ValueError, TypeError, PortReservation.DoesNotExist) as exc:
        raise NotFoundError(f"Reservation '{reservation_id}' not found.") from exc


def conflicts_for(res: PortReservation) -> list[Conflict]:
    return list(active_conflicts(res.machine, reservation_id=res.pk))


def create_reservation(
    machine: Machine, data: dict[str, Any]
) -> tuple[PortReservation, list[Conflict]]:
    cleaned = validate_reservation_data(data, machine)
    with write_transaction():
        res = PortReservation.objects.create(machine=machine, status="active", **cleaned)
        record_events(
            machine,
            [
                EventSpec(
                    "reservation.created",
                    f"Reserved {format_endpoint(res.protocol, res.bind_address, res.port)}"
                    + (f" for '{res.service.name}'" if res.service else ""),
                    entity_type="reservation",
                    entity_id=res.pk,
                    details=reservation_snapshot(res),
                )
            ],
        )
    refresh_conflicts(machine)
    return res, conflicts_for(res)


def update_reservation(
    res: PortReservation, data: dict[str, Any], *, partial: bool = True
) -> tuple[PortReservation, list[Conflict]]:
    machine = res.machine
    cleaned = validate_reservation_data(data, machine, partial=partial, creating=False)
    if not partial:
        cleaned.setdefault("service", None)
        cleaned.setdefault("description", "")
    changes: dict[str, Any] = {}
    for key, value in cleaned.items():
        current = getattr(res, key)
        if current != value:
            changes[key] = {
                "from": current.name if isinstance(current, Service) else current,
                "to": value.name if isinstance(value, Service) else value,
            }
    if not changes:
        return res, conflicts_for(res)
    with write_transaction():
        for key, value in cleaned.items():
            setattr(res, key, value)
        if "status" in changes:
            res.released_at = timezone.now() if res.status == "released" else None
        res.save()
        record_events(
            machine,
            [
                EventSpec(
                    "reservation.updated",
                    f"Reservation #{res.pk} updated ({', '.join(sorted(changes))})",
                    entity_type="reservation",
                    entity_id=res.pk,
                    details={"changes": changes, "reservation": reservation_snapshot(res)},
                )
            ],
        )
    refresh_conflicts(machine)
    return res, conflicts_for(res)


def release_reservation(res: PortReservation) -> PortReservation:
    if res.status == "released":
        return res
    machine = res.machine
    with write_transaction():
        res.status = "released"
        res.released_at = timezone.now()
        res.save(update_fields=["status", "released_at", "updated_at"])
        record_events(
            machine,
            [
                EventSpec(
                    "reservation.released",
                    f"Released reservation #{res.pk} "
                    f"({format_endpoint(res.protocol, res.bind_address, res.port)})",
                    entity_type="reservation",
                    entity_id=res.pk,
                    details=reservation_snapshot(res),
                )
            ],
        )
    refresh_conflicts(machine)
    return res


def delete_reservation(res: PortReservation) -> dict[str, Any]:
    """Hard delete. The history event keeps a snapshot; past events are kept."""
    machine = res.machine
    snapshot = reservation_snapshot(res)
    with write_transaction():
        record_events(
            machine,
            [
                EventSpec(
                    "reservation.deleted",
                    f"Deleted reservation #{res.pk} "
                    f"({format_endpoint(res.protocol, res.bind_address, res.port)})",
                    entity_type="reservation",
                    entity_id=res.pk,
                    details=snapshot,
                )
            ],
        )
        res.delete()
    refresh_conflicts(machine)
    return snapshot


def check_reservation(
    machine: Machine, data: dict[str, Any], *, exclude_id: int | None = None
) -> list[Finding]:
    """Dry run: what would happen if this reservation were created/updated?"""
    payload = {k: v for k, v in data.items() if k != "status"}
    cleaned = validate_reservation_data(payload, machine)
    service = cleaned.get("service")
    candidate = ReservationView(
        id=exclude_id or 0,
        protocol=cleaned.get("protocol", "tcp"),
        bind_address=cleaned.get("bind_address", "*"),
        port=cleaned["port"],
        service_id=service.pk if service else None,
        description=cleaned.get("description", ""),
    )
    return check_reservation_candidate(machine, candidate)
