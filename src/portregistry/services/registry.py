"""Service registry: user-declared services (persistent intent)."""

from __future__ import annotations

from typing import Any

from django.core.exceptions import ValidationError as DjangoValidationError
from django.core.validators import URLValidator
from django.db.models import Count, Q, QuerySet

from portregistry.django_app.models import Machine, Service
from portregistry.exceptions import NotFoundError, ValidationError
from portregistry.services.conflict_store import refresh_conflicts
from portregistry.services.db import write_transaction
from portregistry.services.history import EventSpec, record_events
from portregistry.services.validation import Errors, clean_text, reject_unknown

SERVICE_FIELDS = {
    "name": 100,
    "description": 2000,
    "category": 50,
    "expected_executable": 500,
    "expected_working_directory": 500,
    "documentation_url": 500,
    "notes": 5000,
}
SUGGESTED_CATEGORIES = [
    "application",
    "database",
    "web",
    "cache",
    "queue",
    "dev-tool",
    "homelab",
    "monitoring",
    "system",
    "other",
]

_url_validator = URLValidator(schemes=["http", "https"])


def service_snapshot(service: Service) -> dict[str, Any]:
    return {
        "id": service.pk,
        "name": service.name,
        "category": service.category,
        "expected_executable": service.expected_executable,
        "expected_working_directory": service.expected_working_directory,
    }


def validate_service_data(
    data: dict[str, Any],
    machine: Machine,
    *,
    instance: Service | None = None,
    partial: bool = False,
) -> dict[str, str]:
    if not isinstance(data, dict):
        raise ValidationError(
            "Expected a JSON object.", {"non_field_errors": ["Expected an object."]}
        )
    errors = Errors()
    reject_unknown(data, set(SERVICE_FIELDS) | {"machine"}, errors)
    cleaned: dict[str, str] = {}
    for field, max_length in SERVICE_FIELDS.items():
        value = clean_text(
            data,
            field,
            errors,
            max_length=max_length,
            required=(field == "name" and not partial),
        )
        if value is not None:
            cleaned[field] = value
    if partial and "name" in cleaned and not cleaned["name"]:
        errors.add("name", "This field may not be blank.")
    url = cleaned.get("documentation_url")
    if url:
        try:
            _url_validator(url)
        except DjangoValidationError:
            errors.add("documentation_url", "Enter a valid http(s) URL.")
    if "machine" in data and str(data["machine"]) != str(machine.uuid):
        errors.add("machine", "Only the local machine is supported in this release.")
    name = cleaned.get("name")
    if name:
        clash = Service.objects.filter(machine=machine, name__iexact=name)
        if instance is not None:
            clash = clash.exclude(pk=instance.pk)
        if clash.exists():
            errors.add("name", f"A service named '{name}' already exists on this machine.")
    errors.raise_if_any("Invalid service.")
    return cleaned


def list_services(machine: Machine | None = None, search: str | None = None) -> QuerySet[Service]:
    qs = Service.objects.all()
    if machine is not None:
        qs = qs.filter(machine=machine)
    if search:
        qs = qs.filter(
            Q(name__icontains=search)
            | Q(description__icontains=search)
            | Q(category__icontains=search)
            | Q(expected_executable__icontains=search)
        )
    return qs.annotate(
        reservation_count=Count("reservations", filter=Q(reservations__status="active"))
    ).order_by("name")


def get_service(service_id: int | str, machine: Machine | None = None) -> Service:
    qs = Service.objects.all() if machine is None else Service.objects.filter(machine=machine)
    try:
        return qs.get(pk=int(service_id))
    except (ValueError, TypeError, Service.DoesNotExist):
        pass
    match = qs.filter(name__iexact=str(service_id)).first()
    if match is None:
        raise NotFoundError(f"Service '{service_id}' not found.")
    return match


def create_service(machine: Machine, data: dict[str, Any]) -> Service:
    cleaned = validate_service_data(data, machine)
    with write_transaction():
        service = Service.objects.create(machine=machine, **cleaned)
        record_events(
            machine,
            [
                EventSpec(
                    "service.created",
                    f"Service '{service.name}' registered",
                    entity_type="service",
                    entity_id=service.pk,
                    details=service_snapshot(service),
                )
            ],
        )
    refresh_conflicts(machine)
    return service


def update_service(service: Service, data: dict[str, Any], *, partial: bool = True) -> Service:
    machine = service.machine
    cleaned = validate_service_data(data, machine, instance=service, partial=partial)
    if not partial:
        for field in SERVICE_FIELDS:
            cleaned.setdefault(field, "")
    changes = {
        k: {"from": getattr(service, k), "to": v}
        for k, v in cleaned.items()
        if getattr(service, k) != v
    }
    if not changes:
        return service
    with write_transaction():
        for k, v in cleaned.items():
            setattr(service, k, v)
        service.save()
        record_events(
            machine,
            [
                EventSpec(
                    "service.updated",
                    f"Service '{service.name}' updated ({', '.join(sorted(changes))})",
                    entity_type="service",
                    entity_id=service.pk,
                    details={"changes": changes},
                )
            ],
        )
    refresh_conflicts(machine)
    return service


def delete_service(service: Service) -> dict[str, Any]:
    """Delete a service. Its reservations are kept but unlinked; history is kept."""
    machine = service.machine
    with write_transaction():
        unlinked = list(service.reservations.values_list("id", flat=True))
        snapshot = service_snapshot(service)
        record_events(
            machine,
            [
                EventSpec(
                    "service.deleted",
                    f"Service '{service.name}' deleted"
                    + (f"; {len(unlinked)} reservations kept but unlinked" if unlinked else ""),
                    severity="info",
                    entity_type="service",
                    entity_id=service.pk,
                    details={**snapshot, "unlinked_reservations": unlinked},
                )
            ],
        )
        service.delete()
    refresh_conflicts(machine)
    return {"deleted": snapshot, "unlinked_reservations": unlinked}
