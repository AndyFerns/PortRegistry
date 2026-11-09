"""Declarative registry manifests (``portregistry.toml``): apply and export.

Format (version 1)::

    version = 1

    [[service]]
    name = "web"
    expected_executable = "node"
    expected_working_directory = "."      # relative paths are resolved by the client
    description = "Frontend dev server"

      [[service.port]]
      port = 3000
      protocol = "tcp"                   # default tcp
      address = "*"                      # default * (any address)

    [[reservation]]                      # reservations without a service
    port = 5432
    description = "Shared Postgres"

Semantics:

* Services are matched by name (case-insensitive); keys present in the
  manifest are applied, keys omitted are left unchanged.
* Reservations are matched by (service, protocol, port, address); released
  ones are reactivated.
* Items created or touched by a manifest record its ``source``. With
  ``prune``, items from the same source that are no longer in the manifest are
  released (reservations) or deleted (services). Nothing else is ever pruned.
* Everything is validated before any write; the apply is one transaction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from django.utils import timezone

from portregistry.core.addresses import format_endpoint
from portregistry.django_app.models import Machine, PortReservation, Service
from portregistry.exceptions import ValidationError
from portregistry.services import registry, reservations
from portregistry.services.conflict_store import refresh_conflicts
from portregistry.services.db import write_transaction
from portregistry.services.history import EventSpec, record_events

SERVICE_KEYS = set(registry.SERVICE_FIELDS)
PORT_KEYS = {"port", "protocol", "address", "description"}
MAX_ITEMS = 500


@dataclass
class Plan:
    source: str
    create_services: list[dict[str, Any]] = field(default_factory=list)
    update_services: list[tuple[Service, dict[str, Any]]] = field(default_factory=list)
    unchanged_services: list[str] = field(default_factory=list)
    create_reservations: list[dict[str, Any]] = field(default_factory=list)
    reactivate_reservations: list[tuple[PortReservation, dict[str, Any]]] = field(
        default_factory=list
    )
    unchanged_reservations: list[str] = field(default_factory=list)
    prune_reservations: list[PortReservation] = field(default_factory=list)
    prune_services: list[Service] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "services": {
                "create": [s["name"] for s in self.create_services],
                "update": [
                    {"name": svc.name, "fields": sorted(changes)}
                    for svc, changes in self.update_services
                ],
                "unchanged": self.unchanged_services,
                "prune": [s.name for s in self.prune_services],
            },
            "reservations": {
                "create": [r["label"] for r in self.create_reservations],
                "reactivate_or_update": [
                    format_endpoint(r.protocol, r.bind_address, r.port)
                    for r, _ in self.reactivate_reservations
                ],
                "unchanged": self.unchanged_reservations,
                "release": [
                    format_endpoint(r.protocol, r.bind_address, r.port)
                    for r in self.prune_reservations
                ],
            },
            "changes": self.change_count,
        }

    @property
    def change_count(self) -> int:
        return (
            len(self.create_services)
            + len(self.update_services)
            + len(self.create_reservations)
            + len(self.reactivate_reservations)
            + len(self.prune_reservations)
            + len(self.prune_services)
        )


def _err(path: str, message: str) -> ValidationError:
    return ValidationError("Invalid manifest.", {path: [message]})


def _port_entries(raw: Any, path: str) -> list[dict[str, Any]]:
    if raw is None:
        return []
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list) or not all(isinstance(r, dict) for r in raw):
        raise _err(path, "Must be an array of tables.")
    return raw


def build_plan(
    machine: Machine, document: dict[str, Any], source: str, *, prune: bool = False
) -> Plan:
    if not isinstance(document, dict):
        raise _err("document", "Expected a table/object.")
    unknown = set(document) - {"version", "service", "reservation"}
    if unknown:
        raise _err("document", f"Unknown top-level keys: {', '.join(sorted(unknown))}.")
    if document.get("version", 1) != 1:
        raise _err("version", "Only manifest version 1 is supported.")
    source = (source or "").strip()[:500]
    if not source:
        raise _err("source", "A source identifier (usually the manifest path) is required.")

    services_raw = _port_entries(document.get("service"), "service")
    loose_raw = _port_entries(document.get("reservation"), "reservation")
    if len(services_raw) + len(loose_raw) > MAX_ITEMS:
        raise _err("document", f"Too many items (max {MAX_ITEMS}).")

    plan = Plan(source=source)
    seen_names: set[str] = set()
    keep_reservation_ids: set[int] = set()
    keep_service_ids: set[int] = set()

    def plan_ports(
        entries: list[dict[str, Any]], service: Service | None, service_name: str | None, path: str
    ) -> None:
        for i, entry in enumerate(entries):
            extra = set(entry) - PORT_KEYS
            if extra:
                raise _err(f"{path}[{i}]", f"Unknown keys: {', '.join(sorted(extra))}.")
            payload = {
                "port": entry.get("port"),
                "protocol": entry.get("protocol", "tcp"),
                "bind_address": entry.get("address", "*"),
            }
            if "description" in entry:
                payload["description"] = entry["description"]
            try:
                cleaned = reservations.validate_reservation_data(payload, machine)
            except ValidationError as exc:
                raise ValidationError(
                    "Invalid manifest.",
                    {f"{path}[{i}].{k}": v for k, v in exc.field_errors.items()},
                ) from exc
            label = format_endpoint(cleaned["protocol"], cleaned["bind_address"], cleaned["port"])
            label_full = f"{label} ({service_name})" if service_name else label
            existing = None
            if service is not None or service_name is None:
                existing = (
                    PortReservation.objects.filter(
                        machine=machine,
                        service=service,
                        protocol=cleaned["protocol"],
                        port=cleaned["port"],
                        bind_address=cleaned["bind_address"],
                    )
                    .order_by("status", "id")
                    .first()
                )
            if existing is None:
                plan.create_reservations.append(
                    {**cleaned, "service_name": service_name, "label": label_full}
                )
                continue
            keep_reservation_ids.add(existing.pk)
            changes: dict[str, Any] = {}
            if existing.status != "active":
                changes["status"] = "active"
            if "description" in cleaned and cleaned["description"] != existing.description:
                changes["description"] = cleaned["description"]
            if existing.managed_source != source:
                changes["managed_source"] = source
            if changes:
                plan.reactivate_reservations.append((existing, changes))
            else:
                plan.unchanged_reservations.append(label_full)

    for i, raw in enumerate(services_raw):
        path = f"service[{i}]"
        extra = set(raw) - SERVICE_KEYS - {"port"}
        if extra:
            raise _err(path, f"Unknown keys: {', '.join(sorted(extra))}.")
        fields = {k: v for k, v in raw.items() if k in SERVICE_KEYS}
        name = str(fields.get("name") or "").strip()
        if not name:
            raise _err(f"{path}.name", "This field is required.")
        if name.lower() in seen_names:
            raise _err(f"{path}.name", f"Service '{name}' appears twice in the manifest.")
        seen_names.add(name.lower())
        existing_svc = Service.objects.filter(machine=machine, name__iexact=name).first()
        try:
            cleaned = registry.validate_service_data(
                fields, machine, instance=existing_svc, partial=existing_svc is not None
            )
        except ValidationError as exc:
            raise ValidationError(
                "Invalid manifest.", {f"{path}.{k}": v for k, v in exc.field_errors.items()}
            ) from exc
        if existing_svc is None:
            plan.create_services.append(cleaned)
        else:
            keep_service_ids.add(existing_svc.pk)
            changes = {k: v for k, v in cleaned.items() if getattr(existing_svc, k) != v}
            if existing_svc.managed_source != source:
                changes["managed_source"] = source
            if changes:
                plan.update_services.append((existing_svc, changes))
            else:
                plan.unchanged_services.append(existing_svc.name)
        plan_ports(
            _port_entries(raw.get("port"), f"{path}.port"),
            existing_svc,
            cleaned.get("name", name),
            f"{path}.port",
        )

    plan_ports(loose_raw, None, None, "reservation")

    if prune:
        plan.prune_reservations = list(
            PortReservation.objects.filter(
                machine=machine, managed_source=source, status="active"
            ).exclude(pk__in=keep_reservation_ids)
        )
        plan.prune_services = list(
            Service.objects.filter(machine=machine, managed_source=source).exclude(
                pk__in=keep_service_ids
            )
        )
    return plan


def apply_manifest(
    machine: Machine,
    document: dict[str, Any],
    source: str,
    *,
    prune: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    plan = build_plan(machine, document, source, prune=prune)
    result = plan.as_dict()
    result["dry_run"] = dry_run
    if dry_run or plan.change_count == 0:
        result["applied"] = False
        return result

    now = timezone.now()
    events: list[EventSpec] = []
    with write_transaction():
        by_name: dict[str, Service] = {}
        for data in plan.create_services:
            svc = Service.objects.create(machine=machine, managed_source=plan.source, **data)
            by_name[svc.name.lower()] = svc
            events.append(
                EventSpec(
                    "service.created",
                    f"Service '{svc.name}' created from manifest",
                    entity_type="service",
                    entity_id=svc.pk,
                    details={"source": plan.source},
                )
            )
        for svc, changes in plan.update_services:
            for key, value in changes.items():
                setattr(svc, key, value)
            svc.save()
            by_name[svc.name.lower()] = svc
            events.append(
                EventSpec(
                    "service.updated",
                    f"Service '{svc.name}' updated from manifest ({', '.join(sorted(changes))})",
                    entity_type="service",
                    entity_id=svc.pk,
                    details={"source": plan.source},
                )
            )
        for data in plan.create_reservations:
            service_name = data.pop("service_name")
            data.pop("label")
            service = None
            if service_name:
                service = by_name.get(service_name.lower()) or Service.objects.get(
                    machine=machine, name__iexact=service_name
                )
            res = PortReservation.objects.create(
                machine=machine,
                service=service,
                status="active",
                managed_source=plan.source,
                **data,
            )
            events.append(
                EventSpec(
                    "reservation.created",
                    f"Reserved {format_endpoint(res.protocol, res.bind_address, res.port)} from manifest",
                    entity_type="reservation",
                    entity_id=res.pk,
                    details={"source": plan.source},
                )
            )
        for res, changes in plan.reactivate_reservations:
            for key, value in changes.items():
                setattr(res, key, value)
            if changes.get("status") == "active":
                res.released_at = None
            res.save()
            events.append(
                EventSpec(
                    "reservation.updated",
                    f"Reservation #{res.pk} updated from manifest ({', '.join(sorted(changes))})",
                    entity_type="reservation",
                    entity_id=res.pk,
                    details={"source": plan.source},
                )
            )
        for res in plan.prune_reservations:
            res.status = "released"
            res.released_at = now
            res.save(update_fields=["status", "released_at", "updated_at"])
            events.append(
                EventSpec(
                    "reservation.released",
                    f"Released reservation #{res.pk} (no longer in manifest)",
                    entity_type="reservation",
                    entity_id=res.pk,
                    details={"source": plan.source},
                )
            )
        for svc in plan.prune_services:
            events.append(
                EventSpec(
                    "service.deleted",
                    f"Service '{svc.name}' deleted (no longer in manifest)",
                    entity_type="service",
                    entity_id=svc.pk,
                    details={"source": plan.source},
                )
            )
            svc.delete()
        events.append(
            EventSpec(
                "manifest.applied",
                f"Applied manifest {plan.source} ({plan.change_count} change(s))",
                entity_type="manifest",
                entity_id=plan.source[-64:],
                details=result,
            )
        )
        record_events(machine, events, now)
    refresh_conflicts(machine)
    result["applied"] = True
    return result


def export_registry(
    machine: Machine, *, service: str | None = None, include_released: bool = False
) -> dict[str, Any]:
    services = Service.objects.filter(machine=machine).order_by("name")
    if service:
        services = services.filter(name__iexact=service)
    res_qs = PortReservation.objects.filter(machine=machine).order_by("port", "protocol", "id")
    if not include_released:
        res_qs = res_qs.filter(status="active")

    def port_entry(r: PortReservation) -> dict[str, Any]:
        entry: dict[str, Any] = {"port": r.port, "protocol": r.protocol, "address": r.bind_address}
        if r.description:
            entry["description"] = r.description
        return entry

    out_services = []
    for svc in services:
        data: dict[str, Any] = {"name": svc.name}
        for key in registry.SERVICE_FIELDS:
            if key != "name" and getattr(svc, key):
                data[key] = getattr(svc, key)
        ports = [port_entry(r) for r in res_qs.filter(service=svc)]
        if ports:
            data["port"] = ports
        out_services.append(data)
    document: dict[str, Any] = {"version": 1, "service": out_services}
    if not service:
        loose = [port_entry(r) for r in res_qs.filter(service__isnull=True)]
        if loose:
            document["reservation"] = loose
    return document
