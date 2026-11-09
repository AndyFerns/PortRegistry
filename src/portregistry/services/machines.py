"""Local machine identity records."""

from __future__ import annotations

import uuid

from django.utils import timezone

from portregistry.core.identity import machine_facts
from portregistry.django_app.models import Machine
from portregistry.services.db import write_transaction
from portregistry.services.history import EventSpec, record_events


def ensure_local_machine(machine_uuid: uuid.UUID) -> Machine:
    """Create or refresh the local machine row for the persisted machine UUID."""
    facts = machine_facts()
    with write_transaction():
        machine, created = Machine.objects.get_or_create(
            uuid=machine_uuid, defaults={**facts, "is_local": True}
        )
        changed = []
        for field, value in facts.items():
            if getattr(machine, field) != value:
                setattr(machine, field, value)
                changed.append(field)
        # Only one machine is local; demote others (e.g. restored database).
        Machine.objects.filter(is_local=True).exclude(pk=machine.pk).update(is_local=False)
        if not machine.is_local:
            machine.is_local = True
            changed.append("is_local")
        if changed:
            machine.save(update_fields=changed)
        if created:
            record_events(
                machine,
                [
                    EventSpec(
                        "machine.registered",
                        f"Machine {machine.hostname} registered",
                        entity_type="machine",
                        entity_id=str(machine.uuid),
                        details=facts,
                    )
                ],
            )
    return machine


def get_local_machine() -> Machine:
    return Machine.objects.get(is_local=True)


def set_machine_online(machine: Machine, online: bool, reason: str = "") -> None:
    now = timezone.now()
    with write_transaction():
        Machine.objects.filter(pk=machine.pk).update(online=online, last_seen=now)
        machine.online = online
        machine.last_seen = now
        record_events(
            machine,
            [
                EventSpec(
                    "machine.online" if online else "machine.offline",
                    (
                        f"PortRegistry daemon started on {machine.hostname}"
                        if online
                        else f"PortRegistry daemon stopped on {machine.hostname}"
                    ),
                    entity_type="machine",
                    entity_id=str(machine.uuid),
                    details={"reason": reason} if reason else {},
                )
            ],
        )


def touch_machine(machine: Machine) -> None:
    Machine.objects.filter(pk=machine.pk).update(last_seen=timezone.now())
