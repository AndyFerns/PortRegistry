"""Ignore rules ("known" endpoints) and noise settings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.db.models import QuerySet

from portregistry.config import NoiseConfig
from portregistry.core.addresses import format_endpoint, normalize_address
from portregistry.core.application import get_application, has_application
from portregistry.core.ignore import IgnoreRuleView, ephemeral_range
from portregistry.django_app.models import IgnoreRule, Machine, ProcessInstance, Socket
from portregistry.exceptions import NotFoundError, ValidationError
from portregistry.services.db import write_transaction
from portregistry.services.history import EventSpec, record_events
from portregistry.services.validation import Errors, clean_port, clean_text, reject_unknown

RULE_FIELDS = {
    "name",
    "enabled",
    "process_name",
    "exe",
    "protocol",
    "port_min",
    "port_max",
    "address",
    "suppress_conflicts",
    "quiet_history",
}


@dataclass(frozen=True)
class NoiseSettings:
    ephemeral: tuple[int, int] | None
    flap_window_seconds: float
    noise_retention_days: int


def noise_settings() -> NoiseSettings:
    cfg = get_application().config.noise if has_application() else NoiseConfig()
    return NoiseSettings(
        ephemeral=ephemeral_range() if cfg.ephemeral_udp else None,
        flap_window_seconds=cfg.flap_window_seconds,
        noise_retention_days=cfg.noise_retention_days,
    )


def rule_view(rule: IgnoreRule) -> IgnoreRuleView:
    return IgnoreRuleView(
        id=rule.pk,
        name=rule.name,
        process_name=rule.process_name,
        exe=rule.exe,
        protocol=rule.protocol,
        port_min=rule.port_min,
        port_max=rule.port_max,
        address=rule.address,
        suppress_conflicts=rule.suppress_conflicts,
        quiet_history=rule.quiet_history,
        enabled=rule.enabled,
    )


def active_rule_views(machine: Machine) -> list[IgnoreRuleView]:
    return [rule_view(r) for r in IgnoreRule.objects.filter(machine=machine, enabled=True)]


def list_rules(machine: Machine | None = None) -> QuerySet[IgnoreRule]:
    qs = IgnoreRule.objects.all()
    return qs if machine is None else qs.filter(machine=machine)


def get_rule(rule_id: Any) -> IgnoreRule:
    try:
        return IgnoreRule.objects.get(pk=int(rule_id))
    except (ValueError, TypeError, IgnoreRule.DoesNotExist) as exc:
        raise NotFoundError(f"Ignore rule '{rule_id}' not found.") from exc


def _bool(data: dict[str, Any], key: str, errors: Errors) -> bool | None:
    if key not in data:
        return None
    value = data[key]
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false", "on", "off", "1", "0"):
        return value.lower() in ("true", "on", "1")
    errors.add(key, "Must be true or false.")
    return None


def validate_rule_data(data: dict[str, Any], *, partial: bool = False) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValidationError(
            "Expected a JSON object.", {"non_field_errors": ["Expected an object."]}
        )
    errors = Errors()
    reject_unknown(data, RULE_FIELDS, errors)
    cleaned: dict[str, Any] = {}
    for field, max_length in (("name", 120), ("process_name", 255), ("exe", 500)):
        value = clean_text(
            data, field, errors, max_length=max_length, required=field == "name" and not partial
        )
        if value is not None:
            cleaned[field] = value
    if "protocol" in data:
        proto = str(data["protocol"] or "").strip().lower()
        if proto in ("", "any"):
            cleaned["protocol"] = ""
        elif proto in ("tcp", "udp"):
            cleaned["protocol"] = proto
        else:
            errors.add("protocol", "Protocol must be tcp, udp or any.")
    for key in ("port_min", "port_max"):
        if key in data:
            if data[key] in (None, ""):
                cleaned[key] = None
            else:
                port = clean_port(data[key], errors, field=key)
                if port is not None:
                    cleaned[key] = port
    if "address" in data:
        address = str(data["address"] or "").strip()
        if address in ("", "*"):
            cleaned["address"] = ""
        else:
            try:
                cleaned["address"] = normalize_address(address)[0]
            except ValueError:
                errors.add("address", "Enter an IP address, or leave empty for any.")
    for key in ("enabled", "suppress_conflicts", "quiet_history"):
        value = _bool(data, key, errors)
        if value is not None:
            cleaned[key] = value
    lo, hi = cleaned.get("port_min"), cleaned.get("port_max")
    if lo is not None and hi is not None and lo > hi:
        errors.add("port_max", "port_max must be greater than or equal to port_min.")
    if not partial and not any(
        cleaned.get(k)
        for k in ("process_name", "exe", "protocol", "port_min", "port_max", "address")
    ):
        errors.add(
            "non_field_errors",
            "A rule needs at least one condition (process, exe, protocol, port or address).",
        )
    errors.raise_if_any("Invalid ignore rule.")
    return cleaned


def _refresh(machine: Machine) -> None:
    from portregistry.services.conflict_store import refresh_conflicts

    refresh_conflicts(machine)


def create_rule(machine: Machine, data: dict[str, Any]) -> IgnoreRule:
    cleaned = validate_rule_data(data)
    with write_transaction():
        rule = IgnoreRule.objects.create(machine=machine, **cleaned)
        record_events(
            machine,
            [
                EventSpec(
                    "ignore.created",
                    f"Ignore rule '{rule.name}' added ({rule_view(rule).describe()})",
                    entity_type="ignore_rule",
                    entity_id=rule.pk,
                    details={"rule": rule_view(rule).describe()},
                )
            ],
        )
    _refresh(machine)
    return rule


def update_rule(rule: IgnoreRule, data: dict[str, Any]) -> IgnoreRule:
    cleaned = validate_rule_data(data, partial=True)
    if not cleaned:
        return rule
    with write_transaction():
        for key, value in cleaned.items():
            setattr(rule, key, value)
        rule.save()
        record_events(
            rule.machine,
            [
                EventSpec(
                    "ignore.updated",
                    f"Ignore rule '{rule.name}' updated ({', '.join(sorted(cleaned))})",
                    entity_type="ignore_rule",
                    entity_id=rule.pk,
                )
            ],
        )
    _refresh(rule.machine)
    return rule


def delete_rule(rule: IgnoreRule) -> dict[str, Any]:
    machine = rule.machine
    snapshot = {"id": rule.pk, "name": rule.name, "rule": rule_view(rule).describe()}
    with write_transaction():
        record_events(
            machine,
            [
                EventSpec(
                    "ignore.deleted",
                    f"Ignore rule '{rule.name}' removed",
                    entity_type="ignore_rule",
                    entity_id=rule.pk,
                    details=snapshot,
                )
            ],
        )
        rule.delete()
    _refresh(machine)
    return snapshot


def known_rule_data_for_socket(sock: Socket) -> dict[str, Any]:
    """The rule created by "mark as known" for an endpoint."""
    proc = sock.process
    endpoint = format_endpoint(sock.protocol, sock.address, sock.port)
    if proc is not None and proc.name:
        return {
            "name": f"Known: {proc.name} on {endpoint}"[:120],
            "process_name": proc.name,
            "protocol": sock.protocol,
            "port_min": sock.port,
            "port_max": sock.port,
        }
    return {
        "name": f"Known: {endpoint}"[:120],
        "protocol": sock.protocol,
        "port_min": sock.port,
        "port_max": sock.port,
        "address": sock.address,
    }


def known_rule_data_for_process(proc: ProcessInstance) -> dict[str, Any]:
    if not proc.name:
        raise ValidationError(
            "This process has no readable name; mark individual endpoints as known instead.",
            {"process": ["Process name unavailable."]},
        )
    return {"name": f"Known: {proc.name} (all ports)"[:120], "process_name": proc.name}


def mark_socket_known(sock: Socket) -> IgnoreRule:
    return create_rule(sock.machine, known_rule_data_for_socket(sock))


def mark_process_known(proc: ProcessInstance) -> IgnoreRule:
    return create_rule(proc.machine, known_rule_data_for_process(proc))
