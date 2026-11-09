"""Small helpers for validating untrusted input dictionaries."""

from __future__ import annotations

from typing import Any

from portregistry.exceptions import ValidationError


class Errors:
    def __init__(self) -> None:
        self.fields: dict[str, list[str]] = {}

    def add(self, field: str, message: str) -> None:
        self.fields.setdefault(field, []).append(message)

    def raise_if_any(self, message: str = "Invalid input.") -> None:
        if self.fields:
            raise ValidationError(message, self.fields)


def reject_unknown(data: dict[str, Any], allowed: set[str], errors: Errors) -> None:
    for key in data:
        if key not in allowed:
            errors.add(key, "Unknown field.")


def clean_text(
    data: dict[str, Any],
    field: str,
    errors: Errors,
    *,
    max_length: int,
    required: bool = False,
    default: str = "",
) -> str | None:
    """Returns the cleaned string, or None if absent (for partial updates)."""
    if field not in data:
        if required:
            errors.add(field, "This field is required.")
        return None
    value = data[field]
    if value is None:
        value = default
    if not isinstance(value, str):
        errors.add(field, "Must be a string.")
        return None
    value = value.strip()
    if required and not value:
        errors.add(field, "This field may not be blank.")
        return None
    if len(value) > max_length:
        errors.add(field, f"Ensure this field has no more than {max_length} characters.")
        return None
    if "\x00" in value:
        errors.add(field, "Null characters are not allowed.")
        return None
    return value


def clean_port(value: Any, errors: Errors, field: str = "port") -> int | None:
    if isinstance(value, bool):
        errors.add(field, "Port must be an integer.")
        return None
    if isinstance(value, str) and value.strip().isdigit():
        value = int(value.strip())
    if not isinstance(value, int):
        errors.add(field, "Port must be an integer.")
        return None
    if not 1 <= value <= 65535:
        errors.add(field, "Port must be between 1 and 65535 (port 0 cannot be reserved).")
        return None
    return value


def clean_protocol(value: Any, errors: Errors, field: str = "protocol") -> str | None:
    if not isinstance(value, str) or value.strip().lower() not in ("tcp", "udp"):
        errors.add(field, "Protocol must be 'tcp' or 'udp'.")
        return None
    return value.strip().lower()
