"""Application-wide exception types.

Every exception carries a short machine-readable ``code`` and a human readable
message so that the API, GUI, TUI and CLI can present consistent, actionable
errors.
"""

from __future__ import annotations

from typing import Any


class PortRegistryError(Exception):
    """Base class for all PortRegistry errors."""

    code = "error"

    def __init__(self, message: str, *, details: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ConfigError(PortRegistryError):
    code = "config_error"


class DaemonAlreadyRunningError(PortRegistryError):
    code = "daemon_already_running"


class DaemonNotRunningError(PortRegistryError):
    code = "daemon_not_running"


class LockError(PortRegistryError):
    code = "lock_error"


class ValidationError(PortRegistryError):
    """Invalid user input. ``field_errors`` maps field name -> list of messages."""

    code = "validation_error"

    def __init__(self, message: str, field_errors: dict[str, list[str]] | None = None) -> None:
        super().__init__(message, details={"fields": field_errors or {}})
        self.field_errors: dict[str, list[str]] = field_errors or {}


class NotFoundError(PortRegistryError):
    code = "not_found"


class ApiError(PortRegistryError):
    """Error response returned by the daemon API (client side)."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message, details=details)
        self.status_code = status_code
        self.code = code
