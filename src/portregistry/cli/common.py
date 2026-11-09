"""Shared CLI plumbing: API client factory and common options."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import typer

from portregistry.cli.output import OutputFormat
from portregistry.client import ApiClient

_client_factory: Callable[[], ApiClient] = ApiClient.from_environment


def set_client_factory(factory: Callable[[], ApiClient]) -> None:
    """Used by tests to inject a client with a mock transport."""
    global _client_factory
    _client_factory = factory


def reset_client_factory() -> None:
    global _client_factory
    _client_factory = ApiClient.from_environment


def get_client() -> ApiClient:
    return _client_factory()


def output_option() -> Any:
    return typer.Option(
        OutputFormat.table, "--output", "-o", help="Output format: table, json or csv."
    )


def proc_label(process: dict[str, Any] | None, pid: int | None = None) -> str:
    if process:
        return f"{process.get('name') or '?'}"
    if pid is not None:
        return f"pid {pid} (unresolved)"
    return "unknown"
