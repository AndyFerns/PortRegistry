"""Template filters. All return plain strings; Django autoescaping still applies."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from django import template
from django.utils import timezone

from portregistry.core.addresses import format_endpoint

register = template.Library()


@register.filter
def ago(value: datetime | str | None) -> str:
    if not value:
        return "never"
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value)
        except ValueError:
            return value
    seconds = max(0, int((timezone.now() - value).total_seconds()))
    if seconds < 60:
        return f"{seconds}s ago"
    if seconds < 3600:
        return f"{seconds // 60}m ago"
    if seconds < 86400:
        return f"{seconds // 3600}h {seconds % 3600 // 60}m ago"
    return f"{seconds // 86400}d ago"


@register.filter
def endpoint(obj: Any) -> str:
    address = getattr(obj, "address", None) or getattr(obj, "bind_address", None) or "*"
    return format_endpoint(obj.protocol, address, obj.port)


@register.filter
def pretty_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, default=str)


@register.filter
def cmdline(value: list[str] | None) -> str:
    return " ".join(value) if value else ""


@register.filter
def sev_class(value: str | None) -> str:
    return {
        "error": "sev-error",
        "warning": "sev-warning",
        "info": "sev-info",
        "ok": "st-ok",
        "complete": "st-ok",
        "active": "st-ok",
        "running": "st-ok",
        "attention": "sev-warning",
        "partial": "sev-warning",
        "degraded": "sev-warning",
        "failed": "sev-error",
        "unavailable": "sev-error",
        "released": "st-muted",
        "disabled": "st-muted",
        "exited": "st-muted",
    }.get(str(value or ""), "st-muted")


@register.filter
def get_item(mapping: dict[Any, Any] | None, key: Any) -> Any:
    if not mapping:
        return None
    return mapping.get(key)


@register.simple_tag(takes_context=True)
def query_with(context: Any, **changes: Any) -> str:
    """Current query string with some parameters replaced (for sort/pagination links)."""
    request = context["request"]
    params = request.GET.copy()
    for key, value in changes.items():
        if value in (None, ""):
            params.pop(key, None)
        else:
            params[key] = value
    encoded = params.urlencode()
    return f"?{encoded}" if encoded else "?"
