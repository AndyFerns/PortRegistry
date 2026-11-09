"""Saved filters, small key/value settings and the onboarding checklist."""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlencode

from django.db.models import QuerySet

from portregistry.django_app.models import (
    Conflict,
    Machine,
    PortReservation,
    SavedFilter,
    Service,
    Setting,
)
from portregistry.exceptions import NotFoundError, ValidationError
from portregistry.services.db import write_transaction
from portregistry.services.validation import Errors, clean_text

#: Query keys a saved filter may store, per page. Anything else is dropped.
ALLOWED_KEYS = {
    "ports": {"q", "port", "protocol", "family", "active", "state", "ordering", "group", "address"},
    "history": {"q", "type", "severity", "noise"},
    "conflicts": {"info"},
}


# ------------------------------------------------------------------ settings


def get_setting(key: str, default: Any = None) -> Any:
    row = Setting.objects.filter(key=key).first()
    return row.value if row is not None else default


def set_setting(key: str, value: Any) -> None:
    with write_transaction():
        Setting.objects.update_or_create(key=key, defaults={"value": value})


# ------------------------------------------------------------- saved filters


def clean_querystring(page: str, querystring: str) -> str:
    allowed = ALLOWED_KEYS.get(page, set())
    pairs = [
        (k, v)
        for k, v in parse_qsl(querystring.lstrip("?"), keep_blank_values=False)
        if k in allowed
    ]
    return urlencode(pairs)[:500]


def list_filters(machine: Machine, page: str | None = None) -> QuerySet[SavedFilter]:
    qs = SavedFilter.objects.filter(machine=machine)
    return qs.filter(page=page) if page else qs


def create_filter(machine: Machine, data: dict[str, Any]) -> SavedFilter:
    if not isinstance(data, dict):
        raise ValidationError(
            "Expected a JSON object.", {"non_field_errors": ["Expected an object."]}
        )
    errors = Errors()
    name = clean_text(data, "name", errors, max_length=80, required=True)
    page = str(data.get("page") or "")
    if page not in ALLOWED_KEYS:
        errors.add("page", f"Page must be one of {', '.join(ALLOWED_KEYS)}.")
    errors.raise_if_any("Invalid saved filter.")
    query = clean_querystring(page, str(data.get("querystring") or ""))
    if not query:
        raise ValidationError(
            "Invalid saved filter.", {"querystring": ["Nothing to save: no supported filters set."]}
        )
    with write_transaction():
        saved, _ = SavedFilter.objects.update_or_create(
            machine=machine, page=page, name=name, defaults={"querystring": query}
        )
    return saved


def get_filter(machine: Machine, ref: Any, page: str | None = None) -> SavedFilter:
    qs = list_filters(machine, page)
    match = None
    if str(ref).isdigit():
        match = qs.filter(pk=int(ref)).first()
    if match is None:
        match = qs.filter(name__iexact=str(ref)).first()
    if match is None:
        raise NotFoundError(f"Saved filter '{ref}' not found.")
    return match


def delete_filter(saved: SavedFilter) -> None:
    with write_transaction():
        saved.delete()


def filter_params(saved: SavedFilter) -> dict[str, str]:
    return dict(parse_qsl(saved.querystring))


# ---------------------------------------------------------------- onboarding


def onboarding_state(
    machine: Machine, *, autostart_installed: bool | None = None
) -> dict[str, Any]:
    from portregistry.core.application import get_application, has_application
    from portregistry.services.queries import freshness

    app = get_application() if has_application() else None
    fresh = freshness(machine, app)
    top_listener = (
        Conflict.objects.filter(
            machine=machine, active=True, type="unregistered_listener", socket__isnull=False
        )
        .select_related("socket")
        .order_by("port")
        .first()
    )
    elevated = (app.platform_info or {}).get("elevated") if app else None
    docker_state = app.docker_provider.state if app else "unknown"
    steps = [
        {
            "key": "scan",
            "title": "Daemon running and first scan complete",
            "done": fresh["last_success_at"] is not None,
            "link": "/machine/",
        },
        {
            "key": "visibility",
            "title": "Visibility",
            "done": elevated is True
            or (fresh["restricted_process_count"] + fresh["unknown_owner_count"]) == 0,
            "optional": True,
            "link": "/machine/",
            "hint": "Some process details are hidden by OS permissions. This is fine for most use; see the Machine page for how to get fuller visibility.",
        },
        {
            "key": "docker",
            "title": "Docker discovery",
            "done": docker_state in ("ok", "disabled"),
            "optional": True,
            "link": "/containers/",
            "hint": "Docker is not reachable. Start Docker, or disable Docker discovery in config.toml.",
        },
        {
            "key": "service",
            "title": "Register your first service",
            "done": Service.objects.filter(machine=machine).exists(),
            "link": f"/adopt/?socket={top_listener.socket_id}"
            if top_listener
            else "/services/new/",
            "hint": "Tip: use “Register as service” on any listener to pre-fill everything.",
        },
        {
            "key": "reservation",
            "title": "Reserve a port",
            "done": PortReservation.objects.filter(machine=machine).exists(),
            "link": "/reservations/new/",
        },
        {
            "key": "autostart",
            "title": "Start PortRegistry at login",
            "done": bool(autostart_installed),
            "optional": True,
            "link": "/machine/",
            "hint": "Run `portregistry daemon install` so data is fresh after a reboot.",
        },
        {
            "key": "doctor",
            "title": "Run a health check",
            "done": bool(get_setting("doctor_ran")),
            "optional": True,
            "link": "/machine/",
            "hint": "Run `portregistry doctor` for a full health report with fixes.",
        },
    ]
    required = [s for s in steps if not s.get("optional")]
    return {
        "dismissed": bool(get_setting("onboarding_dismissed")),
        "steps": steps,
        "complete": all(s["done"] for s in required),
        "progress": f"{sum(1 for s in steps if s['done'])}/{len(steps)}",
    }
