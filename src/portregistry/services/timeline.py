"""Who held a port over time.

Intervals are reconstructed per endpoint row from its history events
(appeared / owner_changed / disappeared); endpoints present since the initial
baseline have no "appeared" event and start at their ``first_seen``.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any

from django.utils import timezone

from portregistry.core.addresses import format_endpoint
from portregistry.core.well_known import label_for
from portregistry.django_app.models import Event, Machine, PortReservation, Socket
from portregistry.services.validation import Errors, clean_port, clean_protocol

OPEN_TYPES = ("endpoint.appeared", "endpoint.owner_changed")
CLOSE_TYPE = "endpoint.disappeared"
MAX_DAYS = 90


def parse_params(params: dict[str, Any]) -> tuple[int, str | None, int]:
    errors = Errors()
    port = clean_port(params.get("port"), errors) if params.get("port") not in (None, "") else None
    if port is None and "port" not in errors.fields:
        errors.add("port", "This field is required.")
    protocol = clean_protocol(params["protocol"], errors) if params.get("protocol") else None
    try:
        days = int(params.get("days") or 7)
    except (TypeError, ValueError):
        days = 0
    if not 1 <= days <= MAX_DAYS:
        errors.add("days", f"Days must be between 1 and {MAX_DAYS}.")
    errors.raise_if_any("Invalid timeline query.")
    assert port is not None
    return port, protocol, days


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def build_timeline(
    machine: Machine,
    port: int,
    protocol: str | None = None,
    days: int = 7,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or timezone.now()
    start = now - timedelta(days=days)
    sockets = Socket.objects.filter(machine=machine, port=port).select_related("process")
    if protocol:
        sockets = sockets.filter(protocol=protocol)
    sockets = [s for s in sockets if s.active or (s.ended_at or now) >= start]
    events_by_socket: dict[str, list[Event]] = defaultdict(list)
    if sockets:
        for ev in Event.objects.filter(
            entity_type="socket",
            entity_id__in=[str(s.pk) for s in sockets],
            type__in=(*OPEN_TYPES, CLOSE_TYPE),
        ).order_by("timestamp", "id"):
            events_by_socket[ev.entity_id].append(ev)

    lanes: dict[tuple[str, str, str], dict[str, Any]] = {}
    for sock in sockets:
        proc = sock.process
        owner = (
            f"{proc.name or '?'} (pid {proc.pid})"
            if proc
            else (f"pid {sock.pid} (unresolved)" if sock.pid else "unknown owner")
        )
        lane_key = (owner, sock.protocol, sock.address)
        lane = lanes.setdefault(
            lane_key,
            {
                "owner": owner,
                "process_id": proc.pk if proc else None,
                "project": proc.project_name if proc else "",
                "protocol": sock.protocol,
                "address": sock.address,
                "endpoint": format_endpoint(sock.protocol, sock.address, sock.port),
                "intervals": [],
            },
        )
        intervals: list[tuple[datetime, datetime, bool]] = []
        events = events_by_socket.get(str(sock.pk), [])
        open_at: datetime | None = None
        if not events or events[0].type == CLOSE_TYPE:
            open_at = sock.first_seen
        for ev in events:
            if ev.type in OPEN_TYPES:
                if open_at is None:
                    open_at = ev.timestamp
            else:
                intervals.append((open_at or sock.first_seen, ev.timestamp, False))
                open_at = None
        if sock.active:
            intervals.append((open_at or sock.first_seen, now, True))
        elif open_at is not None and sock.ended_at:
            intervals.append((open_at, sock.ended_at, False))
        for begin, end, ongoing in intervals:
            if end < start:
                continue
            lane["intervals"].append(
                {
                    "start": _iso(max(begin, start)),
                    "end": _iso(end),
                    "ongoing": ongoing,
                    "clipped": begin < start,
                    "seconds": int((end - max(begin, start)).total_seconds()),
                }
            )

    reservations = PortReservation.objects.filter(machine=machine, port=port).select_related(
        "service"
    )
    if protocol:
        reservations = reservations.filter(protocol=protocol)
    res_rows = []
    for r in reservations:
        end = r.released_at or now
        if end < start:
            continue
        res_rows.append(
            {
                "id": r.pk,
                "endpoint": format_endpoint(r.protocol, r.bind_address, r.port),
                "service": r.service.name if r.service else None,
                "status": r.status,
                "start": _iso(max(r.created_at, start)),
                "end": _iso(end),
                "ongoing": r.status == "active",
            }
        )
    lane_list = sorted(
        (lane for lane in lanes.values() if lane["intervals"]),
        key=lambda lane: (lane["intervals"][0]["start"], lane["owner"]),
    )
    return {
        "port": port,
        "protocol": protocol,
        "label": label_for(port, protocol),
        "window": {"start": _iso(start), "end": _iso(now), "days": days},
        "lanes": lane_list,
        "reservations": res_rows,
        "note": "Changes between scans are not observed; intervals have scan-interval precision.",
    }


def layout(timeline: dict[str, Any]) -> dict[str, Any]:
    """Add percentage offsets/widths for rendering bars (used by the GUI SVG)."""
    start = datetime.fromisoformat(timeline["window"]["start"])
    end = datetime.fromisoformat(timeline["window"]["end"])
    span = max((end - start).total_seconds(), 1)

    def place(item: dict[str, Any]) -> dict[str, Any]:
        a = (datetime.fromisoformat(item["start"]) - start).total_seconds() / span * 100
        b = (datetime.fromisoformat(item["end"]) - start).total_seconds() / span * 100
        return {**item, "x": round(max(a, 0), 3), "w": round(max(b - a, 0.4), 3)}

    out = dict(timeline)
    out["lanes"] = [
        {**lane, "intervals": [place(i) for i in lane["intervals"]]} for lane in timeline["lanes"]
    ]
    out["reservations"] = [place(r) for r in timeline["reservations"]]
    days = timeline["window"]["days"]
    out["ticks"] = [
        {"x": round(i / days * 100, 3), "label": (start + timedelta(days=i)).strftime("%m-%d")}
        for i in range(days + 1)
    ]
    return out
