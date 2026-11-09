"""Find ports that are free to use: not observed, not reserved, not Docker-published.

Results are advisory. Another program can bind a port at any moment; the
optional ``verify`` step does a quick test bind on this machine to catch sockets
that discovery could not see (e.g. other users' processes without privileges).
"""

from __future__ import annotations

import socket
import sys
from dataclasses import dataclass
from typing import Any

from portregistry.core.addresses import (
    ANY_ADDRESS,
    Overlap,
    address_overlap,
    normalize_bind_address,
)
from portregistry.core.ignore import ephemeral_range
from portregistry.core.well_known import label_for
from portregistry.django_app.models import DockerPortMapping, Machine, PortReservation, Socket
from portregistry.exceptions import ValidationError
from portregistry.services.validation import Errors, clean_port, clean_protocol

DEFAULT_RANGE = (3000, 9999)
MAX_COUNT = 50
MAX_SPAN = 65535


@dataclass(frozen=True)
class FreePortQuery:
    protocol: str = "tcp"
    start: int = DEFAULT_RANGE[0]
    end: int = DEFAULT_RANGE[1]
    count: int = 5
    address: str = ANY_ADDRESS
    verify: bool = True
    include_ephemeral: bool = False
    include_privileged: bool = False


def parse_query(params: dict[str, Any]) -> FreePortQuery:
    errors = Errors()
    protocol = clean_protocol(params.get("protocol") or "tcp", errors) or "tcp"
    start = DEFAULT_RANGE[0]
    end = DEFAULT_RANGE[1]
    if params.get("range"):
        text = str(params["range"]).replace(" ", "")
        lo, _, hi = text.partition("-")
        start = clean_port(lo, errors, "range") or start
        end = clean_port(hi or lo, errors, "range") or end
    if params.get("start"):
        start = clean_port(params["start"], errors, "start") or start
    if params.get("end"):
        end = clean_port(params["end"], errors, "end") or end
    if start > end:
        errors.add("range", "Range start must not be greater than its end.")
    raw_count = params.get("count")
    try:
        count = 5 if raw_count in (None, "") else int(raw_count)
    except (TypeError, ValueError):
        count = 0
    if not 1 <= count <= MAX_COUNT:
        errors.add("count", f"Count must be between 1 and {MAX_COUNT}.")
    try:
        address = normalize_bind_address(params.get("address") or ANY_ADDRESS)
    except ValueError:
        errors.add("address", "Enter an IP address or * for any.")
        address = ANY_ADDRESS

    def flag(name: str, default: bool) -> bool:
        value = params.get(name)
        if value in (None, ""):
            return default
        return str(value).lower() in ("1", "true", "yes", "on")

    errors.raise_if_any("Invalid free-port query.")
    return FreePortQuery(
        protocol=protocol,
        start=start,
        end=end,
        count=count,
        address=address,
        verify=flag("verify", True),
        include_ephemeral=flag("include_ephemeral", False),
        include_privileged=flag("include_privileged", start < 1024),
    )


def _overlaps(a: str, b: str) -> bool:
    try:
        return address_overlap(a, b).level is not Overlap.NONE
    except ValueError:
        return True


def _bind_test(protocol: str, address: str, port: int) -> bool:
    """True if this process could bind the port right now (closed immediately)."""
    targets = (
        [("0.0.0.0", socket.AF_INET), ("::", socket.AF_INET6)]
        if address == ANY_ADDRESS
        else [(address, socket.AF_INET6 if ":" in address else socket.AF_INET)]
    )
    kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    for host, family in targets:
        try:
            sock = socket.socket(family, kind)
        except OSError:
            continue  # e.g. IPv6 disabled
        try:
            if sys.platform == "win32" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            if family == socket.AF_INET6 and hasattr(socket, "IPV6_V6ONLY"):
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((host, port))
        except OSError:
            return False
        finally:
            sock.close()
    return True


def find_free_ports(machine: Machine, query: FreePortQuery) -> dict[str, Any]:
    proto = query.protocol
    busy_sockets = list(
        Socket.objects.filter(
            machine=machine, active=True, protocol=proto, port__gte=query.start, port__lte=query.end
        ).values_list("port", "address")
    )
    reserved = list(
        PortReservation.objects.filter(
            machine=machine,
            status="active",
            protocol=proto,
            port__gte=query.start,
            port__lte=query.end,
        ).values_list("port", "bind_address")
    )
    docker = list(
        DockerPortMapping.objects.filter(
            active=True,
            protocol=proto,
            host_port__gte=query.start,
            host_port__lte=query.end,
            container__present=True,
            container__machine=machine,
        ).values_list("host_port", "host_ip")
    )
    taken: dict[int, list[str]] = {}
    for port, address in busy_sockets:
        if _overlaps(query.address, address):
            taken.setdefault(port, []).append("in use")
    for port, address in reserved:
        if _overlaps(query.address, address):
            taken.setdefault(port, []).append("reserved")
    for port, host_ip in docker:
        if port is not None and _overlaps(query.address, host_ip or "0.0.0.0"):
            taken.setdefault(port, []).append("published by Docker")

    eph = ephemeral_range()
    results: list[dict[str, Any]] = []
    skipped = {
        "in_use": 0,
        "reserved": 0,
        "docker": 0,
        "ephemeral": 0,
        "privileged": 0,
        "bind_failed": 0,
    }
    for port in range(query.start, query.end + 1):
        if len(results) >= query.count:
            break
        if port < 1024 and not query.include_privileged:
            skipped["privileged"] += 1
            continue
        if not query.include_ephemeral and eph[0] <= port <= eph[1]:
            skipped["ephemeral"] += 1
            continue
        reasons = taken.get(port)
        if reasons:
            if "in use" in reasons:
                skipped["in_use"] += 1
            elif "reserved" in reasons:
                skipped["reserved"] += 1
            else:
                skipped["docker"] += 1
            continue
        if query.verify and not _bind_test(proto, query.address, port):
            skipped["bind_failed"] += 1
            continue
        results.append({"port": port, "protocol": proto, "label": label_for(port, proto)})
    return {
        "advisory": True,
        "query": {
            "protocol": proto,
            "range": f"{query.start}-{query.end}",
            "address": query.address,
            "count": query.count,
            "verified_by_bind": query.verify,
            "ephemeral_range": f"{eph[0]}-{eph[1]}",
        },
        "ports": results,
        "skipped": skipped,
        "note": (
            "Free means: not observed, not reserved, not published by Docker"
            + (", and a test bind succeeded just now" if query.verify else "")
            + ". Another program can still take it before you do; reserve it to record intent."
        ),
    }


def suggest_one(machine: Machine, protocol: str = "tcp", address: str = ANY_ADDRESS) -> int | None:
    try:
        query = parse_query({"protocol": protocol, "address": address, "count": 1})
    except ValidationError:
        return None
    found = find_free_ports(machine, query)["ports"]
    return found[0]["port"] if found else None
