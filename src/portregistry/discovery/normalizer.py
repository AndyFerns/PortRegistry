"""Normalize raw psutil connection tuples into :class:`RawSocket` records.

Rules:

* TCP: only sockets in the LISTEN state are endpoints (established connections
  are ignored).
* UDP: any socket bound to a non-zero local port is an endpoint. UDP has no
  LISTEN state; such sockets are reported with state ``BOUND``.
* Sockets without a local address or bound to port 0 are ignored.
* Addresses are canonicalized (IPv4-mapped IPv6 becomes IPv4).
"""

from __future__ import annotations

import logging
import socket
from collections.abc import Iterable
from typing import Any

from portregistry.core.addresses import normalize_address
from portregistry.core.types import Protocol, RawSocket, ScanScope, SocketState

logger = logging.getLogger(__name__)

TCP_LISTEN = "LISTEN"


def _laddr_parts(laddr: Any) -> tuple[str, int] | None:
    if not laddr:
        return None
    ip = getattr(laddr, "ip", None)
    port = getattr(laddr, "port", None)
    if ip is None or port is None:
        try:
            ip, port = laddr[0], laddr[1]
        except (TypeError, IndexError):
            return None
    try:
        port = int(port)
    except (TypeError, ValueError):
        return None
    return str(ip), port


def normalize_connection(conn: Any) -> RawSocket | None:
    """Convert one psutil ``sconn``/``pconn``-like object; None if not an endpoint."""
    sock_type = getattr(conn, "type", None)
    if sock_type == socket.SOCK_STREAM:
        protocol = Protocol.TCP
        if str(getattr(conn, "status", "")) != TCP_LISTEN:
            return None
        state = SocketState.LISTEN
    elif sock_type == socket.SOCK_DGRAM:
        protocol = Protocol.UDP
        state = SocketState.BOUND
    else:
        return None

    parts = _laddr_parts(getattr(conn, "laddr", None))
    if parts is None:
        return None
    ip, port = parts
    if not 0 < port <= 65535:
        return None
    try:
        address, family = normalize_address(ip)
    except ValueError:
        logger.debug("Skipping socket with unparseable address %r", ip)
        return None
    pid = getattr(conn, "pid", None)
    if pid is not None:
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            pid = None
    return RawSocket(
        protocol=protocol, family=family, address=address, port=port, state=state, pid=pid
    )


def normalize_connections(connections: Iterable[Any], scope: ScanScope) -> list[RawSocket]:
    """Normalize, filter to ``scope`` and de-duplicate a batch of connections."""
    seen: set[RawSocket] = set()
    result: list[RawSocket] = []
    for conn in connections:
        sock = normalize_connection(conn)
        if sock is None or not scope.matches(sock.protocol, sock.port):
            continue
        if sock in seen:
            continue
        seen.add(sock)
        result.append(sock)
    result.sort(key=lambda s: (s.port, s.protocol, s.family, s.address, s.pid or 0))
    return result
