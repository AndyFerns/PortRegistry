"""Address normalization and bind-endpoint overlap semantics.

Overlap rules (PRD section 10.3):

* ``*`` (reservation "any address, any family") overlaps every address: definite.
* Same family, identical address: definite.
* Same family, one side is the family wildcard (``0.0.0.0`` or ``::``): definite.
* IPv6 wildcard ``::`` versus any IPv4 address: *potential*. Whether an IPv6
  wildcard socket also accepts IPv4 depends on dual-stack socket options
  (``IPV6_V6ONLY``) and OS defaults, which cannot be determined from outside.
* Everything else (different specific addresses, different families): no overlap.

Protocol and port are compared by :func:`endpoint_overlap`; TCP and UDP never
overlap just because the port number matches.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import StrEnum

from portregistry.core.types import Family

ANY_ADDRESS = "*"
IPV4_WILDCARD = "0.0.0.0"
IPV6_WILDCARD = "::"


class Overlap(StrEnum):
    NONE = "none"
    POTENTIAL = "potential"
    DEFINITE = "definite"


@dataclass(frozen=True)
class OverlapResult:
    level: Overlap
    reason: str

    def __bool__(self) -> bool:
        return self.level is not Overlap.NONE


def split_zone(address: str) -> tuple[str, str | None]:
    """Split an IPv6 zone/scope id (``fe80::1%eth0``) from the address."""
    if "%" in address:
        base, zone = address.split("%", 1)
        return base, zone or None
    return address, None


def normalize_address(address: str) -> tuple[str, Family]:
    """Return the canonical text form and family of an IP address.

    * Brackets are stripped (``[::1]`` -> ``::1``).
    * IPv4-mapped IPv6 (``::ffff:127.0.0.1``) is normalized to IPv4.
    * IPv6 zone ids are preserved in the returned text.

    Raises ``ValueError`` for anything that is not an IP literal.
    """
    text = address.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if not text:
        raise ValueError("empty address")
    base, zone = split_zone(text)
    ip = ipaddress.ip_address(base)
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped), Family.IPV4
        canonical = str(ip)
        return (f"{canonical}%{zone}" if zone else canonical), Family.IPV6
    return str(ip), Family.IPV4


def normalize_bind_address(address: str | None) -> str:
    """Normalize a reservation bind address; ``*``/empty means any address, any family."""
    if address is None:
        return ANY_ADDRESS
    text = address.strip()
    if text in ("", ANY_ADDRESS, "any"):
        return ANY_ADDRESS
    return normalize_address(text)[0]


def family_of(address: str) -> Family | None:
    """Family of an address, or None for ``*``."""
    if address == ANY_ADDRESS:
        return None
    return normalize_address(address)[1]


def is_wildcard(address: str) -> bool:
    if address == ANY_ADDRESS:
        return True
    try:
        base, _ = split_zone(normalize_address(address)[0])
    except ValueError:
        return False
    return base in (IPV4_WILDCARD, IPV6_WILDCARD)


def is_loopback(address: str) -> bool:
    if address == ANY_ADDRESS:
        return False
    try:
        base, _ = split_zone(normalize_address(address)[0])
        return ipaddress.ip_address(base).is_loopback
    except ValueError:
        return False


def _compare_key(address: str) -> tuple[str, Family]:
    text, family = normalize_address(address)
    base, _ = split_zone(text)
    return base, family


def address_overlap(a: str, b: str) -> OverlapResult:
    """Do two bind addresses overlap? See module docstring for the rules."""
    if a == ANY_ADDRESS or b == ANY_ADDRESS:
        return OverlapResult(Overlap.DEFINITE, "'*' covers every address in both families")
    a_base, a_family = _compare_key(a)
    b_base, b_family = _compare_key(b)
    if a_family == b_family:
        if a_base == b_base:
            return OverlapResult(Overlap.DEFINITE, f"same address {a_base}")
        wildcard = IPV4_WILDCARD if a_family is Family.IPV4 else IPV6_WILDCARD
        if a_base == wildcard or b_base == wildcard:
            specific = b_base if a_base == wildcard else a_base
            return OverlapResult(
                Overlap.DEFINITE,
                f"wildcard {wildcard} covers every {a_family.value} address including {specific}",
            )
        return OverlapResult(Overlap.NONE, f"different {a_family.value} addresses")
    v6_base = a_base if a_family is Family.IPV6 else b_base
    v4_base = b_base if a_family is Family.IPV6 else a_base
    if v6_base == IPV6_WILDCARD:
        return OverlapResult(
            Overlap.POTENTIAL,
            f"IPv6 wildcard :: may also accept IPv4 traffic for {v4_base} on dual-stack "
            "systems unless IPV6_V6ONLY is set; the OS behaviour cannot be determined here",
        )
    return OverlapResult(Overlap.NONE, "different address families")


def endpoint_overlap(
    protocol_a: str, address_a: str, port_a: int, protocol_b: str, address_b: str, port_b: int
) -> OverlapResult:
    if protocol_a != protocol_b:
        return OverlapResult(Overlap.NONE, "different protocols (TCP and UDP are independent)")
    if port_a != port_b:
        return OverlapResult(Overlap.NONE, "different ports")
    return address_overlap(address_a, address_b)


def format_endpoint(protocol: str, address: str, port: int) -> str:
    """Human readable endpoint, e.g. ``tcp 0.0.0.0:8080`` or ``udp [::1]:53``."""
    if address == ANY_ADDRESS:
        host = "*"
    elif ":" in address:
        host = f"[{address}]"
    else:
        host = address
    return f"{protocol} {host}:{port}"
