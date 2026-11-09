"""Ignore rules and ephemeral-port noise classification (pure logic).

Ignore rules let users declare endpoints they know about and do not want to see
as "unregistered listeners" or in history. They never suppress conflicts that
involve an explicit reservation: a reservation is stated intent.
"""

from __future__ import annotations

import fnmatch
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_EPHEMERAL = (49152, 65535)  # IANA dynamic range; Windows and macOS default


@dataclass(frozen=True)
class IgnoreRuleView:
    id: int
    name: str
    process_name: str = ""  # glob, case-insensitive ("" = any)
    exe: str = ""  # glob on executable path, case-insensitive ("" = any)
    protocol: str = ""  # "tcp", "udp" or "" for both
    port_min: int | None = None
    port_max: int | None = None
    address: str = ""  # exact normalized address or "" for any
    suppress_conflicts: bool = True
    quiet_history: bool = True
    enabled: bool = True

    def matches(
        self,
        *,
        protocol: str,
        port: int,
        address: str,
        process_name: str | None,
        exe: str | None,
    ) -> bool:
        if not self.enabled:
            return False
        if self.protocol and self.protocol != protocol:
            return False
        if self.port_min is not None and port < self.port_min:
            return False
        if self.port_max is not None and port > self.port_max:
            return False
        if self.address and self.address != address:
            return False
        if self.process_name and not _glob(self.process_name, process_name):
            return False
        return not (self.exe and not _glob(self.exe, exe))

    def describe(self) -> str:
        parts = []
        if self.process_name:
            parts.append(f"process {self.process_name}")
        if self.exe:
            parts.append(f"exe {self.exe}")
        if self.protocol:
            parts.append(self.protocol.upper())
        if self.port_min is not None or self.port_max is not None:
            lo, hi = self.port_min, self.port_max
            parts.append(f"port {lo}" if lo == hi else f"ports {lo or 1}-{hi or 65535}")
        if self.address:
            parts.append(f"address {self.address}")
        return ", ".join(parts) or "everything"


def _glob(pattern: str, value: str | None) -> bool:
    if not value:
        return False
    pattern = pattern.lower()
    value = value.lower()
    if fnmatch.fnmatchcase(value, pattern):
        return True
    # Allow "node" to match "node.exe" and paths' basenames.
    base = value.replace("\\", "/").rsplit("/", 1)[-1]
    return fnmatch.fnmatchcase(base, pattern) or fnmatch.fnmatchcase(
        base.removesuffix(".exe"), pattern
    )


def ephemeral_range() -> tuple[int, int]:
    """The OS dynamic (ephemeral) port range used for outgoing/short-lived sockets."""
    if sys.platform.startswith("linux"):
        try:
            text = Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split()
            lo, hi = int(text[0]), int(text[1])
            if 0 < lo <= hi <= 65535:
                return lo, hi
        except (OSError, ValueError, IndexError):
            pass
    return DEFAULT_EPHEMERAL


def is_ephemeral(port: int, rng: tuple[int, int]) -> bool:
    return rng[0] <= port <= rng[1]


def first_match(
    rules: list[IgnoreRuleView],
    *,
    protocol: str,
    port: int,
    address: str,
    process_name: str | None,
    exe: str | None,
) -> IgnoreRuleView | None:
    for rule in rules:
        if rule.matches(
            protocol=protocol, port=port, address=address, process_name=process_name, exe=exe
        ):
            return rule
    return None
