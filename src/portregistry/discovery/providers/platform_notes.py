"""Platform capability and limitation notes surfaced in status views.

These are descriptive only: PortRegistry never elevates privileges and never
shells out to ``ss``/``lsof``/PowerShell for discovery in this release.
"""

from __future__ import annotations

import os
import sys
from typing import Any


def is_elevated() -> bool | None:
    try:
        if sys.platform == "win32":
            import ctypes

            windll = getattr(ctypes, "windll")  # noqa: B009 - Windows-only attribute
            return bool(windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return None


def platform_capabilities() -> dict[str, Any]:
    elevated = is_elevated()
    notes: list[str] = []
    if sys.platform == "win32":
        platform_name = "windows"
        notes.append(
            "Windows reports socket owners without elevation, but executable paths and "
            "command lines of system/service processes may be access-denied."
        )
        notes.append("Diagnostic cross-check: Get-NetTCPConnection / Get-NetUDPEndpoint.")
    elif sys.platform == "darwin":
        platform_name = "macos"
        notes.append(
            "macOS requires root for the system-wide socket table; without it PortRegistry "
            "falls back to per-process enumeration and only sees your own processes."
        )
        notes.append("Diagnostic cross-check: lsof -nP -iTCP -sTCP:LISTEN; lsof -nP -iUDP.")
    else:
        platform_name = "linux"
        notes.append(
            "Linux lists all sockets, but owning PIDs of other users' processes require root "
            "(or CAP_NET_ADMIN/CAP_SYS_PTRACE); those endpoints appear with unknown owners."
        )
        notes.append("Diagnostic cross-check: ss -lntup.")
    notes.append(
        "IPv6 wildcard (::) sockets may or may not accept IPv4 traffic depending on "
        "IPV6_V6ONLY; such overlaps are reported as potential conflicts."
    )
    if elevated is False:
        notes.append(
            "Running without elevated privileges: visibility may be incomplete. "
            "PortRegistry never elevates automatically."
        )
    return {"platform": platform_name, "elevated": elevated, "notes": notes}
