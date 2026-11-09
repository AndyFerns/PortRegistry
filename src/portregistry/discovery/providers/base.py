"""Provider interface for native socket discovery."""

from __future__ import annotations

from typing import Protocol

from portregistry.core.types import NativeScanResult, ScanScope


class NativeProvider(Protocol):
    """Enumerates locally bound sockets and resolves their owners.

    Implementations must not touch the database and must never raise for
    permission or process-lifetime problems; those are reported as issues on
    the returned result. Unexpected failures are reported via ``error``.
    """

    name: str

    def scan(self, scope: ScanScope) -> NativeScanResult: ...
