"""Runs native scans: collect (no DB) -> persist (short transaction).

The coordinator guarantees that full scans never overlap for the machine: a
second request while one is running is rejected (the scheduler coalesces
requests before they reach this point).
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Protocol

from portregistry.core.types import NativeScanResult, ScanScope
from portregistry.discovery.providers.base import NativeProvider

logger = logging.getLogger(__name__)


class ScanStore(Protocol):
    def begin(self, scope: ScanScope, trigger: str, provider: str) -> int: ...

    def complete(self, scan_id: int, result: NativeScanResult) -> Any: ...


class DiscoveryCoordinator:
    def __init__(self, provider: NativeProvider, store: ScanStore) -> None:
        self._provider = provider
        self._store = store
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        return self._lock.locked()

    def run_native_scan(self, scope: ScanScope, trigger: str) -> Any | None:
        """Run one scan. Returns the store's summary, or None if a scan is already running."""
        if not self._lock.acquire(blocking=False):
            logger.debug("Native scan already running; not starting another")
            return None
        try:
            scan_id = self._store.begin(scope, trigger, self._provider.name)
            # The OS is queried here, with no database transaction open.
            result = self._provider.scan(scope)
            return self._store.complete(scan_id, result)
        finally:
            self._lock.release()
