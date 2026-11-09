"""Glue between the discovery coordinator and persistence for native scans."""

from __future__ import annotations

import logging

from portregistry.core.application import Application
from portregistry.core.types import NativeScanResult, ScanScope, ScanStatus
from portregistry.django_app.models import DiscoveryScan, Machine
from portregistry.services.conflict_store import refresh_conflicts
from portregistry.services.machines import touch_machine
from portregistry.services.reconcile import NativeReconcileSummary, apply_native_scan, begin_scan

logger = logging.getLogger(__name__)


class NativeScanStore:
    """Implements :class:`portregistry.discovery.coordinator.ScanStore` on the ORM."""

    def __init__(self, machine: Machine, app: Application | None = None) -> None:
        self.machine = machine
        self.app = app

    def begin(self, scope: ScanScope, trigger: str, provider: str) -> int:
        return begin_scan(
            self.machine, kind="native", trigger=trigger, provider=provider, scope=scope
        ).pk

    def complete(self, scan_id: int, result: NativeScanResult) -> NativeReconcileSummary:
        scan = DiscoveryScan.objects.get(pk=scan_id)
        summary = apply_native_scan(self.machine, scan, result)
        if self.app is not None:
            if result.status is ScanStatus.FAILED:
                self.app.native_provider.update("unavailable", result.error or "scan failed")
            elif result.status is ScanStatus.PARTIAL:
                self.app.native_provider.update(
                    "degraded", "Socket enumeration incomplete (insufficient privileges)"
                )
            else:
                restricted = summary.resolution_failures + summary.unknown_owners
                message = (
                    f"{restricted} endpoints/processes with restricted metadata"
                    if restricted
                    else ""
                )
                self.app.native_provider.update("ok", message)
        touch_machine(self.machine)
        if self.app is None or self.app.conflicts_ready:
            refresh_conflicts(self.machine)
        logger.debug(
            "Native scan %s %s: %d endpoints (+%d/-%d)",
            scan_id,
            summary.status,
            summary.socket_count,
            summary.appeared,
            summary.disappeared,
        )
        return summary
