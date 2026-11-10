"""Daemon-side health checks used by ``portregistry doctor`` and the GUI."""

from __future__ import annotations

import shutil
import sys
from typing import Any

from django.db import connection

from portregistry.core.application import get_application, has_application
from portregistry.django_app.models import Machine
from portregistry.services.queries import freshness, latest_scan


def elevation_hint(platform: str) -> str:
    if platform == "windows":
        return (
            "For fuller visibility, stop the daemon (`portregistry daemon stop`), open an "
            "Administrator terminal and run `portregistry daemon start`. PortRegistry never "
            "elevates itself."
        )
    if platform == "macos":
        return (
            "Without root, macOS only shows your own processes' sockets. For a full view run "
            "the daemon as root (`sudo portregistry daemon run`) at your own discretion; "
            "PortRegistry never elevates itself."
        )
    return (
        "Without root, owners of other users' sockets are hidden. Run the daemon as root, or "
        "grant CAP_NET_ADMIN/CAP_SYS_PTRACE, only if you need that visibility; PortRegistry "
        "never elevates itself."
    )


def check(name: str, status: str, detail: str, fix: str = "") -> dict[str, Any]:
    return {"name": name, "status": status, "detail": detail, "fix": fix}


def run_diagnostics(machine: Machine) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    app = get_application() if has_application() else None
    platform = (app.platform_info or {}).get("platform", sys.platform) if app else sys.platform
    elevated = (app.platform_info or {}).get("elevated") if app else None

    # Database integrity and mode.
    with connection.cursor() as cursor:
        cursor.execute("PRAGMA quick_check")
        quick = cursor.fetchone()[0]
        cursor.execute("PRAGMA journal_mode")
        journal = cursor.fetchone()[0]
    checks.append(
        check(
            "database.integrity",
            "ok" if quick == "ok" else "fail",
            f"PRAGMA quick_check: {quick}",
            ""
            if quick == "ok"
            else "Stop the daemon and back up/restore the database (see `portregistry export`).",
        )
    )
    checks.append(
        check(
            "database.wal",
            "ok" if str(journal).lower() == "wal" else "warn",
            f"journal_mode={journal}",
            ""
            if str(journal).lower() == "wal"
            else "Restart the daemon; WAL mode is enabled at startup.",
        )
    )

    # Disk space for the data directory.
    if app is not None:
        target = app.config.paths.data_dir
        while not target.exists() and target.parent != target:
            target = target.parent
        usage = shutil.disk_usage(target)
        free_mb = usage.free // (1024 * 1024)
        checks.append(
            check(
                "disk.free",
                "ok" if free_mb > 200 else "warn",
                f"{free_mb} MB free in data directory",
                ""
                if free_mb > 200
                else "Free up disk space; SQLite needs room for WAL and retention.",
            )
        )

    # Discovery health.
    fresh = freshness(machine, app)
    last = latest_scan(machine)
    if last is None:
        checks.append(
            check(
                "discovery.native",
                "warn",
                "No native scan has finished yet.",
                "Wait a few seconds or run `portregistry scan`.",
            )
        )
    elif last.status == "failed":
        checks.append(
            check(
                "discovery.native",
                "fail",
                f"Last scan failed: {last.message}",
                "See `portregistry daemon logs`.",
            )
        )
    elif last.status == "partial":
        checks.append(
            check(
                "discovery.native",
                "warn",
                "Last scan was partial (socket table not fully readable).",
                elevation_hint(platform),
            )
        )
    else:
        checks.append(
            check("discovery.native", "ok", f"Last scan complete, {last.socket_count} endpoints.")
        )
    if fresh["stale"]:
        checks.append(
            check(
                "discovery.freshness",
                "warn",
                "Discovery data is stale.",
                "Check `portregistry daemon logs`; the scheduler may be stuck.",
            )
        )
    else:
        checks.append(
            check(
                "discovery.freshness",
                "ok",
                f"Last complete scan {fresh['last_success_age_seconds']}s ago.",
            )
        )

    restricted = fresh["restricted_process_count"] + fresh["unknown_owner_count"]
    if restricted:
        checks.append(
            check(
                "discovery.visibility",
                "warn" if elevated is False else "ok",
                f"{fresh['restricted_process_count']} processes with restricted metadata, "
                f"{fresh['unknown_owner_count']} endpoints without an owner.",
                elevation_hint(platform) if elevated is False else "",
            )
        )
    else:
        checks.append(check("discovery.visibility", "ok", "All endpoint owners resolved."))

    # Docker.
    if app is not None:
        docker = app.docker_provider
        if not docker.enabled:
            checks.append(check("docker", "ok", "Docker discovery disabled in config."))
        elif docker.state == "ok":
            checks.append(check("docker", "ok", docker.message or "Docker reachable."))
        else:
            fix = docker.message or ""
            if "not installed" in fix:
                fix = 'pip install "portregistry[docker]"'
            elif "not reachable" in fix:
                fix = "Start Docker, or set docker_enabled = false in config.toml to silence this."
            checks.append(check("docker", "warn", f"Docker {docker.state}: {docker.message}", fix))
        sched = app.scheduler.describe() if app.scheduler else None
        checks.append(
            check(
                "scheduler",
                "ok" if sched and sched.get("running") else "fail",
                "running" if sched and sched.get("running") else "not running",
                ""
                if sched and sched.get("running")
                else "Restart the daemon: `portregistry daemon restart`.",
            )
        )
        hooks = app.config.alerts.webhooks
        checks.append(check("alerts.webhooks", "ok", f"{len(hooks)} webhook(s) configured."))
        checks.append(_control_check(app.config, elevated))

    return {
        "platform": platform,
        "elevated": elevated,
        "elevation_hint": elevation_hint(platform),
        "checks": checks,
    }


def _control_check(config: Any, elevated: bool | None) -> dict[str, Any]:
    from portregistry.services.process_control import control_state

    state = control_state(config, elevated=elevated)
    if state["allow_other_users"]:
        return check(
            "control",
            "warn",
            "Process control is ON and can stop OTHER USERS' processes "
            "(elevated daemon + allow_other_users).",
            "Set allow_other_users = false in [control] unless you need it.",
        )
    if state["enabled"]:
        return check(
            "control",
            "ok",
            "Process control is on: your own processes can be stopped after a two-step "
            "confirmation; every attempt is recorded in history.",
        )
    if state["configured"]:
        return check("control", "warn", state["reason"], "Bind the daemon to a loopback address.")
    return check("control", "ok", "Process control (Stop process) is off.")
