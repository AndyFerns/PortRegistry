"""Administration: doctor, token rotation, alerts, ignore rules, tray, filters."""

from __future__ import annotations

import importlib.util
import os
import stat
import subprocess
import sys
from typing import Any

import typer
from rich.table import Table

from portregistry.cli.common import get_client, output_option
from portregistry.cli.output import OutputFormat, console, emit, esc, glyph, new_table
from portregistry.exceptions import ConfigError, PortRegistryError


def status_icon(status: str) -> str:
    return {
        "ok": f"[green]{glyph('✓', 'ok')}[/]",
        "warn": "[yellow]![/]",
        "fail": f"[bold red]{glyph('✗', 'X')}[/]",
    }.get(status, status)


# ------------------------------------------------------------------ doctor


def _check(name: str, status: str, detail: str, fix: str = "") -> dict[str, Any]:
    return {"name": name, "status": status, "detail": detail, "fix": fix, "source": "client"}


def _token_permissions(path: Any) -> dict[str, Any]:
    if not path.exists():
        return _check(
            "token.file",
            "warn",
            f"No token file at {path} (the daemon creates it on first start).",
            "Start the daemon: portregistry daemon start",
        )
    if sys.platform != "win32":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            return _check(
                "token.file",
                "warn",
                f"Token file is readable by other users (mode {oct(mode)}).",
                f"chmod 600 {path}",
            )
        return _check("token.file", "ok", f"Token file is private (mode {oct(mode)}).")
    try:
        output = subprocess.run(
            ["icacls", str(path)], capture_output=True, text=True, timeout=10, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return _check("token.file", "ok", "Token file is in your user profile (ACL not inspected).")
    broad = [
        p
        for p in ("Everyone", "BUILTIN\\Users", "Authenticated Users")
        if p.lower() in output.lower()
    ]
    if broad:
        return _check(
            "token.file",
            "warn",
            f"Token file ACL grants access to {', '.join(broad)}.",
            f'icacls "{path}" /inheritance:r /grant:r "%USERNAME%:F"',
        )
    return _check(
        "token.file", "ok", "Token file ACL is limited to your account, SYSTEM and Administrators."
    )


def run_client_checks() -> tuple[list[dict[str, Any]], bool]:
    from portregistry.config import load_config
    from portregistry.daemon import autostart, control
    from portregistry.daemon.lifecycle import port_available
    from portregistry.paths import get_paths

    checks: list[dict[str, Any]] = []
    paths = get_paths()
    version = sys.version_info
    checks.append(
        _check(
            "python",
            "ok" if version >= (3, 12) else "fail",
            f"Python {version.major}.{version.minor}.{version.micro}",
            "" if version >= (3, 12) else "PortRegistry needs Python 3.12 or newer.",
        )
    )
    try:
        config = load_config(paths)
        checks.append(
            _check(
                "config",
                "ok",
                f"{paths.config_file} is valid."
                if paths.config_file.exists()
                else "No config file yet; defaults are used.",
            )
        )
    except ConfigError as exc:
        checks.append(_check("config", "fail", exc.message, f"Edit {paths.config_file}"))
        return checks, False
    data_dir = paths.data_dir
    probe = data_dir if data_dir.exists() else data_dir.parent
    writable = os.access(probe, os.W_OK)
    checks.append(
        _check(
            "data_dir",
            "ok" if writable else "fail",
            f"{data_dir}",
            "" if writable else f"Make {probe} writable for your user.",
        )
    )
    checks.append(_token_permissions(paths.token_file))
    status = control.daemon_status(paths, config)
    reachable = status["running"] and status["healthy"]
    if reachable:
        checks.append(_check("daemon", "ok", f"Running (pid {status['pid']}) at {status['url']}."))
    else:
        free = port_available(config.daemon.host, config.daemon.port)
        checks.append(
            _check(
                "daemon",
                "fail",
                "Daemon is not running."
                + ("" if free else f" Port {config.daemon.port} is in use by another program."),
                "portregistry daemon start"
                if free
                else f"Free port {config.daemon.port} or set PORTREGISTRY_PORT / [daemon] port.",
            )
        )
    has_docker = importlib.util.find_spec("docker") is not None
    checks.append(
        _check(
            "docker.sdk",
            "ok" if has_docker or not config.discovery.docker_enabled else "warn",
            "Docker SDK installed." if has_docker else "Docker SDK not installed.",
            ""
            if has_docker or not config.discovery.docker_enabled
            else 'pip install "portregistry[docker]"',
        )
    )
    auto = autostart.status()
    checks.append(
        _check(
            "autostart",
            "ok" if auto.installed else "warn",
            f"Installed via {auto.mechanism}."
            if auto.installed
            else "Daemon does not start at login.",
            "" if auto.installed else "portregistry daemon install   (preview with --dry-run)",
        )
    )
    has_tray = importlib.util.find_spec("pystray") is not None
    checks.append(
        _check(
            "tray",
            "ok",
            "Tray extra installed."
            if has_tray
            else 'Tray icon not installed (optional: pip install "portregistry[tray]").',
        )
    )
    return checks, reachable


def doctor(output: OutputFormat = output_option()) -> None:
    """Check installation, permissions, daemon, discovery and Docker; print exact fixes."""
    checks, reachable = run_client_checks()
    daemon_report: dict[str, Any] = {}
    if reachable:
        try:
            with get_client() as client:
                daemon_report = client.post("diagnostics/")
            for c in daemon_report.get("checks", []):
                checks.append({**c, "source": "daemon"})
        except PortRegistryError as exc:
            checks.append(
                _check("daemon.diagnostics", "fail", exc.message, "portregistry daemon logs")
            )
    failed = [c for c in checks if c["status"] == "fail"]
    data = {
        "ok": not failed,
        "checks": checks,
        "elevation_hint": daemon_report.get("elevation_hint"),
    }

    def table() -> Table:
        tbl = new_table(None, "", "Check", "Result", "Fix")
        for c in checks:
            tbl.add_row(
                status_icon(c["status"]),
                esc(c["name"]),
                esc(c["detail"]),
                esc(c.get("fix") or ""),
            )
        warns = sum(1 for c in checks if c["status"] == "warn")
        tbl.caption = f"{len(failed)} failure(s), {warns} warning(s)"
        return tbl

    emit(data, output, table=table)
    if failed:
        raise typer.Exit(1)


# ------------------------------------------------------------------- token

token_app = typer.Typer(help="Local API token management.", no_args_is_help=True)


@token_app.command("rotate")
def token_rotate(
    keep_sessions: bool = typer.Option(
        False, "--keep-sessions", help="Do not log browser sessions out."
    ),
) -> None:
    """Replace the local API token (the old one stops working immediately)."""
    with get_client() as client:
        result = client.post("auth/rotate-token/", {"keep_sessions": keep_sessions})
    console.print(
        f"[green]Token rotated.[/] New token written to {esc(result['token_file'])} (not printed)."
    )
    if result["sessions_revoked"]:
        console.print(
            f"{result['sessions_revoked']} browser session(s) logged out; use `portregistry gui` to log in again."
        )


@token_app.command("path")
def token_path() -> None:
    """Show where the token file lives (never prints the token)."""
    from portregistry.paths import get_paths

    console.print(esc(get_paths().token_file))


# ------------------------------------------------------------------ alerts

alerts_app = typer.Typer(help="Alert webhooks configured in config.toml.", no_args_is_help=True)


@alerts_app.command("status")
def alerts_status(output: OutputFormat = output_option()) -> None:
    """Show configured webhooks and delivery counters."""
    with get_client() as client:
        data = client.get("alerts/")

    def table() -> None:
        if not data.get("webhooks"):
            console.print(
                "No webhooks configured. Add [[alerts.webhook]] entries to config.toml, then restart the daemon."
            )
            return
        for w in data["webhooks"]:
            console.print(
                f"{esc(w['url'])}  min={w['min_severity']}  signed={'yes' if w['signed'] else 'no'}"
            )
        console.print(
            f"delivered={data['delivered']} failed={data['failed']} dropped={data['dropped']} queued={data['queued']}"
        )

    emit(data, output, table=table)


@alerts_app.command("test")
def alerts_test(output: OutputFormat = output_option()) -> None:
    """Send a test event to every configured webhook now."""
    with get_client() as client:
        data = client.post("alerts/test/")

    def table() -> None:
        for r in data["results"]:
            if r["ok"]:
                console.print(f"{status_icon('ok')} {esc(r['url'])} (HTTP {r['status']})")
            else:
                console.print(f"{status_icon('fail')} {esc(r['url'])}: {esc(r['error'])}")

    emit(data, output, table=table)
    if not all(r["ok"] for r in data["results"]):
        raise typer.Exit(1)


# ------------------------------------------------------------- ignore rules

ignore_app = typer.Typer(help="Ignore rules: endpoints you know about.", no_args_is_help=True)


def _port_range(text: str | None) -> tuple[int | None, int | None]:
    if not text:
        return None, None
    lo, _, hi = text.partition("-")
    try:
        return int(lo), int(hi or lo)
    except ValueError as exc:
        raise typer.BadParameter("Use PORT or FROM-TO.") from exc


@ignore_app.command("list")
def ignore_list(output: OutputFormat = output_option()) -> None:
    """List ignore rules."""
    with get_client() as client:
        items = client.list_all("ignore-rules/")

    def table() -> Table:
        tbl = new_table(None, "ID", "Name", "Matches", "Enabled", "Hides")
        for r in items:
            hides = ", ".join(
                x
                for x, on in (
                    ("conflicts", r["suppress_conflicts"]),
                    ("history", r["quiet_history"]),
                )
                if on
            )
            tbl.add_row(
                str(r["id"]),
                esc(r["name"]),
                esc(r["describe"]),
                "yes" if r["enabled"] else "no",
                hides,
            )
        return tbl

    emit(
        items, output, table=table, csv_rows=lambda: (items, ["id", "name", "describe", "enabled"])
    )


@ignore_app.command("add")
def ignore_add(
    name: str = typer.Option(..., "--name", help="Rule name."),
    process: str | None = typer.Option(
        None, "--process", help="Process name glob, e.g. 'chrome*'."
    ),
    exe: str | None = typer.Option(None, "--exe", help="Executable path glob."),
    protocol: str | None = typer.Option(None, "--protocol", "-p", help="tcp, udp or any."),
    port: str | None = typer.Option(None, "--port", help="PORT or FROM-TO."),
    address: str | None = typer.Option(None, "--address", "-a"),
    keep_conflicts: bool = typer.Option(
        False, "--keep-conflicts", help="Still report as unregistered; only quiet history."
    ),
    keep_history: bool = typer.Option(
        False, "--keep-history", help="Still record history; only hide findings."
    ),
) -> None:
    """Add an ignore rule."""
    lo, hi = _port_range(port)
    body = {
        "name": name,
        "process_name": process or "",
        "exe": exe or "",
        "protocol": protocol or "",
        "port_min": lo,
        "port_max": hi,
        "address": address or "",
        "suppress_conflicts": not keep_conflicts,
        "quiet_history": not keep_history,
    }
    with get_client() as client:
        rule = client.post("ignore-rules/", body)
    console.print(f"[green]Rule #{rule['id']} added:[/] {esc(rule['describe'])}")


@ignore_app.command("known")
def ignore_known(
    endpoint_id: int | None = typer.Argument(None, help="Endpoint id (from `portregistry ports`)."),
    process: int | None = typer.Option(
        None, "--process", help="Mark every endpoint of this process id's program as known."
    ),
) -> None:
    """Mark an endpoint (or a whole program) as known."""
    if endpoint_id is None and process is None:
        raise typer.BadParameter("Give an endpoint id or --process ID.")
    with get_client() as client:
        rule = client.post(
            f"processes/{process}/known/" if process is not None else f"ports/{endpoint_id}/known/"
        )
    console.print(f"[green]Rule #{rule['id']} added:[/] {esc(rule['name'])}")


@ignore_app.command("remove")
def ignore_remove(rule_id: int) -> None:
    """Remove an ignore rule."""
    with get_client() as client:
        client.delete(f"ignore-rules/{rule_id}/")
    console.print(f"Removed rule #{rule_id}.")


@ignore_app.command("toggle")
def ignore_toggle(rule_id: int, enable: bool = typer.Option(..., "--enable/--disable")) -> None:
    """Enable or disable an ignore rule."""
    with get_client() as client:
        client.patch(f"ignore-rules/{rule_id}/", {"enabled": enable})
    console.print(f"Rule #{rule_id} {'enabled' if enable else 'disabled'}.")


# --------------------------------------------------------------- saved filters

filters_app = typer.Typer(help="Saved filters (shared with the web GUI).", no_args_is_help=True)


@filters_app.command("list")
def filters_list(
    page: str | None = typer.Option(None, "--page"), output: OutputFormat = output_option()
) -> None:
    """List saved filters."""
    with get_client() as client:
        items = client.list_all("filters/", page=page)

    def table() -> Table:
        tbl = new_table(None, "ID", "Page", "Name", "Query")
        for f in items:
            tbl.add_row(str(f["id"]), f["page"], esc(f["name"]), esc(f["querystring"]))
        return tbl

    emit(items, output, table=table)


@filters_app.command("save")
def filters_save(
    name: str = typer.Argument(...),
    page: str = typer.Option("ports", "--page"),
    query: str = typer.Option(..., "--query", help="Query string, e.g. 'q=node&protocol=tcp'."),
) -> None:
    """Save a named filter."""
    with get_client() as client:
        saved = client.post("filters/", {"name": name, "page": page, "querystring": query})
    console.print(f"Saved '{esc(saved['name'])}': {esc(saved['querystring'])}")


@filters_app.command("delete")
def filters_delete(ref: str, page: str | None = typer.Option(None, "--page")) -> None:
    """Delete a saved filter by id or name."""
    with get_client() as client:
        client.request("DELETE", f"filters/{ref}/", params={"page": page})
    console.print(f"Deleted saved filter {esc(ref)}.")


# --------------------------------------------------------------------- tray


def tray(
    home: str | None = typer.Option(None, "--home", help="Use this PORTREGISTRY_HOME."),
) -> None:
    r"""Run the system tray icon (needs the optional extra: pip install "portregistry\[tray]")."""
    if home:
        os.environ["PORTREGISTRY_HOME"] = home
    from portregistry.tray.app import run_tray

    run_tray()
