"""``portregistry`` command-line entry point."""

from __future__ import annotations

import sys
import webbrowser

import typer

from portregistry import __version__
from portregistry.cli import inspect_cmds, registry_cmds
from portregistry.cli.common import get_client, output_option
from portregistry.cli.daemon_cmds import daemon_app
from portregistry.cli.output import OutputFormat, console, emit, err_console, esc
from portregistry.exceptions import (
    ApiError,
    ConfigError,
    DaemonAlreadyRunningError,
    DaemonNotRunningError,
    PortRegistryError,
)

app = typer.Typer(
    name="portregistry",
    help=(
        "PortRegistry: local-first port discovery and service registry.\n\n"
        "All commands talk to the local daemon (start it with `portregistry daemon start`)."
    ),
    no_args_is_help=True,
    pretty_exceptions_enable=False,
    add_completion=False,
)

app.add_typer(daemon_app, name="daemon")
app.command("status")(inspect_cmds.status)
app.command("scan")(inspect_cmds.scan)
app.add_typer(inspect_cmds.ports_app, name="ports")
app.add_typer(inspect_cmds.processes_app, name="processes")
app.add_typer(inspect_cmds.containers_app, name="containers")
app.command("conflicts")(inspect_cmds.conflicts)
app.command("history")(inspect_cmds.history)
app.command("machines")(inspect_cmds.machines)
app.command("report")(inspect_cmds.report)
app.add_typer(registry_cmds.service_app, name="service")
app.command("reserve")(registry_cmds.reserve)
app.add_typer(registry_cmds.reservations_app, name="reservations")
app.command("release")(registry_cmds.release)


def _ensure_daemon(no_start: bool) -> None:
    from portregistry.daemon import control

    status = control.daemon_status()
    if status["running"] and status["healthy"]:
        return
    if no_start:
        raise DaemonNotRunningError(
            "PortRegistry daemon is not running. Start it with: portregistry daemon start"
        )
    with console.status("Daemon not running; starting it in the background..."):
        status = control.start_daemon()
    console.print(f"Started daemon (pid {status['pid']}) at {esc(status['url'])}")


@app.command("gui")
def gui(
    no_browser: bool = typer.Option(False, "--no-browser", help="Only print the login link."),
    no_start: bool = typer.Option(
        False, "--no-start", help="Do not start the daemon automatically."
    ),
) -> None:
    """Open the web GUI (served by the daemon) using a single-use login link."""
    _ensure_daemon(no_start)
    with get_client() as client:
        link = client.post("auth/gui-link/")
    url = link["url"]
    console.print(f"Single-use login link (valid {link['expires_in']}s):\n  {esc(url)}")
    console.print(
        "[dim]Afterwards, browse to the daemon URL directly; your session lasts 7 days.[/]"
    )
    if not no_browser:
        webbrowser.open(url)


@app.command("tui")
def tui(
    no_start: bool = typer.Option(
        False, "--no-start", help="Do not start the daemon automatically."
    ),
) -> None:
    """Open the terminal UI (works over SSH)."""
    _ensure_daemon(no_start)
    from portregistry.tui.app import run_tui

    run_tui()


@app.command("paths")
def paths(output: OutputFormat = output_option()) -> None:
    """Show configuration, data and log locations (never prints secrets)."""
    from portregistry.paths import get_paths

    data = get_paths().as_dict()

    def table() -> None:
        for key, value in data.items():
            console.print(f"{key:<12} {esc(value)}")

    emit(data, output, table=table)


@app.command("version")
def version() -> None:
    """Show the PortRegistry version."""
    console.print(f"PortRegistry {__version__}")


def main() -> None:
    try:
        app()
    except DaemonNotRunningError as exc:
        err_console.print(f"[red]Error:[/] {esc(exc.message)}")
        sys.exit(3)
    except DaemonAlreadyRunningError as exc:
        err_console.print(f"[yellow]{esc(exc.message)}[/]")
        sys.exit(4)
    except ApiError as exc:
        err_console.print(f"[red]Error ({exc.status_code} {esc(exc.code)}):[/] {esc(exc.message)}")
        fields = exc.details.get("fields") if isinstance(exc.details, dict) else None
        if isinstance(fields, dict):
            for field, messages in fields.items():
                text = "; ".join(messages) if isinstance(messages, list) else str(messages)
                err_console.print(f"  {esc(field)}: {esc(text)}")
        sys.exit(1)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/] {esc(exc.message)}")
        sys.exit(2)
    except PortRegistryError as exc:
        err_console.print(f"[red]Error:[/] {esc(exc.message)}")
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
