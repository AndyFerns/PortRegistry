"""``portregistry daemon ...`` lifecycle commands."""

from __future__ import annotations

import time

import typer

from portregistry.cli.common import output_option
from portregistry.cli.output import OutputFormat, console, emit, esc
from portregistry.daemon import control
from portregistry.paths import get_paths

daemon_app = typer.Typer(
    help="Start, stop and inspect the PortRegistry daemon.", no_args_is_help=True
)


@daemon_app.command("start")
def start(
    port: int | None = typer.Option(None, "--port", help="Override the configured API port."),
    foreground: bool = typer.Option(
        False, "--foreground", "-f", help="Run in this terminal (same as `daemon run`)."
    ),
    timeout: float = typer.Option(45.0, help="Seconds to wait for the daemon to become healthy."),
) -> None:
    """Start the daemon (detached by default)."""
    if foreground:
        run(quiet=False, port=port)
        return
    with console.status("Starting PortRegistry daemon (initial discovery runs first)..."):
        status = control.start_daemon(port=port, timeout=timeout)
    console.print(
        f"[green]Daemon started[/] (pid {status['pid']}) at {esc(status['url'])}\n"
        f"Logs: {esc(get_paths().log_file)}"
    )


@daemon_app.command("run")
def run(
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Log to the log file only."),
    port: int | None = typer.Option(None, "--port", help="Override the configured API port."),
) -> None:
    """Run the daemon in the foreground (Ctrl+C to stop)."""
    import os

    from portregistry.daemon.lifecycle import run_daemon

    if port is not None:
        os.environ["PORTREGISTRY_PORT"] = str(port)
    code = run_daemon(console=not quiet)
    if code:
        raise typer.Exit(code)


@daemon_app.command("stop")
def stop(
    force: bool = typer.Option(
        False, "--force", help="Terminate the daemon process if it does not stop gracefully."
    ),
    timeout: float = typer.Option(25.0, help="Seconds to wait for a graceful shutdown."),
) -> None:
    """Stop the daemon gracefully (finishes the current scan, flushes writes)."""
    with console.status("Stopping PortRegistry daemon..."):
        result = control.stop_daemon(timeout=timeout, force=force)
    how = "gracefully" if result["graceful"] else ("by force" if result["forced"] else "")
    console.print(f"[green]Daemon stopped[/] {how} (pid {result['pid']}).")


@daemon_app.command("status")
def status(output: OutputFormat = output_option()) -> None:
    """Show whether the daemon is running and healthy."""
    data = control.daemon_status()

    def table():
        state = "[green]running[/]" if data["running"] else "[red]not running[/]"
        console.print(f"Daemon:  {state}")
        if data["running"]:
            console.print(f"PID:     {data['pid']}")
            console.print(f"URL:     {esc(data['url'])}")
            console.print(f"Started: {esc(data['started_at'])}")
            health = "[green]healthy[/]" if data["healthy"] else "[yellow]not responding[/]"
            console.print(f"Health:  {health}")
        elif data["stale_state_file"]:
            console.print("[dim]A stale state file from a previous run was found (ignored).[/]")
        console.print(f"Logs:    {esc(data['paths']['log_file'])}")
        return None

    emit(data, output, table=table)
    if not data["running"]:
        raise typer.Exit(3)


@daemon_app.command("restart")
def restart(
    timeout: float = typer.Option(45.0, help="Seconds to wait for the daemon to become healthy."),
) -> None:
    """Stop (if running) and start the daemon."""
    current = control.daemon_status()
    if current["running"]:
        with console.status("Stopping PortRegistry daemon..."):
            control.stop_daemon()
    with console.status("Starting PortRegistry daemon..."):
        status_info = control.start_daemon(timeout=timeout)
    console.print(
        f"[green]Daemon restarted[/] (pid {status_info['pid']}) at {esc(status_info['url'])}"
    )


@daemon_app.command("logs")
def logs(
    lines: int = typer.Option(50, "--lines", "-n", help="Number of lines to show."),
    follow: bool = typer.Option(False, "--follow", "-f", help="Keep printing new lines."),
) -> None:
    """Show the daemon log (reads the local log file; works even if the daemon failed)."""
    path = get_paths().log_file
    if not path.exists():
        console.print(f"No log file yet at {esc(path)}")
        raise typer.Exit(1)
    text = control.read_log_tail(lines=lines)
    console.out(text, end="", highlight=False)
    if not follow:
        return
    with open(path, encoding="utf-8", errors="replace") as handle:
        handle.seek(0, 2)
        try:
            while True:
                line = handle.readline()
                if line:
                    console.out(line, end="", highlight=False)
                else:
                    time.sleep(0.5)
        except KeyboardInterrupt:
            pass
