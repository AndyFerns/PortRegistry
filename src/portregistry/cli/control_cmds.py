"""``portregistry stop``: opt-in, two-step, audited process stop.

There is deliberately no ``--yes`` flag: stopping always needs an interactive
terminal and the PID typed back within 30 seconds. ``--show-command`` prints the
commands to do it yourself and never asks the daemon to stop anything.
"""

from __future__ import annotations

import sys
import time
from typing import Any

import typer

from portregistry.cli.common import get_client
from portregistry.cli.output import console, err_console, esc, glyph
from portregistry.client import ApiClient, control_headers

EXIT_REFUSED = 4
EXIT_NOT_INTERACTIVE = 2
EXIT_TIMEOUT = 6

RESULT_STYLE = {
    "stopped": "green",
    "already_exited": "green",
    "still_running": "yellow",
    "failed": "red",
    "skipped": "red",
}


def _is_interactive() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except (AttributeError, ValueError):
        return False


def _resolve_process(
    client: ApiClient, port: int | None, protocol: str | None, process: int | None, pid: int | None
) -> int:
    chosen = [v for v in (port, process, pid) if v is not None]
    if len(chosen) != 1:
        raise typer.BadParameter("Give exactly one of PORT, --process or --pid.")
    if process is not None:
        return process
    if pid is not None:
        matches = client.list_all("processes/", pid=pid)
        if not matches:
            raise typer.BadParameter(
                f"No observed process with PID {pid} (only processes that own ports are known)."
            )
        return int(sorted(matches, key=lambda p: p.get("first_seen") or "")[-1]["id"])
    endpoints = client.list_all("ports/", port=port, protocol=protocol)
    owners: dict[int, dict[str, Any]] = {}
    for ep in endpoints:
        proc = ep.get("process")
        if proc and proc.get("id") is not None:
            owners.setdefault(int(proc["id"]), {**proc, "endpoint": ep.get("endpoint")})
    if not owners:
        proto = (protocol or "tcp/udp").upper()
        raise typer.BadParameter(
            f"No resolved owning process for {proto} port {port}. "
            "Run `portregistry who` to see what is known."
        )
    if len(owners) > 1:
        console.print(f"Port {port} is owned by several processes; pick one with --process:")
        for proc_id, proc in owners.items():
            console.print(
                f"  --process {proc_id}  {esc(proc.get('name'))} (PID {proc.get('pid')}) "
                f"on {esc(proc.get('endpoint'))}"
            )
        raise typer.Exit(EXIT_REFUSED)
    return next(iter(owners))


def _render(data: dict[str, Any]) -> None:
    ident = data["identity"]
    target = data.get("target") or {}
    arrow = glyph("→", "->")
    console.print(
        f"[bold]Stop {esc(ident.get('name') or '?')}[/] (PID {ident.get('pid')}), "
        f"mode: [bold]{'whole tree' if data['mode'] == 'tree' else 'this process only'}[/]"
    )
    cmdline = target.get("cmdline") or ident.get("cmdline") or []
    console.print(f"  Command line: {esc(' '.join(cmdline)) if cmdline else '-'}")
    console.print(f"  Folder:       {esc(target.get('cwd') or ident.get('cwd'))}")
    console.print(f"  User:         {esc(target.get('username') or ident.get('username'))}")
    if data.get("parent_chain"):
        chain = f" {arrow} ".join(
            f"{p.get('name') or '?'} ({p['pid']})" for p in reversed(data["parent_chain"])
        )
        console.print(f"  Started by:   {esc(chain)} {arrow} this process")
    if data.get("method_label"):
        style = "green" if data.get("graceful") else "yellow"
        console.print(f"  How:          [{style}]{esc(data['method_label'])}[/]")
    impact = data.get("impact") or {}
    if data["mode"] == "tree" or len(data.get("members") or []) > 1:
        console.print(
            f"  [bold]Would stop {impact.get('processes', 0)} process(es), in this order:[/]"
        )
        for m in data.get("members") or []:
            mark = "" if not m["refusals"] else f" [red]{glyph('✗', 'X')} protected[/]"
            ports = f" ports {esc(', '.join(m['ports']))}" if m["ports"] else ""
            console.print(
                f"    {'  ' * m['depth']}{esc(m['name'] or '?')} (PID {m['pid']}, "
                f"{esc(m['method'])}){ports}{mark}"
            )
    console.print(f"  Ports freed:  {esc(', '.join(impact.get('ports') or [])) or '-'}")
    if impact.get("services"):
        console.print("  [yellow]Registered services affected:[/]")
        for svc in impact["services"]:
            console.print(f"    - {esc(svc)}")
    for warning in data.get("warnings") or []:
        console.print(f"  [yellow]Note:[/] {esc(warning)}")
    for reason in data.get("reasons") or []:
        console.print(f"  [red]Refused:[/] {esc(reason)}")


def _render_commands(data: dict[str, Any]) -> None:
    if data.get("docker"):
        console.print("[bold]Stop it with Docker instead:[/]")
        for hint in data["docker"]:
            console.print(f"  {esc(hint['command'])}")
    if data.get("commands"):
        console.print("[bold]To stop it yourself instead:[/]")
        for cmd in data["commands"]:
            console.print(f"  {esc(cmd['command'])}    [dim]# {esc(cmd['label'])}[/]")
    if data.get("command_note"):
        console.print(f"[dim]{esc(data['command_note'])}[/]")


def _render_result(op: dict[str, Any]) -> None:
    outcome = op.get("outcome") or op.get("state")
    style = {"stopped": "green", "timeout": "yellow"}.get(str(outcome), "red")
    console.print(f"[{style}]{esc(op.get('message') or outcome)}[/]")
    for m in op.get("members") or []:
        result_style = RESULT_STYLE.get(m["result"], "")
        console.print(
            f"  {esc(m['name'] or '?')} (PID {m['pid']}): "
            f"[{result_style}]{esc(m['result'])}[/] {esc(m['detail'])}"
        )
    console.print("[dim]Recorded in history: portregistry history --type process.stop[/]")


def stop(
    port: int | None = typer.Argument(None, help="Port whose owning process to stop."),
    protocol: str | None = typer.Option(None, "--protocol", "-p", help="tcp or udp."),
    process: int | None = typer.Option(
        None, "--process", help="PortRegistry process id (see `portregistry processes`)."
    ),
    pid: int | None = typer.Option(None, "--pid", help="OS process id of an observed process."),
    tree: bool = typer.Option(
        False, "--tree", help="Also stop all of its child processes (listed before you confirm)."
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Forced stop (SIGKILL / TerminateProcess) instead of the graceful one. No cleanup.",
    ),
    show_command: bool = typer.Option(
        False, "--show-command", help="Only print the commands to stop it yourself."
    ),
) -> None:
    """Stop the process that owns PORT (opt-in; two-step; recorded in history).

    Shows what will be stopped, then asks you to type the PID within 30 seconds.
    There is no --yes: stopping always needs an interactive terminal.
    """
    headers = control_headers("cli")
    mode = "tree" if tree else "process"
    with get_client() as client:
        process_id = _resolve_process(client, port, protocol, process, pid)
        data = client.request(
            "GET",
            f"processes/{process_id}/stop/preview/",
            params={"mode": mode, "force": "1" if force else ""},
            headers=headers,
        )
        _render(data)
        _render_commands(data)
        if show_command:
            return
        if not data.get("control_enabled"):
            err_console.print(f"[yellow]{esc(data['control'].get('reason'))}[/]")
            raise typer.Exit(EXIT_REFUSED)
        if not data.get("allowed"):
            err_console.print("[red]PortRegistry will not stop this process.[/]")
            raise typer.Exit(EXIT_REFUSED)
        if not _is_interactive():
            err_console.print(
                "[red]Stopping requires an interactive terminal (there is no --yes).[/] "
                "Use --show-command to get the commands instead."
            )
            raise typer.Exit(EXIT_NOT_INTERACTIVE)

        issued = client.post(
            f"processes/{process_id}/stop/request/",
            {"mode": mode, "force": force},
            headers=headers,
        )
        target_pid = issued["assessment"]["identity"]["pid"]
        console.print(
            f"\n[bold]This cannot be undone.[/] Type the PID [bold]{target_pid}[/] within "
            f"{issued['expires_in']} seconds to confirm, or press Enter to cancel."
        )
        typed = console.input("PID: ").strip()
        if not typed:
            console.print("Cancelled. Nothing was stopped.")
            raise typer.Exit(1)
        # A wrong PID is sent too: the daemon refuses it and records the attempt.
        op = client.post(
            "processes/stop/confirm/",
            {"code": issued["code"], "pid": typed},
            headers=headers,
            timeout=30,
        )
        deadline = time.monotonic() + float(op.get("grace_seconds") or 10) + 20
        with console.status("Waiting for the process to exit..."):
            while op.get("state") == "running" and time.monotonic() < deadline:
                time.sleep(0.5)
                op = client.get(f"processes/stop/operations/{op['id']}/")
    _render_result(op)
    if op.get("outcome") == "timeout":
        raise typer.Exit(EXIT_TIMEOUT)
    if op.get("outcome") != "stopped":
        raise typer.Exit(1)
