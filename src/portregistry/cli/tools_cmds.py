"""Everyday tools: who owns a port, find a free port, adopt, timeline, watch."""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any

import typer
from rich.live import Live
from rich.table import Table

from portregistry.cli.common import get_client, output_option, proc_label
from portregistry.cli.output import (
    SEVERITY_STYLE,
    OutputFormat,
    ago,
    console,
    emit,
    esc,
    glyph,
    new_table,
    styled,
)
from portregistry.exceptions import PortRegistryError

# --------------------------------------------------------------------- who


def who(
    port: int = typer.Argument(..., help="Port number."),
    protocol: str | None = typer.Option(
        None, "--protocol", "-p", help="tcp or udp (default both)."
    ),
    output: OutputFormat = output_option(),
) -> None:
    """Who owns PORT? Owner, project, label, Docker mapping, reservations and conflicts."""
    with get_client() as client:
        endpoints = client.list_all("ports/", port=port, protocol=protocol)
        details = [client.get(f"ports/{e['id']}/") for e in endpoints]
        reserved = client.list_all("reservations/", port=port, protocol=protocol)
        fresh = client.get("status/")["discovery"]
    data = {
        "port": port,
        "protocol": protocol,
        "endpoints": details,
        "reservations": reserved,
        "last_complete_scan": fresh["last_success_at"],
    }

    def table() -> None:
        proto_text = (protocol or "tcp/udp").upper()
        if not details:
            console.print(
                f"Nothing is bound to {proto_text} port {port} (as of the last complete scan "
                f"{ago(fresh['last_success_at'])})."
            )
        for d in details:
            p = d.get("process") or {}
            owner = esc(proc_label(p, d.get("pid")))
            label = f" [dim]{esc(d.get('label'))}[/]" if d.get("label") else ""
            console.print(
                f"[bold]{esc(d['endpoint'])}[/]{label} {glyph('←', '<-')} {owner}"
                + (f" (pid {d['pid']})" if d.get("pid") else "")
            )
            if p.get("exe"):
                console.print(f"    exe:     {esc(p['exe'])}")
            if p.get("cmdline"):
                console.print(f"    cmdline: {esc(' '.join(p['cmdline']))}")
            if p.get("project_name"):
                console.print(
                    f"    project: {esc(p['project_name'])} ({esc(p.get('project_root'))})"
                )
            for m in d.get("docker") or []:
                c = m["container"]
                console.print(
                    f"    docker:  {esc(c['name'])} ({esc(c['image'])}) {glyph('→', '->')} {m['container_port']}/{m['protocol']}"
                )
            if d.get("ignored"):
                console.print(f"    [dim]{esc(d['ignored'])}[/]")
            for c in d.get("conflicts") or []:
                console.print(f"    {styled(c['severity'], SEVERITY_STYLE)} {esc(c['title'])}")
        for r in reserved:
            svc = (r.get("service") or {}).get("name")
            console.print(
                f"Reserved: #{r['id']} {esc(r['endpoint'])}"
                + (f" for '{esc(svc)}'" if svc else "")
                + f" [{esc(r.get('display_status', r['status']))}]"
            )
        if not details and not reserved:
            console.print(
                f"[green]{proto_text} {port} looks free.[/] Reserve it with `portregistry reserve {port}`."
            )

    emit(data, output, table=table)


# -------------------------------------------------------------------- free


def free(
    range_: str = typer.Option("3000-9999", "--range", "-r", help="Port range, e.g. 3000-3999."),
    protocol: str = typer.Option("tcp", "--protocol", "-p", help="tcp or udp."),
    count: int = typer.Option(5, "--count", "-n", help="How many ports to suggest (1-50)."),
    address: str = typer.Option("*", "--address", "-a", help="Bind address to check (* = any)."),
    no_verify: bool = typer.Option(False, "--no-verify", help="Skip the quick test bind."),
    include_ephemeral: bool = typer.Option(
        False, "--include-ephemeral", help="Allow the OS ephemeral range."
    ),
    reserve: bool = typer.Option(False, "--reserve", help="Reserve the first free port."),
    service: str | None = typer.Option(None, "--service", "-s", help="Service for --reserve."),
    output: OutputFormat = output_option(),
) -> None:
    """Find free ports: not observed, not reserved, not published by Docker."""
    with get_client() as client:
        data = client.get(
            "ports/free/",
            range=range_,
            protocol=protocol,
            count=count,
            address=address,
            verify="0" if no_verify else "1",
            include_ephemeral="1" if include_ephemeral else None,
        )
        reservation = None
        if reserve and data["ports"]:
            body: dict[str, Any] = {
                "port": data["ports"][0]["port"],
                "protocol": protocol,
                "bind_address": address,
            }
            if service:
                body["service"] = service
            reservation = client.post("reservations/", body)
            data["reservation"] = reservation

    def table() -> None:
        if not data["ports"]:
            console.print(
                f"[yellow]No free {protocol.upper()} port in {esc(range_)}.[/] Skipped: {esc(data['skipped'])}"
            )
            return
        for p in data["ports"]:
            label = f"  [dim](usually {esc(p['label'])})[/]" if p.get("label") else ""
            console.print(f"[green]{p['port']}[/]/{protocol}{label}")
        if reservation:
            console.print(f"Reserved #{reservation['id']} {esc(reservation['endpoint'])}.")
        console.print(f"[dim]{esc(data['note'])}[/]")

    emit(data, output, table=table, csv_rows=lambda: (data["ports"], ["port", "protocol", "label"]))


# ------------------------------------------------------------------- adopt


def adopt(
    port: int | None = typer.Argument(None, help="Port of the endpoint to adopt."),
    protocol: str | None = typer.Option(
        None, "--protocol", "-p", help="tcp or udp if the port is ambiguous."
    ),
    process: int | None = typer.Option(
        None, "--process", help="Adopt a process by its PortRegistry id instead."
    ),
    name: str | None = typer.Option(None, "--name", help="Service name (default: suggested)."),
    exe: str | None = typer.Option(None, "--exe", help="Override the expected executable."),
    cwd: str | None = typer.Option(None, "--cwd", help="Override the expected working directory."),
    category: str | None = typer.Option(None, "--category", "-c"),
    only_this: bool = typer.Option(
        False, "--only-this", help="Reserve only this endpoint, not all of the process's."
    ),
    any_address: bool = typer.Option(
        False, "--any-address", help="Reserve on * instead of the observed address."
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation."),
    output: OutputFormat = output_option(),
) -> None:
    """Register a running endpoint/process as a service, pre-filled from what is observed."""
    if port is None and process is None:
        raise typer.BadParameter("Give a PORT or --process ID.")
    with get_client() as client:
        params: dict[str, Any] = {}
        if process is not None:
            params["process"] = process
        else:
            candidates = client.list_all("ports/", port=port, protocol=protocol)
            if not candidates:
                raise PortRegistryError(
                    f"Nothing is bound to port {port} (see `portregistry who {port}`)."
                )
            owned = [c for c in candidates if c.get("process")] or candidates
            protocols = {c["protocol"] for c in owned}
            if len(protocols) > 1 and protocol is None:
                raise typer.BadParameter(
                    f"Port {port} is bound for {sorted(protocols)}; pass --protocol."
                )
            params["socket"] = owned[0]["id"]
        proposal = client.get("services/adopt/", **params)
        svc = proposal["service"]
        for key, value in (
            ("name", name),
            ("expected_executable", exe),
            ("expected_working_directory", cwd),
            ("category", category),
        ):
            if value is not None:
                svc[key] = value
        endpoints = proposal["endpoints"]
        selected = [
            e
            for e in endpoints
            if e["selected"] and (not only_this or e["socket_id"] == params.get("socket"))
        ]
        if output is OutputFormat.table:
            console.print(f"Adopting {esc(proposal['source'])}:")
            console.print(
                f"  service:  [bold]{esc(svc['name'])}[/]  category={esc(svc['category'])}"
            )
            console.print(f"  exe:      {esc(svc['expected_executable'])}")
            console.print(f"  cwd:      {esc(svc['expected_working_directory'])}")
            console.print(
                "  reserve:  " + (", ".join(esc(e["endpoint"]) for e in selected) or "nothing")
            )
            if not yes:
                typer.confirm("Create this service?", abort=True)
        result = client.post(
            "services/adopt/",
            {
                "service": svc,
                "socket_ids": [e["socket_id"] for e in selected],
                "reserve_any_address": any_address,
            },
        )
    emit(
        result,
        output,
        table=lambda: console.print(
            f"[green]Service #{result['service']['id']} '{esc(result['service']['name'])}' registered with "
            f"{len(result['reservations'])} reservation(s).[/]"
        ),
    )


# ---------------------------------------------------------------- timeline


def timeline(
    port: int = typer.Argument(..., help="Port number."),
    protocol: str | None = typer.Option(None, "--protocol", "-p"),
    days: int = typer.Option(7, "--days", "-d", help="Window in days (1-90)."),
    output: OutputFormat = output_option(),
) -> None:
    """Who held PORT over the last N days (text bars)."""
    with get_client() as client:
        data = client.get("ports/timeline/", port=port, protocol=protocol, days=days)

    def table() -> None:
        width = 48
        start = datetime.fromisoformat(data["window"]["start"])
        end = datetime.fromisoformat(data["window"]["end"])
        span = max((end - start).total_seconds(), 1)

        def bar(items: list[dict[str, Any]], char: str) -> str:
            cells = [" "] * width
            for item in items:
                a = int(
                    (datetime.fromisoformat(item["start"]) - start).total_seconds() / span * width
                )
                b = int(
                    (datetime.fromisoformat(item["end"]) - start).total_seconds() / span * width
                )
                for i in range(max(a, 0), min(max(b, a + 1), width)):
                    cells[i] = char
            return "".join(cells)

        title = (
            f"Port {port}"
            + (f"/{protocol}" if protocol else "")
            + (f" ({data['label']})" if data.get("label") else "")
        )
        tbl = new_table(
            f"{esc(title)}: last {days} day(s)",
            "Owner / reservation",
            "Endpoint",
            f"{start:%m-%d} .. now",
        )
        for lane in data["lanes"]:
            tbl.add_row(
                esc(lane["owner"]),
                esc(lane["endpoint"]),
                "[cyan]" + bar(lane["intervals"], glyph("█", "#")) + "[/]",
            )
        for r in data["reservations"]:
            tbl.add_row(
                f"reservation #{r['id']} ({esc(r['service'] or 'no service')})",
                esc(r["endpoint"]),
                "[yellow]" + bar([r], glyph("░", "=")) + "[/]",
            )
        if not data["lanes"] and not data["reservations"]:
            console.print(f"Nothing held or reserved port {port} in the last {days} day(s).")
            return
        tbl.caption = data["note"]
        console.print(tbl)

    emit(data, output, table=table)


# ------------------------------------------------------------------- watch


def _ports_table(
    items: list[dict[str, Any]], previous: dict[int, dict[str, Any]], gone: list[dict[str, Any]]
) -> Table:
    tbl = new_table(None, "Proto", "Address", "Port", "Label", "PID", "Process", "Project", "Since")
    for item in items:
        p = item.get("process") or {}
        style = "green" if previous and item["id"] not in previous else ""
        cells = [
            item["protocol"].upper(),
            esc(item["address"]),
            str(item["port"]),
            esc(item.get("label") or ""),
            str(item.get("pid") or "-"),
            esc(proc_label(p, item.get("pid"))),
            esc(p.get("project") or ""),
            ago(item["first_seen"]),
        ]
        tbl.add_row(*cells, style=style)
    for item in gone:
        p = item.get("process") or {}
        tbl.add_row(
            item["protocol"].upper(),
            esc(item["address"]),
            str(item["port"]),
            esc(item.get("label") or ""),
            str(item.get("pid") or "-"),
            esc(proc_label(p, item.get("pid"))),
            "",
            "closed",
            style="red dim",
        )
    return tbl


def watch_ports(params: dict[str, Any], limit: int) -> None:
    """Live-updating ports table driven by the daemon's SSE stream (Ctrl+C to exit)."""
    previous: dict[int, dict[str, Any]] = {}

    def snapshot(client: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        nonlocal previous
        items = client.list_all("ports/", max_items=limit, **params)
        current = {i["id"]: i for i in items}
        gone = [v for k, v in previous.items() if k not in current] if previous else []
        result = (items, gone)
        previous = current
        return result

    with get_client() as client:
        items, gone = snapshot(client)
        caption = "Watching for changes (Ctrl+C to stop)"
        table = _ports_table(items, {}, [])
        table.caption = caption
        try:
            with Live(table, console=console, refresh_per_second=4, transient=False) as live:
                backoff = 1.0
                while True:
                    try:
                        with get_client() as stream_client:
                            for event, _data in stream_client.stream_events():
                                if event in ("ports", "hello", "scan"):
                                    before = dict(previous)
                                    items, gone = snapshot(client)
                                    table = _ports_table(items, before, gone)
                                    table.caption = f"{caption} - {len(items)} endpoints - updated {time.strftime('%H:%M:%S')}"
                                    live.update(table)
                                    backoff = 1.0
                    except PortRegistryError:
                        table.caption = f"Daemon unreachable; retrying in {int(backoff)}s"
                        live.update(table)
                        time.sleep(backoff)
                        backoff = min(backoff * 2, 30)
        except KeyboardInterrupt:
            pass
