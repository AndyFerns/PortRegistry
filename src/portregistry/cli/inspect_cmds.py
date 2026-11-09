"""Read-mostly commands: status, scan, ports, processes, containers, conflicts, history."""

from __future__ import annotations

import time
from typing import Any

import typer
from rich.table import Table

from portregistry.cli.common import get_client, output_option, proc_label
from portregistry.cli.output import (
    SEVERITY_STYLE,
    STATUS_STYLE,
    OutputFormat,
    ago,
    console,
    emit,
    esc,
    new_table,
    styled,
)
from portregistry.exceptions import PortRegistryError


def _docker_cell(item: dict[str, Any]) -> str:
    entries = item.get("docker") or []
    return (
        ", ".join(
            f"{m['container']['name']}->{m['container_port']}/{m['protocol']}" for m in entries
        )
        or "-"
    )


# ----------------------------------------------------------------------- status


def status(output: OutputFormat = output_option()) -> None:
    """Daemon, discovery freshness, provider health and summary counts."""
    with get_client() as client:
        data = client.get("status/")

    def table() -> None:
        d, m, disc = data["daemon"], data["machine"], data["discovery"]
        s = data["summary"]
        grid = Table.grid(padding=(0, 2))
        grid.add_column(style="bold")
        grid.add_column()
        grid.add_row(
            "Daemon",
            f"v{esc(d['version'])} pid {d['pid']} at {esc(d['base_url'])}, up {int(d['uptime_seconds'])}s",
        )
        grid.add_row(
            "Machine",
            f"{esc(m['hostname'])} ({esc(m['os_name'])} {esc(m['os_version'])}, {esc(m['architecture'])}) {esc(m['uuid'])}",
        )
        fresh = "[red]stale[/]" if disc["stale"] else "[green]fresh[/]"
        grid.add_row(
            "Discovery",
            f"last scan {styled(disc['last_scan_status'], STATUS_STYLE)} {ago(disc['last_scan_at'])}; "
            f"last complete {ago(disc['last_success_at'])} ({fresh})",
        )
        for name, prov in data["providers"].items():
            msg = f" - {esc(prov['message'])}" if prov.get("message") else ""
            grid.add_row(f"  {name}", f"{styled(prov['state'], STATUS_STYLE)}{msg}")
        e = s["endpoints"]
        grid.add_row(
            "Endpoints",
            f"{e['total']} active ({e['tcp']} TCP, {e['udp']} UDP; {e['ipv4']} IPv4, {e['ipv6']} IPv6), "
            f"{e['unresolved_owner']} with unresolved owner",
        )
        grid.add_row("Processes", str(s["processes"]))
        r = s["reservations"]
        grid.add_row(
            "Registry",
            f"{s['services']} services, {r['active']} active reservations ({r['attention']} need attention)",
        )
        c = s["conflicts"]
        grid.add_row(
            "Conflicts",
            f"[bold red]{c['error']} error[/], [yellow]{c['warning']} warning[/], [cyan]{c['info']} info[/]",
        )
        grid.add_row(
            "Containers",
            f"{s['containers']['running']} running / {s['containers']['present']} known",
        )
        console.print(grid)
        platform = data.get("platform") or {}
        if platform.get("elevated") is False:
            console.print(
                "[dim]Running without elevated privileges: some process metadata may be hidden.[/]"
            )

    emit(data, output, table=table)


# ------------------------------------------------------------------------- scan


def scan(
    protocol: str | None = typer.Option(
        None, "--protocol", "-p", help="tcp or udp (default both)."
    ),
    port: int | None = typer.Option(None, "--port", help="Only reconcile this port."),
    wait: bool = typer.Option(True, "--wait/--no-wait", help="Wait for the scan to finish."),
    timeout: float = typer.Option(120.0, help="Seconds to wait."),
    output: OutputFormat = output_option(),
) -> None:
    """Ask the daemon to run a discovery scan now (requests are coalesced)."""
    with get_client() as client:
        ticket = client.post("discovery/scan/", {"protocol": protocol, "port": port})
        if wait:
            deadline = time.monotonic() + timeout
            with console.status("Scanning..."):
                while ticket["status"] not in ("done", "failed", "skipped"):
                    if time.monotonic() > deadline:
                        raise PortRegistryError(f"Scan did not finish within {timeout:.0f}s.")
                    time.sleep(0.3)
                    ticket = client.get(f"discovery/scan/{ticket['ticket']}/")

    def table() -> None:
        note = " (joined an in-flight request)" if ticket.get("coalesced_requests") else ""
        if not wait:
            console.print(f"Scan request #{ticket['ticket']} {ticket['status']}{note}.")
            return
        if ticket["status"] != "done":
            console.print(f"[red]Scan {ticket['status']}[/]: {esc(ticket.get('error'))}")
            return
        r = ticket.get("result") or {}
        scan_info = ticket.get("scan") or {}
        console.print(
            f"Scan #{ticket.get('scan_id')} {styled(r.get('status'), STATUS_STYLE)}{note}: "
            f"{r.get('socket_count', 0)} endpoints, {r.get('process_count', 0)} processes, "
            f"+{r.get('appeared', 0)} / -{r.get('disappeared', 0)} endpoints, "
            f"{r.get('owner_changed', 0)} owner changes "
            f"({scan_info.get('duration_ms', '?')} ms)"
        )
        if r.get("resolution_failures") or r.get("unknown_owners"):
            console.print(
                f"[dim]{r.get('resolution_failures', 0)} processes with restricted metadata, "
                f"{r.get('unknown_owners', 0)} endpoints without an owner (OS permissions).[/]"
            )

    emit(ticket, output, table=table)
    if ticket["status"] == "failed":
        raise typer.Exit(1)


# ------------------------------------------------------------------------ ports

ports_app = typer.Typer(
    help="Endpoints (TCP listeners and bound UDP sockets).", invoke_without_command=True
)

PORT_CSV = [
    "id",
    "protocol",
    "family",
    "address",
    "port",
    "state",
    "pid",
    "process_name",
    "exe",
    "username",
    "docker",
    "active",
    "first_seen",
    "last_seen",
]


def _port_rows(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for item in items:
        p = item.get("process") or {}
        rows.append(
            {
                **item,
                "process_name": p.get("name"),
                "exe": p.get("exe"),
                "username": p.get("username"),
                "docker": _docker_cell(item) if item.get("docker") else "",
            }
        )
    return rows


@ports_app.callback()
def ports(
    ctx: typer.Context,
    port: int | None = typer.Option(None, "--port", help="Filter by port number."),
    protocol: str | None = typer.Option(None, "--protocol", "-p", help="tcp or udp."),
    machine: str | None = typer.Option(None, "--machine", help="Machine hostname or UUID."),
    family: str | None = typer.Option(None, "--family", help="ipv4 or ipv6."),
    search: str | None = typer.Option(
        None, "--search", "-s", help="Search address/process/exe/user."
    ),
    include_inactive: bool = typer.Option(
        False, "--all", help="Include endpoints no longer observed."
    ),
    ordering: str = typer.Option(
        "port", help="port, -port, protocol, address, process, pid, first_seen, last_seen."
    ),
    limit: int = typer.Option(1000, help="Maximum rows."),
    output: OutputFormat = output_option(),
) -> None:
    """List endpoints and the processes that own them."""
    if ctx.invoked_subcommand is not None:
        return
    with get_client() as client:
        items = client.list_all(
            "ports/",
            max_items=limit,
            port=port,
            protocol=protocol,
            machine=machine,
            family=family,
            q=search,
            active="all" if include_inactive else None,
            ordering=ordering,
        )
        freshness = client.get("status/")["discovery"]

    def table() -> Table:
        caption = f"{len(items)} endpoints; last complete scan {ago(freshness['last_success_at'])}"
        if freshness["stale"]:
            caption += " [red](STALE)[/]"
        tbl = new_table(
            None,
            "ID",
            "Proto",
            "Address",
            "Port",
            "State",
            "PID",
            "Process",
            "User",
            "Docker",
            "Since",
        )
        tbl.caption = caption
        for item in items:
            p = item.get("process")
            name = esc(proc_label(p, item.get("pid")))
            if not item["active"]:
                name = f"[dim]{name} (gone)[/]"
            tbl.add_row(
                str(item["id"]),
                item["protocol"].upper(),
                esc(item["address"]),
                str(item["port"]),
                item["state"],
                str(item["pid"] or "-"),
                name,
                esc((p or {}).get("username")),
                esc(_docker_cell(item)),
                ago(item["first_seen"]),
            )
        return tbl

    emit(items, output, table=table, csv_rows=lambda: (_port_rows(items), PORT_CSV))


@ports_app.command("show")
def port_show(endpoint_id: int, output: OutputFormat = output_option()) -> None:
    """Show one endpoint with process, Docker, reservation and conflict context."""
    with get_client() as client:
        data = client.get(f"ports/{endpoint_id}/")

    def table() -> None:
        console.print(
            f"[bold]{esc(data['endpoint'])}[/] ({data['family']}, {data['state']})"
            f"{'' if data['active'] else ' [dim](no longer observed)[/]'}"
        )
        console.print(f"First seen {ago(data['first_seen'])}, last seen {ago(data['last_seen'])}")
        p = data.get("process")
        if p:
            console.print(f"Process: {esc(p['name'])} pid {p['pid']} user {esc(p.get('username'))}")
            console.print(f"  exe: {esc(p.get('exe'))}")
            if p.get("cmdline"):
                console.print(f"  cmdline: {esc(' '.join(p['cmdline']))}")
            if p.get("metadata_errors"):
                console.print(
                    f"  [yellow]restricted metadata:[/] {esc(', '.join(p['metadata_errors']))}"
                )
        else:
            console.print(f"Process: [yellow]unresolved[/] (pid {data.get('pid') or 'unknown'})")
        for m in data.get("docker") or []:
            console.print(
                f"Docker: {esc(m['container']['name'])} ({esc(m['container']['image'])}) -> {m['container_port']}/{m['protocol']}"
            )
        for r in data.get("reservations") or []:
            service = (r.get("service") or {}).get("name")
            console.print(
                f"Reservation #{r['id']} {esc(r['endpoint'])}"
                + (f" for {esc(service)}" if service else "")
            )
        for c in data.get("conflicts") or []:
            console.print(f"{styled(c['severity'], SEVERITY_STYLE)} {esc(c['title'])}")

    emit(data, output, table=table)


# -------------------------------------------------------------------- processes

processes_app = typer.Typer(
    help="Observed process instances (owning endpoints).", invoke_without_command=True
)


@processes_app.callback()
def processes(
    ctx: typer.Context,
    search: str | None = typer.Option(None, "--search", "-s", help="Name, exe, user or PID."),
    pid: int | None = typer.Option(None, "--pid"),
    include_inactive: bool = typer.Option(
        False, "--all", help="Include processes no longer observed."
    ),
    output: OutputFormat = output_option(),
) -> None:
    """List processes that own endpoints."""
    if ctx.invoked_subcommand is not None:
        return
    with get_client() as client:
        items = client.list_all(
            "processes/", q=search, pid=pid, active="all" if include_inactive else None
        )

    def table() -> Table:
        tbl = new_table(
            None, "ID", "PID", "Name", "User", "Endpoints", "Started", "Identity", "Executable"
        )
        for p in items:
            ident = "complete" if p["identity_complete"] else "[yellow]incomplete[/]"
            tbl.add_row(
                str(p["id"]),
                str(p["pid"]),
                esc(p["name"]),
                esc(p["username"]),
                str(p.get("active_socket_count", "-")),
                ago(p["started_at"]),
                ident,
                esc(p["exe"]),
            )
        return tbl

    columns = [
        "id",
        "pid",
        "name",
        "username",
        "active_socket_count",
        "started_at",
        "identity_complete",
        "exe",
        "active",
    ]
    emit(items, output, table=table, csv_rows=lambda: (items, columns))


@processes_app.command("show")
def process_show(process_id: int, output: OutputFormat = output_option()) -> None:
    """Show a process instance and its endpoints."""
    with get_client() as client:
        data = client.get(f"processes/{process_id}/")

    def table() -> None:
        console.print(
            f"[bold]{esc(data['name'])}[/] pid {data['pid']} ({'active' if data['active'] else 'gone'})"
        )
        console.print(
            f"Identity: {esc(data['identity_key'])} ({'complete' if data['identity_complete'] else 'incomplete: creation time unknown'})"
        )
        for label, key in [
            ("Executable", "exe"),
            ("User", "username"),
            ("Parent PID", "ppid"),
            ("Working dir", "cwd"),
            ("Started", "started_at"),
        ]:
            console.print(f"{label}: {esc(data.get(key))}")
        if data.get("cmdline"):
            console.print(f"Command line: {esc(' '.join(data['cmdline']))}")
        if data.get("metadata_errors"):
            console.print(f"[yellow]Restricted metadata:[/] {esc(data['metadata_errors'])}")
        tbl = new_table("Endpoints", "ID", "Endpoint", "State", "Active", "First seen")
        for s in data.get("sockets", []):
            tbl.add_row(
                str(s["id"]),
                esc(s["endpoint"]),
                s["state"],
                "yes" if s["active"] else "no",
                ago(s["first_seen"]),
            )
        console.print(tbl)

    emit(data, output, table=table)


# ------------------------------------------------------------------- containers

containers_app = typer.Typer(
    help="Docker containers and port mappings (read-only).", invoke_without_command=True
)


@containers_app.callback()
def containers(
    ctx: typer.Context,
    include_removed: bool = typer.Option(False, "--all", help="Include removed containers."),
    output: OutputFormat = output_option(),
) -> None:
    """List Docker containers and published ports."""
    if ctx.invoked_subcommand is not None:
        return
    with get_client() as client:
        page = client.get("containers/", present="all" if include_removed else "true", limit=1000)
    items = page.get("results", [])
    docker = page.get("docker") or {}

    def table() -> Table:
        tbl = new_table(None, "ID", "Name", "Image", "Status", "Published", "Internal")
        state = docker.get("state", "unknown")
        tbl.caption = f"Docker provider: {state}" + (
            f" - {docker.get('message')}" if docker.get("message") else ""
        )
        for c in items:
            published = ", ".join(
                f"{m['host_ip'] or '0.0.0.0'}:{m['host_port']}->{m['container_port']}/{m['protocol']}"
                for m in c["ports"]
                if m["published"] and m["active"]
            )
            internal = ", ".join(
                f"{m['container_port']}/{m['protocol']}" for m in c["ports"] if not m["published"]
            )
            status_text = c["status"] if c["present"] else "removed"
            tbl.add_row(
                c["short_id"],
                esc(c["name"]),
                esc(c["image"]),
                styled(status_text, STATUS_STYLE),
                esc(published or "-"),
                esc(internal or "-"),
            )
        return tbl

    emit(page, output, table=table)


@containers_app.command("show")
def container_show(ref: str, output: OutputFormat = output_option()) -> None:
    """Show one container (by id prefix or name)."""
    with get_client() as client:
        data = client.get(f"containers/{ref}/")
    emit(data, output if output is not OutputFormat.table else OutputFormat.json)


# -------------------------------------------------------------------- conflicts


def conflicts(
    include_info: bool = typer.Option(
        False, "--all", "-a", help="Include info-level findings (e.g. unregistered listeners)."
    ),
    type_: str | None = typer.Option(None, "--type", help="Filter by conflict type."),
    severity: str | None = typer.Option(None, "--severity", help="error, warning or info."),
    certainty: str | None = typer.Option(None, "--certainty", help="definite or potential."),
    brief: bool = typer.Option(False, "--brief", help="Hide explanations."),
    output: OutputFormat = output_option(),
) -> None:
    """Show current conflicts with explanations."""
    with get_client() as client:
        items = client.list_all(
            "conflicts/",
            type=type_,
            severity=severity,
            certainty=certainty,
            min_severity=None if (include_info or severity) else "warning",
        )

    def table() -> Table | None:
        if not items:
            console.print(
                "[green]No conflicts.[/]"
                + ("" if include_info else " (use --all to include informational findings)")
            )
            return None
        tbl = new_table(None, "Severity", "Certainty", "Type", "Endpoint", "Finding")
        for c in items:
            endpoint = (
                f"{c['protocol']} {c['address'] or '*'}:{c['port']}" if c.get("port") else "-"
            )
            text = f"[bold]{esc(c['title'])}[/]"
            if not brief:
                text += f"\n[dim]{esc(c['explanation'])}[/]"
            tbl.add_row(
                styled(c["severity"], SEVERITY_STYLE),
                c["certainty"],
                c["type"],
                esc(endpoint),
                text,
            )
        return tbl

    columns = [
        "id",
        "severity",
        "certainty",
        "type",
        "protocol",
        "address",
        "port",
        "title",
        "explanation",
        "reservation_id",
        "service_id",
        "first_seen",
    ]
    emit(items, output, table=table, csv_rows=lambda: (items, columns))


# ---------------------------------------------------------------------- history


def history(
    type_: str | None = typer.Option(
        None, "--type", help="Event type prefix, e.g. endpoint or reservation.created."
    ),
    since: str | None = typer.Option(None, "--since", help="ISO timestamp."),
    entity_type: str | None = typer.Option(None, "--entity-type"),
    search: str | None = typer.Option(None, "--search", "-s"),
    limit: int = typer.Option(50, "--limit", "-n"),
    output: OutputFormat = output_option(),
) -> None:
    """Show meaningful state changes (not every poll)."""
    with get_client() as client:
        page = client.get(
            "history/", type=type_, since=since, entity_type=entity_type, q=search, limit=limit
        )
    items = page.get("results", [])

    def table() -> Table:
        tbl = new_table(None, "Time", "Type", "Sev", "Summary")
        for e in items:
            tbl.add_row(
                e["timestamp"][:19].replace("T", " "),
                e["type"],
                styled(e["severity"], SEVERITY_STYLE),
                esc(e["summary"]),
            )
        tbl.caption = f"{len(items)} of {page.get('count', len(items))} events"
        return tbl

    columns = ["id", "timestamp", "type", "severity", "entity_type", "entity_id", "summary"]
    emit(items, output, table=table, csv_rows=lambda: (items, columns))


def machines(output: OutputFormat = output_option()) -> None:
    """Show known machines (the local machine in this release)."""
    with get_client() as client:
        items = client.list_all("machines/")

    def table() -> Table:
        tbl = new_table(None, "UUID", "Hostname", "OS", "Arch", "Local", "Online", "Last seen")
        for m in items:
            tbl.add_row(
                esc(m["uuid"]),
                esc(m["hostname"]),
                esc(f"{m['os_name']} {m['os_version']}"),
                esc(m["architecture"]),
                "yes" if m["is_local"] else "no",
                "yes" if m["online"] else "no",
                ago(m["last_seen"]),
            )
        return tbl

    columns = [
        "uuid",
        "hostname",
        "os_name",
        "os_version",
        "architecture",
        "is_local",
        "online",
        "last_seen",
    ]
    emit(items, output, table=table, csv_rows=lambda: (items, columns))


def report(output: OutputFormat = output_option()) -> None:
    """Summary report: status, services, reservations and actionable conflicts."""
    with get_client() as client:
        status_data = client.get("status/")
        services = client.list_all("services/")
        reservation_items = client.list_all("reservations/", status="active")
        conflict_items = client.list_all("conflicts/", min_severity="warning")
    data = {
        "machine": status_data["machine"],
        "summary": status_data["summary"],
        "discovery": status_data["discovery"],
        "services": services,
        "reservations": reservation_items,
        "conflicts": conflict_items,
    }

    def table() -> None:
        from rich.markdown import Markdown

        m, s = data["machine"], data["summary"]
        lines = [
            f"# PortRegistry report: {m['hostname']}",
            "",
            f"- Endpoints: {s['endpoints']['total']} ({s['endpoints']['tcp']} TCP / {s['endpoints']['udp']} UDP)",
            f"- Services: {s['services']}, active reservations: {s['reservations']['active']}",
            f"- Conflicts: {s['conflicts']['error']} error, {s['conflicts']['warning']} warning, {s['conflicts']['info']} info",
            f"- Discovery: last complete scan {ago(data['discovery']['last_success_at'])}"
            + (" (stale)" if data["discovery"]["stale"] else ""),
            "",
            "## Reservations",
            "",
        ]
        for r in reservation_items:
            svc = (r.get("service") or {}).get("name") or "-"
            lines.append(
                f"- #{r['id']} `{r['endpoint']}` service: {svc} [{r.get('display_status', r['status'])}]"
            )
        lines += ["", "## Actionable conflicts", ""]
        for c in conflict_items:
            lines.append(f"- **{c['severity']}/{c['certainty']}** {c['title']}: {c['explanation']}")
        if not conflict_items:
            lines.append("- none")
        console.print(Markdown("\n".join(lines)))

    emit(data, output, table=table)
