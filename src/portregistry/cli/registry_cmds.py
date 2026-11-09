"""Service registry and reservation commands."""

from __future__ import annotations

from typing import Any

import typer
from rich.table import Table

from portregistry.cli.common import get_client, output_option
from portregistry.cli.output import (
    SEVERITY_STYLE,
    STATUS_STYLE,
    OutputFormat,
    console,
    emit,
    esc,
    new_table,
    styled,
)

service_app = typer.Typer(help="Manage registered services.", no_args_is_help=True)
reservations_app = typer.Typer(
    help="List and manage port reservations.", invoke_without_command=True
)

SERVICE_COLUMNS = [
    "id",
    "name",
    "category",
    "expected_executable",
    "expected_working_directory",
    "documentation_url",
    "active_reservation_count",
    "description",
]
RESERVATION_COLUMNS = [
    "id",
    "protocol",
    "bind_address",
    "port",
    "status",
    "display_status",
    "service_name",
    "description",
    "conflict_count",
]


def _print_findings(findings: list[dict[str, Any]], *, heading: str) -> None:
    if not findings:
        console.print(
            "[green]No conflicts detected.[/] (Reservations are advisory; nothing prevents other programs from binding.)"
        )
        return
    console.print(f"[bold]{heading}[/]")
    for f in findings:
        console.print(
            f"  {styled(f['severity'], SEVERITY_STYLE)} ({f['certainty']}) [bold]{esc(f['title'])}[/]"
        )
        console.print(f"    [dim]{esc(f['explanation'])}[/]")


def _service_body(**fields: Any) -> dict[str, Any]:
    return {k: v for k, v in fields.items() if v is not None}


# --------------------------------------------------------------------- services


@service_app.command("list")
def service_list(
    search: str | None = typer.Option(None, "--search", "-s"),
    output: OutputFormat = output_option(),
) -> None:
    """List services."""
    with get_client() as client:
        items = client.list_all("services/", q=search)

    def table() -> Table:
        tbl = new_table(
            None, "ID", "Name", "Category", "Expected executable", "Reservations", "Description"
        )
        for s in items:
            tbl.add_row(
                str(s["id"]),
                esc(s["name"]),
                esc(s["category"]),
                esc(s["expected_executable"]),
                str(s.get("active_reservation_count", "-")),
                esc(s["description"]),
            )
        return tbl

    emit(items, output, table=table, csv_rows=lambda: (items, SERVICE_COLUMNS))


@service_app.command("add")
def service_add(
    name: str = typer.Argument(..., help="Unique service name."),
    description: str | None = typer.Option(None, "--description", "-d"),
    category: str | None = typer.Option(None, "--category", "-c"),
    exe: str | None = typer.Option(
        None,
        "--exe",
        help="Expected executable: name (python), full path, or docker:<container-or-image>.",
    ),
    cwd: str | None = typer.Option(None, "--cwd", help="Expected working directory."),
    docs: str | None = typer.Option(None, "--docs", help="Documentation URL (http/https)."),
    notes: str | None = typer.Option(None, "--notes"),
    output: OutputFormat = output_option(),
) -> None:
    """Register a service."""
    body = _service_body(
        name=name,
        description=description,
        category=category,
        expected_executable=exe,
        expected_working_directory=cwd,
        documentation_url=docs,
        notes=notes,
    )
    with get_client() as client:
        data = client.post("services/", body)
    emit(
        data,
        output,
        table=lambda: console.print(
            f"[green]Service #{data['id']} '{esc(data['name'])}' registered.[/]"
        ),
    )


@service_app.command("show")
def service_show(
    ref: str = typer.Argument(..., help="Service id or name."),
    output: OutputFormat = output_option(),
) -> None:
    """Show a service, its reservations and conflicts."""
    with get_client() as client:
        data = client.get(f"services/{ref}/")

    def table() -> None:
        console.print(f"[bold]{esc(data['name'])}[/] (#{data['id']}) {esc(data['category'])}")
        for label, key in [
            ("Description", "description"),
            ("Expected executable", "expected_executable"),
            ("Expected working dir", "expected_working_directory"),
            ("Docs", "documentation_url"),
            ("Notes", "notes"),
        ]:
            if data.get(key):
                console.print(f"{label}: {esc(data[key])}")
        tbl = new_table("Reservations", "ID", "Endpoint", "Status")
        for r in data.get("reservations", []):
            tbl.add_row(
                str(r["id"]),
                esc(r["endpoint"]),
                styled(r.get("display_status", r["status"]), STATUS_STYLE),
            )
        console.print(tbl)
        _print_findings(data.get("conflicts", []), heading="Conflicts")

    emit(data, output, table=table)


@service_app.command("edit")
def service_edit(
    ref: str = typer.Argument(..., help="Service id or name."),
    name: str | None = typer.Option(None, "--name"),
    description: str | None = typer.Option(None, "--description", "-d"),
    category: str | None = typer.Option(None, "--category", "-c"),
    exe: str | None = typer.Option(None, "--exe"),
    cwd: str | None = typer.Option(None, "--cwd"),
    docs: str | None = typer.Option(None, "--docs"),
    notes: str | None = typer.Option(None, "--notes"),
    output: OutputFormat = output_option(),
) -> None:
    """Update fields of a service (only the options given)."""
    body = _service_body(
        name=name,
        description=description,
        category=category,
        expected_executable=exe,
        expected_working_directory=cwd,
        documentation_url=docs,
        notes=notes,
    )
    if not body:
        raise typer.BadParameter("Nothing to change; pass at least one option.")
    with get_client() as client:
        data = client.patch(f"services/{ref}/", body)
    emit(data, output, table=lambda: console.print(f"[green]Service #{data['id']} updated.[/]"))


@service_app.command("delete")
def service_delete(
    ref: str = typer.Argument(..., help="Service id or name."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask for confirmation."),
    output: OutputFormat = output_option(),
) -> None:
    """Delete a service. Its reservations are kept (unlinked); history is kept."""
    if not yes:
        typer.confirm(f"Delete service '{ref}'? Reservations are kept but unlinked.", abort=True)
    with get_client() as client:
        data = client.delete(f"services/{ref}/")

    def table() -> None:
        console.print(f"[green]Deleted service '{esc(data['deleted']['name'])}'.[/]")
        if data["unlinked_reservations"]:
            console.print(
                f"Reservations kept but unlinked: {', '.join('#' + str(i) for i in data['unlinked_reservations'])}"
            )

    emit(data, output, table=table)


# ------------------------------------------------------------------ reservations


def reserve(
    port: int = typer.Argument(..., help="Port number (1-65535)."),
    protocol: str = typer.Option("tcp", "--protocol", "-p", help="tcp or udp."),
    address: str = typer.Option(
        "*", "--address", "-a", help="Bind address: IP literal, 0.0.0.0, :: or * (any)."
    ),
    service: str | None = typer.Option(None, "--service", "-s", help="Service id or name."),
    description: str | None = typer.Option(None, "--description", "-d"),
    dry_run: bool = typer.Option(
        False, "--dry-run", "--check", help="Only check occupancy and overlaps."
    ),
    output: OutputFormat = output_option(),
) -> None:
    """Create an advisory reservation and report any conflicts."""
    body: dict[str, Any] = {"port": port, "protocol": protocol, "bind_address": address}
    if service:
        body["service"] = service
    if description:
        body["description"] = description
    with get_client() as client:
        if dry_run:
            data = client.post("reservations/check/", body)
            emit(
                data,
                output,
                table=lambda: _print_findings(data["findings"], heading="Findings if reserved:"),
            )
            return
        data = client.post("reservations/", body)

    def table() -> None:
        svc = (data.get("service") or {}).get("name")
        console.print(
            f"[green]Reservation #{data['id']} created:[/] {esc(data['endpoint'])}"
            + (f" for '{esc(svc)}'" if svc else "")
        )
        _print_findings(data.get("conflicts", []), heading="Conflicts:")

    emit(data, output, table=table)


def _reservation_rows(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            **r,
            "service_name": (r.get("service") or {}).get("name"),
            "conflict_count": len(r.get("conflicts", [])),
        }
        for r in items
    ]


@reservations_app.callback()
def reservations(
    ctx: typer.Context,
    status: str = typer.Option("active", "--status", help="active, released or all."),
    port: int | None = typer.Option(None, "--port"),
    protocol: str | None = typer.Option(None, "--protocol", "-p"),
    service: str | None = typer.Option(None, "--service", "-s"),
    output: OutputFormat = output_option(),
) -> None:
    """List reservations (advisory claims; not OS-level locks)."""
    if ctx.invoked_subcommand is not None:
        return
    with get_client() as client:
        items = client.list_all(
            "reservations/", status=status, port=port, protocol=protocol, service=service
        )

    def table() -> Table:
        tbl = new_table(None, "ID", "Endpoint", "Status", "Service", "Conflicts", "Description")
        for r in items:
            worst = [c for c in r.get("conflicts", []) if c["severity"] != "info"]
            conflict_text = (
                ", ".join(sorted({c["type"] for c in worst}))
                if worst
                else ("info" if r.get("conflicts") else "-")
            )
            tbl.add_row(
                str(r["id"]),
                esc(r["endpoint"]),
                styled(r.get("display_status", r["status"]), STATUS_STYLE),
                esc((r.get("service") or {}).get("name")),
                esc(conflict_text),
                esc(r["description"]),
            )
        tbl.caption = (
            "Reservations are advisory: they do not stop other programs from binding a port."
        )
        return tbl

    emit(
        items, output, table=table, csv_rows=lambda: (_reservation_rows(items), RESERVATION_COLUMNS)
    )


@reservations_app.command("show")
def reservation_show(reservation_id: int, output: OutputFormat = output_option()) -> None:
    """Show a reservation with its current conflicts."""
    with get_client() as client:
        data = client.get(f"reservations/{reservation_id}/")

    def table() -> None:
        svc = (data.get("service") or {}).get("name")
        console.print(
            f"[bold]Reservation #{data['id']}[/] {esc(data['endpoint'])} {styled(data.get('display_status', data['status']), STATUS_STYLE)}"
        )
        console.print(f"Service: {esc(svc)}  Description: {esc(data['description'])}")
        _print_findings(data.get("conflicts", []), heading="Conflicts:")

    emit(data, output, table=table)


@reservations_app.command("edit")
def reservation_edit(
    reservation_id: int,
    port: int | None = typer.Option(None, "--port"),
    protocol: str | None = typer.Option(None, "--protocol", "-p"),
    address: str | None = typer.Option(None, "--address", "-a"),
    service: str | None = typer.Option(
        None, "--service", "-s", help="Service id/name, or 'none' to unlink."
    ),
    description: str | None = typer.Option(None, "--description", "-d"),
    status: str | None = typer.Option(None, "--status", help="active or released."),
    output: OutputFormat = output_option(),
) -> None:
    """Edit a reservation (only the options given)."""
    body: dict[str, Any] = {}
    if port is not None:
        body["port"] = port
    if protocol is not None:
        body["protocol"] = protocol
    if address is not None:
        body["bind_address"] = address
    if service is not None:
        body["service"] = None if service.lower() == "none" else service
    if description is not None:
        body["description"] = description
    if status is not None:
        body["status"] = status
    if not body:
        raise typer.BadParameter("Nothing to change; pass at least one option.")
    with get_client() as client:
        data = client.patch(f"reservations/{reservation_id}/", body)

    def table() -> None:
        console.print(
            f"[green]Reservation #{data['id']} updated:[/] {esc(data['endpoint'])} ({data['status']})"
        )
        _print_findings(data.get("conflicts", []), heading="Conflicts:")

    emit(data, output, table=table)


@reservations_app.command("delete")
def reservation_delete(
    reservation_id: int,
    yes: bool = typer.Option(False, "--yes", "-y"),
    output: OutputFormat = output_option(),
) -> None:
    """Permanently delete a reservation (history keeps a snapshot). Prefer `release`."""
    if not yes:
        typer.confirm(f"Permanently delete reservation #{reservation_id}?", abort=True)
    with get_client() as client:
        data = client.delete(f"reservations/{reservation_id}/")
    emit(
        data,
        output,
        table=lambda: console.print(f"[green]Deleted reservation #{reservation_id}.[/]"),
    )


def release(reservation_id: int, output: OutputFormat = output_option()) -> None:
    """Release a reservation (kept with status 'released')."""
    with get_client() as client:
        data = client.post(f"reservations/{reservation_id}/release/")
    emit(
        data,
        output,
        table=lambda: console.print(
            f"[green]Released reservation #{data['id']}[/] ({esc(data['endpoint'])})."
        ),
    )
