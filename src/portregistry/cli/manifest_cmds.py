"""Declarative manifests: ``portregistry apply``, ``export`` and ``init``."""

from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

import typer

from portregistry.cli.common import get_client, output_option
from portregistry.cli.output import OutputFormat, console, emit, esc
from portregistry.core.tomlwriter import dumps
from portregistry.exceptions import PortRegistryError

DEFAULT_FILE = "portregistry.toml"

TEMPLATE = """\
# PortRegistry manifest: services and the ports they reserve.
# Apply with `portregistry apply` (preview with --dry-run). Commit it to share port
# assignments with your team. Relative working directories are resolved against
# this file's directory.
version = 1

# [[service]]
# name = "web"
# expected_executable = "node"
# expected_working_directory = "."
# description = "Frontend dev server"
#
#   [[service.port]]
#   port = 3000
#   protocol = "tcp"
#   address = "*"
"""


def _load(path: Path) -> dict[str, Any]:
    try:
        document = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise PortRegistryError(
            f"Manifest not found: {path}. Create one with `portregistry init`."
        ) from exc
    except tomllib.TOMLDecodeError as exc:
        raise PortRegistryError(f"{path} is not valid TOML: {exc}") from exc
    base = path.resolve().parent
    for service in document.get("service", []) or []:
        if isinstance(service, dict):
            cwd = service.get("expected_working_directory")
            if isinstance(cwd, str) and cwd and not Path(cwd).is_absolute():
                service["expected_working_directory"] = str((base / cwd).resolve())
    return document


def _print_plan(result: dict[str, Any]) -> None:
    s, r = result["services"], result["reservations"]

    def line(label: str, items: list[Any], style: str) -> None:
        if items:
            names = ", ".join(
                esc(i if isinstance(i, str) else f"{i['name']} ({', '.join(i['fields'])})")
                for i in items
            )
            console.print(f"  [{style}]{label}[/]: {names}")

    console.print(f"Services from {esc(result['source'])}:")
    line("create", s["create"], "green")
    line("update", s["update"], "cyan")
    line("delete (prune)", s["prune"], "red")
    console.print(f"  unchanged: {len(s['unchanged'])}")
    console.print("Reservations:")
    line("create", r["create"], "green")
    line("reactivate/update", r["reactivate_or_update"], "cyan")
    line("release (prune)", r["release"], "red")
    console.print(f"  unchanged: {len(r['unchanged'])}")


def apply(
    file: Path = typer.Argument(
        Path(DEFAULT_FILE), help="Manifest file (default ./portregistry.toml)."
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Show the changes without applying them."
    ),
    prune: bool = typer.Option(
        False,
        "--prune",
        help="Release/delete items this manifest created earlier but no longer lists.",
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Do not ask before pruning."),
    output: OutputFormat = output_option(),
) -> None:
    """Apply a declarative manifest (services + reservations) to the registry."""
    document = _load(file)
    source = str(file.resolve())
    with get_client() as client:
        plan = client.post(
            "registry/apply/",
            {"document": document, "source": source, "prune": prune, "dry_run": True},
        )
        if dry_run or plan["changes"] == 0:
            result = plan
        else:
            destructive = plan["services"]["prune"] or plan["reservations"]["release"]
            if destructive and not yes and output is OutputFormat.table:
                _print_plan(plan)
                typer.confirm("Apply these changes, including pruning?", abort=True)
            result = client.post(
                "registry/apply/", {"document": document, "source": source, "prune": prune}
            )

    def table() -> None:
        _print_plan(result)
        if result.get("applied"):
            console.print(f"[green]Applied {result['changes']} change(s).[/]")
        elif result["changes"] == 0:
            console.print("[green]Already up to date.[/]")
        else:
            console.print(f"[yellow]Dry run: {result['changes']} change(s) not applied.[/]")

    emit(result, output, table=table)


def export(
    out: Path | None = typer.Option(
        None, "--output-file", "-f", help="Write to this file instead of stdout."
    ),
    fmt: str = typer.Option("toml", "--format", help="toml or json."),
    service: str | None = typer.Option(None, "--service", "-s", help="Only this service."),
    include_released: bool = typer.Option(False, "--include-released"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    """Export services and reservations as a manifest (backup / share / restore with `apply`)."""
    with get_client() as client:
        document = client.get(
            "registry/export/", service=service, include_released="1" if include_released else None
        )
    if fmt == "json":
        text = json.dumps(document, indent=2) + "\n"
    elif fmt == "toml":
        text = dumps(
            document, header="PortRegistry manifest export. Restore with: portregistry apply <file>"
        )
    else:
        raise typer.BadParameter("--format must be toml or json.")
    if out is None:
        typer.echo(text, nl=False)
        return
    if out.exists() and not force:
        raise PortRegistryError(f"{out} exists; pass --force to overwrite.")
    out.write_text(text, encoding="utf-8")
    console.print(f"Wrote {len(document.get('service', []))} service(s) to {esc(out)}.")


def init(
    out: Path = typer.Option(Path(DEFAULT_FILE), "--output-file", "-f", help="Manifest to create."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    """Scaffold portregistry.toml for the current directory's project.

    Includes registered services whose working directory is inside this directory,
    plus running processes detected in this project (with their ports).
    """
    if out.exists() and not force:
        raise PortRegistryError(f"{out} exists; pass --force to overwrite.")
    here = Path.cwd().resolve()
    services: list[dict[str, Any]] = []
    with get_client() as client:
        exported = client.get("registry/export/")
        for svc in exported.get("service", []):
            cwd = svc.get("expected_working_directory")
            if cwd and _inside(Path(cwd), here):
                svc["expected_working_directory"] = _relative(Path(cwd), out.resolve().parent)
                services.append(svc)
        known = {s["name"].lower() for s in services}
        for proc in client.list_all("processes/"):
            root = proc.get("project_root")
            if not root or not _inside(Path(root), here):
                continue
            ports = [
                s for s in client.get(f"processes/{proc['id']}/").get("sockets", []) if s["active"]
            ]
            name = (proc.get("project_name") or proc["name"] or "service").removesuffix(".exe")
            if name.lower() in known or not ports:
                continue
            known.add(name.lower())
            entry: dict[str, Any] = {
                "name": name,
                "expected_executable": Path(proc.get("exe") or proc["name"]).name,
            }
            if proc.get("cwd"):
                entry["expected_working_directory"] = _relative(
                    Path(proc["cwd"]), out.resolve().parent
                )
            entry["port"] = [
                {"port": s["port"], "protocol": s["protocol"], "address": "*"} for s in ports
            ]
            services.append(entry)
    if services:
        text = dumps(
            {"version": 1, "service": services},
            header=TEMPLATE.split("version = 1")[0].replace("# ", "").strip(),
        )
    else:
        text = TEMPLATE
    out.write_text(text, encoding="utf-8")
    console.print(
        f"Wrote {esc(out)} with {len(services)} service(s)."
        if services
        else f"Wrote a commented template to {esc(out)} (nothing detected for {esc(here)})."
    )
    console.print("Review it, then run `portregistry apply --dry-run`.")


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
        return True
    except (ValueError, OSError):
        return False


def _relative(path: Path, base: Path) -> str:
    try:
        rel = path.resolve().relative_to(base)
        return "." if str(rel) == "." else rel.as_posix()
    except (ValueError, OSError):
        return str(path)
