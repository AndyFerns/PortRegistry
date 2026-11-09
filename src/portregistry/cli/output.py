"""Rendering helpers: rich tables, JSON and CSV."""

from __future__ import annotations

import csv
import io
import json
import sys
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from rich.console import Console
from rich.markup import escape
from rich.table import Table

console = Console()
err_console = Console(stderr=True)


class OutputFormat(StrEnum):
    table = "table"
    json = "json"
    csv = "csv"


SEVERITY_STYLE = {"error": "bold red", "warning": "yellow", "info": "cyan"}
STATUS_STYLE = {
    "ok": "green",
    "complete": "green",
    "active": "green",
    "running": "green",
    "degraded": "yellow",
    "partial": "yellow",
    "attention": "yellow",
    "unavailable": "red",
    "failed": "red",
    "released": "dim",
    "disabled": "dim",
    "unknown": "dim",
}


def styled(value: str | None, styles: dict[str, str]) -> str:
    text = escape(str(value or "-"))
    style = styles.get(str(value or ""))
    return f"[{style}]{text}[/]" if style else text


def esc(value: Any) -> str:
    """Escape untrusted values (process names, notes...) for rich markup."""
    if value is None or value == "":
        return "-"
    return escape(str(value))


def ago(value: str | None) -> str:
    if not value:
        return "-"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return value
    seconds = (datetime.now(UTC) - dt).total_seconds()
    if seconds < 0:
        seconds = 0
    if seconds < 60:
        return f"{int(seconds)}s ago"
    if seconds < 3600:
        return f"{int(seconds // 60)}m ago"
    if seconds < 86400:
        return f"{int(seconds // 3600)}h ago"
    return f"{int(seconds // 86400)}d ago"


def print_json(data: Any) -> None:
    sys.stdout.write(json.dumps(data, indent=2, default=str) + "\n")


def print_csv(rows: Sequence[dict[str, Any]], columns: Sequence[str]) -> None:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(columns), extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({c: _csv_value(row.get(c)) for c in columns})
    sys.stdout.write(buffer.getvalue())


def _csv_value(value: Any) -> Any:
    if isinstance(value, dict | list):
        return json.dumps(value, default=str)
    return value


def emit(
    data: Any,
    fmt: OutputFormat,
    *,
    table: Callable[[], Table | None] | None = None,
    csv_rows: Callable[[], tuple[Sequence[dict[str, Any]], Sequence[str]]] | None = None,
) -> None:
    if fmt is OutputFormat.json:
        print_json(data)
    elif fmt is OutputFormat.csv:
        if csv_rows is None:
            print_json(data)
        else:
            rows, columns = csv_rows()
            print_csv(rows, columns)
    elif table is not None:
        rendered = table()
        if rendered is not None:
            console.print(rendered)


def new_table(title: str | None = None, *columns: str) -> Table:
    tbl = Table(title=title, header_style="bold", show_lines=False, pad_edge=False, expand=False)
    for column in columns:
        tbl.add_column(column, overflow="fold")
    return tbl
