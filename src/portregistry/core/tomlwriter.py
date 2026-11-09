"""Minimal TOML writer for PortRegistry manifests (stdlib has a reader only).

Supports exactly what manifests use: top-level scalars, arrays of tables, and
one level of nested arrays of tables. Strings are emitted as TOML basic strings.
"""

from __future__ import annotations

import json
from typing import Any


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    if value is None:
        raise TypeError("TOML cannot represent null; omit the key instead")
    if isinstance(value, list):
        return "[" + ", ".join(_scalar(v) for v in value) + "]"
    # JSON string escaping is valid TOML basic-string escaping for our purposes.
    return json.dumps(str(value), ensure_ascii=False)


def _table_body(table: dict[str, Any], lines: list[str]) -> list[tuple[str, list[dict[str, Any]]]]:
    nested: list[tuple[str, list[dict[str, Any]]]] = []
    for key, value in table.items():
        if value is None:
            continue
        if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
            nested.append((key, value))
        else:
            lines.append(f"{key} = {_scalar(value)}")
    return nested


def dumps(document: dict[str, Any], header: str = "") -> str:
    lines: list[str] = []
    if header:
        lines.extend(f"# {line}" if line else "#" for line in header.splitlines())
        lines.append("")
    arrays = _table_body(document, lines)
    for name, items in arrays:
        for item in items:
            lines.append("")
            lines.append(f"[[{name}]]")
            for child_name, children in _table_body(item, lines):
                for child in children:
                    lines.append("")
                    lines.append(f"[[{name}.{child_name}]]")
                    if _table_body(child, lines):
                        raise TypeError("Only one level of nested tables is supported")
    return "\n".join(lines).strip() + "\n"
