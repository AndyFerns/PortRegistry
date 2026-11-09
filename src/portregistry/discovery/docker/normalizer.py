"""Normalize Docker inspect data into PortRegistry types.

Three concepts are kept distinct:

* internal container ports (``Config.ExposedPorts``) - ``host_port`` is None;
* host-published mappings (``NetworkSettings.Ports`` / ``HostConfig.PortBindings``);
* host-visible sockets, which come from native discovery, not from Docker.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from portregistry.core.addresses import normalize_address
from portregistry.core.types import (
    DockerContainerInfo,
    DockerImageInfo,
    DockerPortInfo,
    Protocol,
)

MAX_LABELS = 100
MAX_LABEL_VALUE = 500


def parse_docker_time(value: Any) -> datetime | None:
    if not value or not isinstance(value, str) or value.startswith("0001-01-01"):
        return None
    text = value.strip().replace("Z", "+00:00")
    # Docker uses nanosecond precision; Python supports microseconds.
    if "." in text:
        head, rest = text.split(".", 1)
        frac = ""
        tz = ""
        for i, ch in enumerate(rest):
            if not ch.isdigit():
                frac, tz = rest[:i], rest[i:]
                break
        else:
            frac = rest
        text = f"{head}.{frac[:6].ljust(6, '0')}{tz}"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def parse_image_ref(ref: str) -> tuple[str | None, str | None, str | None]:
    """Split ``repo[:tag][@digest]`` into parts. Bare image IDs yield (None, None, None)."""
    if not ref or ref.startswith("sha256:"):
        return None, None, None
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    repo, tag = ref, None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        repo, tag = ref.rsplit(":", 1)
    elif digest is None:
        tag = "latest"
    return repo, tag, digest


def _parse_port_key(key: str) -> tuple[int, Protocol] | None:
    try:
        number, _, proto = key.partition("/")
        protocol = Protocol((proto or "tcp").lower())
        port = int(number)
    except ValueError:
        return None
    if protocol not in (Protocol.TCP, Protocol.UDP) or not 0 < port <= 65535:
        return None
    return port, protocol


def _normalize_host_ip(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return "0.0.0.0"  # Docker publishes on all interfaces when HostIp is empty
    try:
        return normalize_address(text)[0]
    except ValueError:
        return text


def parse_ports(attrs: dict[str, Any]) -> list[DockerPortInfo]:
    config = attrs.get("Config") or {}
    network = attrs.get("NetworkSettings") or {}
    host_config = attrs.get("HostConfig") or {}
    live = network.get("Ports") or {}
    configured = host_config.get("PortBindings") or {}
    exposed = set((config.get("ExposedPorts") or {}).keys()) | set(live) | set(configured)

    ports: list[DockerPortInfo] = []
    seen: set[str] = set()
    for key in sorted(exposed):
        parsed = _parse_port_key(key)
        if parsed is None:
            continue
        container_port, protocol = parsed
        bindings = live.get(key) if live else None
        if bindings is None:
            bindings = configured.get(key)
        published = False
        for binding in bindings or []:
            try:
                host_port = int(str(binding.get("HostPort") or "0"))
            except ValueError:
                continue
            if not 0 < host_port <= 65535:
                continue
            info = DockerPortInfo(
                container_port=container_port,
                protocol=protocol,
                host_ip=_normalize_host_ip(binding.get("HostIp")),
                host_port=host_port,
            )
            if info.key not in seen:
                seen.add(info.key)
                ports.append(info)
                published = True
        if not published:
            info = DockerPortInfo(container_port=container_port, protocol=protocol)
            if info.key not in seen:
                seen.add(info.key)
                ports.append(info)
    return ports


def _labels(raw: Any) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    items = sorted(raw.items())[:MAX_LABELS]
    return {str(k)[:200]: str(v)[:MAX_LABEL_VALUE] for k, v in items}


def _networks(network_settings: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, data in (network_settings.get("Networks") or {}).items():
        if not isinstance(data, dict):
            continue
        result[str(name)] = {
            "network_id": str(data.get("NetworkID") or "")[:12],
            "ip_address": data.get("IPAddress") or "",
            "ipv6_address": data.get("GlobalIPv6Address") or "",
            "gateway": data.get("Gateway") or "",
            "aliases": [str(a) for a in (data.get("Aliases") or [])][:10],
        }
    return result


def normalize_container(attrs: dict[str, Any]) -> DockerContainerInfo:
    config = attrs.get("Config") or {}
    state = attrs.get("State") or {}
    image_ref = str(config.get("Image") or attrs.get("Image") or "")
    image_id = str(attrs.get("Image") or "")
    repo, tag, digest = parse_image_ref(image_ref)
    name = str(attrs.get("Name") or "").lstrip("/") or str(attrs.get("Id", ""))[:12]
    status = state.get("Status") if isinstance(state, dict) else None
    return DockerContainerInfo(
        container_id=str(attrs.get("Id") or ""),
        name=name,
        image=DockerImageInfo(image_id=image_id, repository=repo, tag=tag, digest=digest),
        image_ref=image_ref,
        status=str(status or attrs.get("Status") or "unknown"),
        created_at=parse_docker_time(attrs.get("Created")),
        started_at=parse_docker_time(state.get("StartedAt") if isinstance(state, dict) else None),
        labels=_labels(config.get("Labels")),
        networks=_networks(attrs.get("NetworkSettings") or {}),
        ports=parse_ports(attrs),
    )
