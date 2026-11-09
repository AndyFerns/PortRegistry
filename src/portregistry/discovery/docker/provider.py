"""Read-only Docker inventory via the Docker SDK for Python.

Only read operations are used (ping, version, container list/inspect, events).
PortRegistry never executes commands in containers, never changes container
lifecycle, and never exposes the Docker socket through its own API.

Note: access to the Docker socket is highly privileged (root-equivalent on
Linux) even though PortRegistry only reads from it.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import Any

from portregistry.core.types import DockerContainerInfo, DockerInventoryResult
from portregistry.discovery.docker.normalizer import normalize_container

logger = logging.getLogger(__name__)

SDK_MISSING = (
    'Docker SDK for Python is not installed. Install it with: pip install "portregistry[docker]"'
)


def docker_sdk_available() -> bool:
    try:
        import docker  # noqa: F401
    except ImportError:
        return False
    return True


def describe_docker_error(exc: BaseException) -> str:
    text = str(exc) or exc.__class__.__name__
    lowered = text.lower()
    if isinstance(exc, PermissionError) or "permission denied" in lowered:
        return (
            "Permission denied accessing the Docker socket. Granting access (e.g. the 'docker' "
            "group) is root-equivalent; PortRegistry only performs read operations."
        )
    if (
        "filenotfounderror" in lowered
        or "no such file" in lowered
        or "connection refused" in lowered
        or "connection aborted" in lowered
        or "error while fetching server api version" in lowered
        or "pipe" in lowered
    ):
        return "Docker daemon is not reachable (is Docker installed and running?)."
    return f"Docker error: {text[:300]}"


class DockerProvider:
    name = "docker"

    def __init__(
        self,
        client_factory: Callable[[], Any] | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._client_factory = client_factory
        self._timeout = timeout
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            if self._client_factory is not None:
                self._client = self._client_factory()
            else:
                import docker

                self._client = docker.from_env(timeout=int(self._timeout))
        return self._client

    def close(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            try:
                client.close()
            except Exception:  # pragma: no cover - best effort
                pass

    def inventory(self) -> DockerInventoryResult:
        started = datetime.now(UTC)
        if self._client_factory is None and not docker_sdk_available():
            return DockerInventoryResult(
                started_at=started,
                finished_at=datetime.now(UTC),
                available=False,
                error=SDK_MISSING,
            )
        try:
            client = self._get_client()
            client.ping()
            version = None
            try:
                version = (client.version() or {}).get("Version")
            except Exception:
                version = None
            containers: list[DockerContainerInfo] = []
            for container in client.containers.list(all=True, ignore_removed=True):
                try:
                    attrs = container.attrs
                    if attrs:
                        containers.append(normalize_container(attrs))
                except Exception as exc:  # container removed mid-listing etc.
                    logger.debug("Skipping container during inventory: %s", exc)
            return DockerInventoryResult(
                started_at=started,
                finished_at=datetime.now(UTC),
                available=True,
                containers=containers,
                server_version=version,
            )
        except Exception as exc:
            # Reset the client so the next attempt reconnects from scratch.
            self.close()
            return DockerInventoryResult(
                started_at=started,
                finished_at=datetime.now(UTC),
                available=False,
                error=describe_docker_error(exc),
            )

    def event_stream(self) -> Any:
        """Blocking iterator of container events. Has ``close()`` to unblock it.

        A dedicated client is used so the long-lived stream never shares a
        connection with inventory requests made from the scheduler thread.
        """
        if self._client_factory is not None:
            client = self._client_factory()
        else:
            import docker

            client = docker.from_env(timeout=int(self._timeout))
        return client.events(decode=True, filters={"type": "container"})


def iter_events(stream: Any) -> Iterator[dict[str, Any]]:
    for event in stream:
        if isinstance(event, dict):
            yield event
