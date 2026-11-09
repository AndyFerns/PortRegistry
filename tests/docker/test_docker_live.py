"""Live Docker discovery against a real Docker daemon.

Skipped when Docker is not reachable. Set ``PORTREGISTRY_REQUIRE_DOCKER=1`` (as
the CI ``docker-live`` job does) to turn the skip into a failure.

Only the *test* creates and removes a container; PortRegistry itself only reads
from Docker.
"""

from __future__ import annotations

import os
import socket
import time
import uuid

import pytest

pytestmark = [pytest.mark.docker_live, pytest.mark.django_db]

IMAGE = "nginx:alpine"
LABEL = "portregistry-test"


def _docker_client():
    reason = None
    try:
        import docker

        client = docker.from_env(timeout=10)
        client.ping()
        return client
    except ImportError:
        reason = "Docker SDK not installed (pip install 'portregistry[docker]')"
    except Exception as exc:
        reason = f"Docker daemon not reachable: {exc}"
    if os.environ.get("PORTREGISTRY_REQUIRE_DOCKER") == "1":
        pytest.fail(f"PORTREGISTRY_REQUIRE_DOCKER=1 but {reason}")
    pytest.skip(reason)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def docker_client():
    client = _docker_client()
    yield client
    for container in client.containers.list(all=True, filters={"label": LABEL}):
        try:
            container.remove(force=True)
        except Exception:
            pass
    client.close()


@pytest.fixture
def running_container(docker_client):
    try:
        docker_client.images.get(IMAGE)
    except Exception:
        docker_client.images.pull(IMAGE)
    host_port = _free_port()
    name = f"portregistry-test-{uuid.uuid4().hex[:8]}"
    container = docker_client.containers.run(
        IMAGE,
        name=name,
        detach=True,
        labels={LABEL: "1"},
        ports={"80/tcp": ("127.0.0.1", host_port)},
    )
    yield container, host_port
    try:
        container.remove(force=True)
    except Exception:
        pass


def test_live_inventory_finds_container_and_mapping(running_container):
    from portregistry.discovery.docker.provider import DockerProvider

    container, host_port = running_container
    result = DockerProvider(timeout=10).inventory()
    assert result.available, result.error
    found = {c.container_id: c for c in result.containers}
    info = found[container.id]
    assert info.status == "running"
    assert info.image.repository == "nginx"
    published = [(p.host_ip, p.host_port, p.container_port) for p in info.ports if p.published]
    assert ("127.0.0.1", host_port, 80) in published


def test_live_events_and_reconciliation(app, machine, docker_client, running_container):
    from portregistry.discovery.docker.provider import DockerProvider
    from portregistry.django_app.models import DockerContainer
    from portregistry.services.docker_state import DockerDiscoveryService

    container, host_port = running_container
    provider = DockerProvider(timeout=10)
    app.docker_provider.enabled = True
    service = DockerDiscoveryService(app, machine, provider)
    assert service.reconcile("initial").available
    row = DockerContainer.objects.get(container_id=container.id)
    assert row.present and row.port_mappings.filter(host_port=host_port).exists()

    refreshes: list[str] = []
    service.start_listener(refreshes.append)
    try:
        deadline = time.monotonic() + 15
        while "docker-events-connected" not in refreshes and time.monotonic() < deadline:
            time.sleep(0.1)
        container.remove(force=True)
        deadline = time.monotonic() + 30
        while (
            not any(r.startswith("docker-event:") for r in refreshes)
            and time.monotonic() < deadline
        ):
            time.sleep(0.2)
        assert any(r.startswith("docker-event:") for r in refreshes), refreshes
    finally:
        service.stop()

    summary = service.reconcile("docker-event:destroy")
    assert summary.available
    row.refresh_from_db()
    assert not row.present and row.removed_at is not None
