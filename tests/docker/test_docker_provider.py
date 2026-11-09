"""Docker discovery with fake clients (deterministic; no Docker required)."""

import threading
import time

import pytest

from portregistry.core.types import Protocol
from portregistry.discovery.docker.events import DockerEventListener
from portregistry.discovery.docker.normalizer import (
    normalize_container,
    parse_docker_time,
    parse_image_ref,
    parse_ports,
)
from portregistry.discovery.docker.provider import DockerProvider, describe_docker_error
from portregistry.django_app.models import DockerContainer, DockerPortMapping, Event
from portregistry.services.docker_state import DockerDiscoveryService

# --------------------------------------------------------------------- fixtures


def container_attrs(
    cid="a" * 64,
    name="/web",
    image="nginx:alpine",
    status="running",
    ports=None,
    exposed=None,
    bindings=None,
):
    return {
        "Id": cid,
        "Name": name,
        "Image": "sha256:" + "b" * 64,
        "Created": "2026-11-01T10:00:00.123456789Z",
        "State": {"Status": status, "StartedAt": "2026-11-01T10:00:01.5Z"},
        "Config": {
            "Image": image,
            "Labels": {"com.docker.compose.project": "demo"},
            "ExposedPorts": exposed if exposed is not None else {"80/tcp": {}, "9000/udp": {}},
        },
        "HostConfig": {"PortBindings": bindings or {}},
        "NetworkSettings": {
            "Ports": ports
            if ports is not None
            else {
                "80/tcp": [
                    {"HostIp": "", "HostPort": "8080"},
                    {"HostIp": "::", "HostPort": "8080"},
                ],
                "9000/udp": None,
            },
            "Networks": {
                "bridge": {
                    "NetworkID": "c" * 64,
                    "IPAddress": "172.17.0.2",
                    "Gateway": "172.17.0.1",
                }
            },
        },
    }


class FakeContainer:
    def __init__(self, attrs):
        self.attrs = attrs


class FakeContainers:
    def __init__(self, state):
        self.state = state

    def list(self, all=False, ignore_removed=False):  # noqa: A002 - mirrors docker SDK
        return [FakeContainer(a) for a in self.state["items"]]


class FakeClient:
    """Reads ``state`` on every call, so tests can change Docker's behaviour later."""

    def __init__(self, items=None, fail=None, state=None):
        self.state = state if state is not None else {"items": items or [], "fail": fail}
        self.containers = FakeContainers(self.state)
        self.closed = False

    def ping(self):
        if self.state.get("fail"):
            raise self.state["fail"]
        return True

    def version(self):
        return {"Version": "27.0.0"}

    def close(self):
        self.closed = True


# ------------------------------------------------------------------- normalizer


def test_parse_image_ref():
    assert parse_image_ref("nginx:alpine") == ("nginx", "alpine", None)
    assert parse_image_ref("nginx") == ("nginx", "latest", None)
    assert parse_image_ref("registry:5000/team/app:1.2") == ("registry:5000/team/app", "1.2", None)
    assert parse_image_ref("redis@sha256:abc") == ("redis", None, "sha256:abc")
    assert parse_image_ref("sha256:" + "f" * 64) == (None, None, None)


def test_parse_docker_time():
    assert parse_docker_time("0001-01-01T00:00:00Z") is None
    ts = parse_docker_time("2026-11-01T10:00:00.123456789Z")
    assert ts is not None and ts.microsecond == 123456 and ts.tzinfo is not None
    assert parse_docker_time("garbage") is None


def test_ports_keep_internal_and_published_distinct():
    ports = parse_ports(container_attrs())
    published = [p for p in ports if p.published]
    internal = [p for p in ports if not p.published]
    assert {(p.host_ip, p.host_port, p.container_port) for p in published} == {
        ("0.0.0.0", 8080, 80),  # empty HostIp means all interfaces
        ("::", 8080, 80),
    }
    assert [(p.container_port, p.protocol) for p in internal] == [(9000, Protocol.UDP)]


def test_stopped_container_uses_configured_bindings():
    attrs = container_attrs(
        status="exited",
        ports={},
        bindings={"5432/tcp": [{"HostIp": "127.0.0.1", "HostPort": "5432"}]},
        exposed={},
    )
    ports = parse_ports(attrs)
    assert [(p.host_ip, p.host_port, p.container_port) for p in ports] == [
        ("127.0.0.1", 5432, 5432)
    ]


def test_normalize_container():
    info = normalize_container(container_attrs())
    assert info.name == "web" and info.status == "running"
    assert info.image.repository == "nginx" and info.image.tag == "alpine"
    assert info.labels == {"com.docker.compose.project": "demo"}
    assert info.networks["bridge"]["ip_address"] == "172.17.0.2"


# --------------------------------------------------------------------- provider


def test_inventory_available():
    provider = DockerProvider(client_factory=lambda: FakeClient([container_attrs()]))
    result = provider.inventory()
    assert result.available and result.server_version == "27.0.0"
    assert [c.name for c in result.containers] == ["web"]


def test_inventory_unavailable_is_reported_not_raised():
    provider = DockerProvider(
        client_factory=lambda: FakeClient(fail=ConnectionError("Connection refused"))
    )
    result = provider.inventory()
    assert not result.available
    assert "not reachable" in result.error


def test_permission_denied_message_mentions_privilege():
    msg = describe_docker_error(PermissionError(13, "Permission denied"))
    assert "root-equivalent" in msg


def test_real_provider_never_raises_on_this_machine():
    """Exercises the real SDK path: unavailable here (no Docker) or available in CI."""
    result = DockerProvider(timeout=3).inventory()
    if not result.available:
        assert result.error


# ----------------------------------------------------------------- persistence


@pytest.mark.django_db
class TestDockerReconciliation:
    def service(self, app, machine, items, fail=None):
        holder = {"items": items, "fail": fail}
        provider = DockerProvider(client_factory=lambda: FakeClient(state=holder))
        app.docker_provider.enabled = True
        app.docker_provider.state = "unknown"
        return DockerDiscoveryService(app, machine, provider), holder

    def test_inventory_lifecycle(self, app, machine):
        svc, holder = self.service(app, machine, [container_attrs()])
        first = svc.reconcile("initial")
        assert first.available and first.baseline and first.containers == 1
        container = DockerContainer.objects.get()
        assert container.present and container.image.repository == "nginx"
        assert DockerPortMapping.objects.filter(container=container, host_port=8080).count() == 2
        assert (
            DockerPortMapping.objects.filter(container=container, host_port__isnull=True).count()
            == 1
        )
        assert app.docker_provider.state == "ok"

        holder["items"] = [container_attrs(status="exited", ports={})]
        svc.reconcile("docker-event:die")
        assert Event.objects.filter(type="container.status_changed").exists()

        holder["items"] = []
        summary = svc.reconcile("scheduled")
        assert summary.disappeared == 1
        container.refresh_from_db()
        assert not container.present and container.removed_at is not None
        assert not DockerPortMapping.objects.filter(active=True).exists()

    def test_unavailable_docker_preserves_last_known_state(self, app, machine):
        svc, holder = self.service(app, machine, [container_attrs()])
        svc.reconcile("initial")
        holder["fail"] = ConnectionError("Connection refused")
        summary = svc.reconcile("scheduled")
        assert not summary.available
        assert DockerContainer.objects.get().present  # not assumed removed
        assert app.docker_provider.state == "unavailable"
        assert Event.objects.filter(type="docker.unavailable").exists()
        holder["fail"] = None
        svc.reconcile("scheduled")
        assert Event.objects.filter(type="docker.available").count() == 2  # initial + recovery

    def test_published_mapping_occupies_reservation(self, app, machine):
        from portregistry.services import reservations

        svc, _ = self.service(app, machine, [container_attrs()])
        svc.reconcile("initial")
        _, conflicts = reservations.create_reservation(machine, {"port": 8080})
        assert conflicts and conflicts[0].evidence["occupants"][0]["kind"] == "docker"


# ---------------------------------------------------------------- event stream


class FakeStream:
    def __init__(self, events, block=False):
        self._events = list(events)
        self._block = block
        self._closed = threading.Event()

    def __iter__(self):
        yield from self._events
        if self._block:
            self._closed.wait(5)

    def close(self):
        self._closed.set()


def test_event_listener_requests_refresh_and_reconnects():
    calls = []
    streams = [
        FakeStream(
            [
                {"Type": "container", "Action": "start"},
                {"Type": "container", "Action": "exec_create: sh"},
            ]
        ),
        ConnectionError("daemon restarted"),
        FakeStream([{"Type": "container", "Action": "die"}], block=True),
    ]

    def factory():
        item = streams.pop(0) if streams else FakeStream([], block=True)
        if isinstance(item, Exception):
            raise item
        return item

    listener = DockerEventListener(factory, calls.append, initial_backoff=0.01, max_backoff=0.05)
    listener.start()
    deadline = time.monotonic() + 5
    while "docker-event:die" not in calls and time.monotonic() < deadline:
        time.sleep(0.02)
    listener.stop()
    assert calls.count("docker-events-connected") >= 2  # full reconcile after each (re)connect
    assert "docker-event:start" in calls and "docker-event:die" in calls
    assert not any("exec" in c for c in calls)  # exec events are ignored
    assert listener.stopped
