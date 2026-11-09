import os
import socket

import psutil
import pytest

from portregistry.core.types import IssueKind, Protocol, ScanScope, ScanStatus
from portregistry.discovery.process_resolver import ProcessResolver
from portregistry.discovery.providers.psutil_provider import PsutilProvider
from tests.fakes import FakePsutil, PConn, proc_fields, tcp_listen, udp_bound


def make_provider(fake: FakePsutil, **resolver_kwargs) -> PsutilProvider:
    return PsutilProvider(
        ProcessResolver(psutil_module=fake, **resolver_kwargs), psutil_module=fake
    )


def test_complete_scan_resolves_processes():
    fake = FakePsutil(
        [tcp_listen("0.0.0.0", 8080, 100), udp_bound("127.0.0.1", 5353, 200)],
        {100: proc_fields("web"), 200: proc_fields("mdns", create_time=1.5)},
    )
    result = make_provider(fake).scan(ScanScope.build())
    assert result.status is ScanStatus.COMPLETE
    assert result.complete and result.enumerated_pids is None
    assert len(result.sockets) == 2
    web = result.processes[100]
    assert web.name == "web" and web.identity_complete
    assert web.cmdline == ["web", "--serve"] and web.cwd == "/srv"
    assert result.issues == []


def test_access_denied_metadata_is_partial_resolution_not_failure():
    fake = FakePsutil(
        [tcp_listen("0.0.0.0", 445, 4)],
        {4: proc_fields("System", exe=psutil.AccessDenied(4), cmdline=psutil.AccessDenied(4))},
    )
    result = make_provider(fake).scan(ScanScope.build())
    assert result.status is ScanStatus.COMPLETE  # enumeration was complete
    info = result.processes[4]
    assert info.name == "System" and info.exe is None
    assert info.errors["exe"] == IssueKind.ACCESS_DENIED.value
    assert info.identity_complete  # creation time still known
    assert any(i.kind is IssueKind.ACCESS_DENIED and i.pid == 4 for i in result.issues)


def test_process_exiting_during_scan_is_recorded():
    fake = FakePsutil([tcp_listen("0.0.0.0", 9000, 300)], {})  # PID vanished before lookup
    result = make_provider(fake).scan(ScanScope.build())
    assert result.status is ScanStatus.COMPLETE
    info = result.processes[300]
    assert info.exited and not info.identity_complete
    assert any(i.kind is IssueKind.PROCESS_EXITED for i in result.issues)


def test_process_exiting_mid_read_drops_create_time():
    fake = FakePsutil(
        [tcp_listen("0.0.0.0", 9000, 301)],
        {301: proc_fields(name=psutil.NoSuchProcess(301))},
    )
    info = make_provider(fake).scan(ScanScope.build()).processes[301]
    assert info.exited and info.create_time is None


def test_missing_create_time_marks_identity_incomplete():
    fake = FakePsutil(
        [tcp_listen("0.0.0.0", 9100, 400)],
        {400: proc_fields("odd", create_time=psutil.AccessDenied(400))},
    )
    info = make_provider(fake).scan(ScanScope.build()).processes[400]
    assert not info.identity_complete and info.name == "odd"


def test_unknown_owner_reported():
    fake = FakePsutil([tcp_listen("0.0.0.0", 135, None)], {})
    result = make_provider(fake).scan(ScanScope.build())
    assert result.sockets[0].pid is None
    assert any(i.kind is IssueKind.OWNER_UNKNOWN for i in result.issues)


def test_access_denied_socket_table_falls_back_to_partial_scan():
    fake = FakePsutil(
        psutil.AccessDenied(),
        {10: proc_fields("mine"), 11: proc_fields("other")},
        per_process_connections={
            10: [PConn(-1, socket.AF_INET, socket.SOCK_STREAM, ("127.0.0.1", 3000), (), "LISTEN")],
            11: psutil.AccessDenied(11),
        },
    )
    result = make_provider(fake).scan(ScanScope.build())
    assert result.status is ScanStatus.PARTIAL
    assert not result.complete
    assert result.enumerated_pids == frozenset({10})
    assert [(s.port, s.pid) for s in result.sockets] == [(3000, 10)]
    # Absence is authoritative only for fully enumerated PIDs.
    assert result.is_absence_authoritative("tcp", 4000, 10)
    assert not result.is_absence_authoritative("tcp", 4000, 11)
    assert not result.is_absence_authoritative("tcp", 4000, None)


def test_unexpected_failure_is_reported_not_raised():
    fake = FakePsutil(RuntimeError("kaboom"), {})
    result = make_provider(fake).scan(ScanScope.build())
    assert result.status is ScanStatus.FAILED
    assert "kaboom" in (result.error or "")
    assert not result.is_absence_authoritative("tcp", 80, 1)


def test_optional_metadata_can_be_disabled():
    fake = FakePsutil([tcp_listen("0.0.0.0", 8080, 100)], {100: proc_fields("web")})
    result = make_provider(fake, collect_cmdline=False, collect_username=False).scan(
        ScanScope.build()
    )
    info = result.processes[100]
    assert info.cmdline is None and info.username is None


def test_scope_limits_absence_authority():
    fake = FakePsutil([tcp_listen("0.0.0.0", 8080, 100)], {100: proc_fields("web")})
    result = make_provider(fake).scan(ScanScope.build("tcp", 8080))
    assert result.is_absence_authoritative("tcp", 8080, 1)
    assert not result.is_absence_authoritative("tcp", 8081, 1)
    assert not result.is_absence_authoritative("udp", 8080, 1)


# --------------------------------------------------------------------- real sockets


@pytest.fixture
def controlled_sockets():
    """A TCP listener and a bound UDP socket on 127.0.0.1 using OS-assigned free ports."""
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(("127.0.0.1", 0))
    tcp.listen()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    try:
        yield tcp.getsockname()[1], udp.getsockname()[1]
    finally:
        tcp.close()
        udp.close()


def test_real_discovery_finds_controlled_sockets(controlled_sockets):
    tcp_port, udp_port = controlled_sockets
    provider = PsutilProvider(ProcessResolver())
    result = provider.scan(ScanScope.build())
    assert result.error is None
    found = {(s.protocol, s.port): s for s in result.sockets if s.pid == os.getpid()}
    assert (Protocol.TCP, tcp_port) in found
    assert (Protocol.UDP, udp_port) in found
    assert found[(Protocol.TCP, tcp_port)].address == "127.0.0.1"
    me = result.processes[os.getpid()]
    assert me.identity_complete
    assert "python" in (me.name or "").lower()
