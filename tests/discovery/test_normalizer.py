import socket

from portregistry.core.types import Family, Protocol, ScanScope, SocketState
from portregistry.discovery.normalizer import normalize_connection, normalize_connections
from tests.fakes import Addr, SConn, tcp_established, tcp_listen, udp_bound


def test_tcp_listener_normalized():
    sock = normalize_connection(tcp_listen("0.0.0.0", 8080, 100))
    assert sock is not None
    assert sock.protocol is Protocol.TCP
    assert sock.family is Family.IPV4
    assert sock.state is SocketState.LISTEN
    assert (sock.address, sock.port, sock.pid) == ("0.0.0.0", 8080, 100)


def test_established_tcp_is_not_an_endpoint():
    assert normalize_connection(tcp_established("10.0.0.2", 51000, 5)) is None


def test_udp_bound_socket_has_bound_state():
    sock = normalize_connection(udp_bound("::", 5353, 9, family=socket.AF_INET6))
    assert sock is not None
    assert sock.protocol is Protocol.UDP
    assert sock.state is SocketState.BOUND
    assert sock.family is Family.IPV6


def test_ipv4_mapped_ipv6_normalized_to_ipv4():
    sock = normalize_connection(tcp_listen("::ffff:127.0.0.1", 9000, 1, family=socket.AF_INET6))
    assert sock is not None
    assert sock.address == "127.0.0.1" and sock.family is Family.IPV4


def test_unbound_and_port_zero_ignored():
    assert (
        normalize_connection(SConn(-1, socket.AF_INET, socket.SOCK_DGRAM, (), (), "NONE", 1))
        is None
    )
    assert normalize_connection(udp_bound("0.0.0.0", 0, 1)) is None


def test_missing_pid_kept_as_unknown_owner():
    sock = normalize_connection(tcp_listen("127.0.0.1", 445, None))
    assert sock is not None and sock.pid is None


def test_garbage_address_skipped():
    conn = SConn(-1, socket.AF_INET, socket.SOCK_STREAM, Addr("bogus", 80), (), "LISTEN", 1)
    assert normalize_connection(conn) is None


def test_scope_filter_and_dedup():
    conns = [
        tcp_listen("0.0.0.0", 80, 1),
        tcp_listen("0.0.0.0", 80, 1),  # duplicate (e.g. SO_REUSEPORT siblings)
        udp_bound("0.0.0.0", 80, 2),
        tcp_listen("127.0.0.1", 443, 3),
    ]
    everything = normalize_connections(conns, ScanScope.build())
    assert len(everything) == 3
    tcp_only = normalize_connections(conns, ScanScope.build("tcp"))
    assert {s.protocol for s in tcp_only} == {Protocol.TCP}
    port_80 = normalize_connections(conns, ScanScope.build(port=80))
    assert {(s.protocol, s.port) for s in port_80} == {(Protocol.TCP, 80), (Protocol.UDP, 80)}


def test_multiple_processes_sharing_a_port_are_distinct():
    conns = [tcp_listen("0.0.0.0", 7000, 10), tcp_listen("0.0.0.0", 7000, 11)]
    assert len(normalize_connections(conns, ScanScope.build())) == 2
