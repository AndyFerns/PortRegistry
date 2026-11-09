import pytest

from portregistry.core.addresses import (
    ANY_ADDRESS,
    Overlap,
    address_overlap,
    endpoint_overlap,
    format_endpoint,
    is_loopback,
    is_wildcard,
    normalize_address,
    normalize_bind_address,
)
from portregistry.core.types import Family


@pytest.mark.parametrize(
    ("raw", "expected", "family"),
    [
        ("127.0.0.1", "127.0.0.1", Family.IPV4),
        ("0.0.0.0", "0.0.0.0", Family.IPV4),
        ("::", "::", Family.IPV6),
        ("[::1]", "::1", Family.IPV6),
        ("::ffff:127.0.0.1", "127.0.0.1", Family.IPV4),
        ("0:0:0:0:0:0:0:1", "::1", Family.IPV6),
        ("fe80::1%eth0", "fe80::1%eth0", Family.IPV6),
    ],
)
def test_normalize_address(raw, expected, family):
    assert normalize_address(raw) == (expected, family)


@pytest.mark.parametrize("bad", ["", "localhost", "999.1.1.1", "abc", "1.2.3"])
def test_normalize_address_rejects_non_ip(bad):
    with pytest.raises(ValueError):
        normalize_address(bad)


def test_normalize_bind_address_any():
    assert normalize_bind_address(None) == ANY_ADDRESS
    assert normalize_bind_address("") == ANY_ADDRESS
    assert normalize_bind_address(" * ") == ANY_ADDRESS
    assert normalize_bind_address("any") == ANY_ADDRESS
    assert normalize_bind_address("::FFFF:10.0.0.1") == "10.0.0.1"


def test_wildcard_and_loopback_helpers():
    assert is_wildcard("0.0.0.0") and is_wildcard("::") and is_wildcard("*")
    assert not is_wildcard("127.0.0.1")
    assert is_loopback("127.0.0.1") and is_loopback("::1")
    assert not is_loopback("0.0.0.0") and not is_loopback("*")


@pytest.mark.parametrize(
    ("a", "b", "level"),
    [
        ("127.0.0.1", "127.0.0.1", Overlap.DEFINITE),
        ("0.0.0.0", "127.0.0.1", Overlap.DEFINITE),  # PRD: IPv4 wildcard overlaps specific IPv4
        ("127.0.0.1", "0.0.0.0", Overlap.DEFINITE),
        ("::", "::1", Overlap.DEFINITE),
        ("*", "10.1.2.3", Overlap.DEFINITE),
        ("*", "::1", Overlap.DEFINITE),
        ("127.0.0.1", "192.168.1.5", Overlap.NONE),
        ("::1", "127.0.0.1", Overlap.NONE),
        ("::", "0.0.0.0", Overlap.POTENTIAL),  # dual-stack depends on IPV6_V6ONLY
        ("::", "127.0.0.1", Overlap.POTENTIAL),
        ("0.0.0.0", "::1", Overlap.NONE),
        ("::ffff:127.0.0.1", "127.0.0.1", Overlap.DEFINITE),  # mapped address normalized
        ("fe80::1%eth0", "fe80::1%eth1", Overlap.DEFINITE),  # zone ignored for comparison
    ],
)
def test_address_overlap_matrix(a, b, level):
    result = address_overlap(a, b)
    assert result.level is level
    assert result.reason


def test_endpoint_overlap_tcp_udp_independent():
    result = endpoint_overlap("tcp", "0.0.0.0", 53, "udp", "0.0.0.0", 53)
    assert result.level is Overlap.NONE
    assert "TCP and UDP" in result.reason


def test_endpoint_overlap_different_ports():
    assert endpoint_overlap("tcp", "*", 80, "tcp", "*", 81).level is Overlap.NONE


def test_format_endpoint():
    assert format_endpoint("tcp", "0.0.0.0", 80) == "tcp 0.0.0.0:80"
    assert format_endpoint("udp", "::1", 53) == "udp [::1]:53"
    assert format_endpoint("tcp", "*", 5432) == "tcp *:5432"
