import uuid

import pytest

from portregistry.config import (
    load_config,
    load_or_create_token,
    parse_config,
    read_token,
    write_default_config,
)
from portregistry.core.identity import (
    incomplete_process_key,
    load_or_create_machine_id,
    process_identity_hash,
    process_key,
    socket_key,
)
from portregistry.exceptions import ConfigError
from portregistry.paths import AppPaths


@pytest.fixture
def paths(tmp_path):
    return AppPaths(tmp_path / "config", tmp_path / "data", tmp_path / "logs")


def test_machine_id_is_generated_once(tmp_path):
    path = tmp_path / "machine_id"
    first = load_or_create_machine_id(path)
    second = load_or_create_machine_id(path)
    assert isinstance(first, uuid.UUID)
    assert first == second


def test_process_key_uses_pid_and_create_time():
    assert process_key(42, 1700000000.12345) == "42:1700000000.123"
    # Same PID, different creation time (PID reuse) -> different identity.
    assert process_key(42, 1700000000.1) != process_key(42, 1700000500.1)


def test_incomplete_identity_is_never_reused():
    assert incomplete_process_key(7) != incomplete_process_key(7)
    assert incomplete_process_key(7).startswith("7:incomplete:")


def test_identity_hash_depends_on_machine():
    a = process_identity_hash(uuid.UUID(int=1), 10, 5.0)
    b = process_identity_hash(uuid.UUID(int=2), 10, 5.0)
    assert a != b and len(a) == 32
    assert a == process_identity_hash(uuid.UUID(int=1), 10, 5.0004)  # ms precision


def test_socket_key_format():
    assert socket_key("tcp", "ipv4", "0.0.0.0", 80, "1:2.000") == "tcp|ipv4|0.0.0.0|80|1:2.000"


def test_default_config(paths):
    config = load_config(paths)
    assert config.daemon.host == "127.0.0.1"
    assert config.daemon.port == 8765
    assert config.discovery.native_interval == 10
    assert config.history.retention_days == 30
    assert config.base_url == "http://127.0.0.1:8765"


def test_written_default_config_round_trips(paths):
    assert write_default_config(paths) is True
    assert write_default_config(paths) is False
    config = load_config(paths)
    assert config.discovery.collect_cmdline is True


def test_non_loopback_requires_allow_remote(paths):
    with pytest.raises(ConfigError, match="non-loopback"):
        parse_config({"daemon": {"host": "0.0.0.0"}}, paths)
    config = parse_config({"daemon": {"host": "0.0.0.0", "allow_remote": True}}, paths)
    assert config.daemon.host == "0.0.0.0"
    assert config.base_url == "http://127.0.0.1:8765"


@pytest.mark.parametrize(
    "raw",
    [
        {"daemon": {"port": 0}},
        {"daemon": {"port": 70000}},
        {"daemon": {"port": "8765"}},
        {"daemon": {"host": "not-an-ip"}},
        {"discovery": {"native_interval": 0.5}},
        {"discovery": {"native_interval": True}},
        {"history": {"retention_days": 0}},
        {"logging": {"level": "LOUD"}},
        {"daemon": "oops"},
    ],
)
def test_invalid_config_rejected(paths, raw):
    with pytest.raises(ConfigError):
        parse_config(raw, paths)


def test_env_port_override(paths, monkeypatch):
    monkeypatch.setenv("PORTREGISTRY_PORT", "9999")
    assert parse_config({}, paths).daemon.port == 9999


def test_token_created_once(paths):
    assert read_token(paths) is None
    token = load_or_create_token(paths)
    assert len(token) >= 32
    assert load_or_create_token(paths) == token == read_token(paths)
