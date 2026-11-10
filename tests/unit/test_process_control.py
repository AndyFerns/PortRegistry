"""Process control: decision rules, two-step codes, execution and audit (fake OS)."""

from __future__ import annotations

import time

import pytest

from portregistry.config import ConfigError, parse_config
from portregistry.core.application import ActionNonces
from portregistry.django_app.models import Event, ProcessInstance, Service
from portregistry.services import process_control as pc
from portregistry.services.conflict_store import refresh_conflicts
from portregistry.services.history import EventSpec, alert_for
from portregistry.services.reconcile import apply_native_scan, begin_scan
from tests.conftest import pinfo, raw_tcp, scan_result
from tests.control_fakes import DAEMON_PID, ME, enable_control

pytestmark = pytest.mark.django_db


def observe(machine, sockets, processes):
    result = scan_result(sockets, processes)
    scan = begin_scan(machine, kind="native", trigger="t", provider="fake", scope=result.scope)
    apply_native_scan(machine, scan, result)
    refresh_conflicts(machine)


def record(machine, fake, pid=4242, name="node", port=3000, **kw):
    """Live fake process + its observed DB record owning ``port``."""
    live = fake.add(pid, name, **kw)
    info = pinfo(pid, name, create_time=live.create_time, username=live.username)
    observe(machine, [raw_tcp(port, pid)], [info])
    return ProcessInstance.objects.get(pid=pid)


def events(type_):
    return list(Event.objects.filter(type=type_).order_by("id"))


@pytest.fixture
def on(app):
    return enable_control(app)


# ------------------------------------------------------------------ state


def test_control_is_off_by_default_and_forced_off_on_network(app, tmp_path):
    assert pc.control_state(app.config, elevated=False)["enabled"] is False
    cfg = parse_config(
        {
            "daemon": {"host": "0.0.0.0", "allow_remote": True},
            "control": {"enabled": True},
        },
        app.config.paths,
    )
    state = pc.control_state(cfg, elevated=False)
    assert state["configured"] and not state["enabled"]
    assert "non-loopback" in state["reason"]


def test_config_validates_grace_seconds(app):
    with pytest.raises(ConfigError):
        parse_config({"control": {"grace_seconds": 1}}, app.config.paths)
    with pytest.raises(ConfigError):
        parse_config({"control": {"enabled": "yes"}}, app.config.paths)
    cfg = parse_config({"control": {"enabled": True, "grace_seconds": 5}}, app.config.paths)
    assert cfg.control.enabled and cfg.control.grace_seconds == 5


@pytest.mark.parametrize(
    ("configured", "elevated", "active"),
    [(False, True, False), (True, False, False), (True, True, True)],
)
def test_other_users_needs_setting_and_elevation(app, configured, elevated, active):
    enable_control(app, allow_other_users=configured, elevated=elevated)
    state = pc.control_state(app.config, elevated=elevated)
    assert state["allow_other_users"] is active
    if configured and not active:
        assert "not elevated" in state["other_users_note"]


# ------------------------------------------------------------- assessment


def test_preview_when_disabled_shows_commands_but_cannot_request(app, machine, fake_os):
    proc = record(machine, fake_os)
    data = pc.preview(proc.pk)
    assert data["control_enabled"] is False and data["can_request"] is False
    assert data["allowed"] is True
    assert [c["command"] for c in data["commands"]] == ["kill -TERM 4242", "kill -KILL 4242"]
    assert data["method"] == "graceful" and "SIGTERM" in data["method_label"]
    assert data["impact"]["ports"] == ["tcp 0.0.0.0:3000"]
    assert [p["pid"] for p in data["parent_chain"]] == [899, 1]
    assert all(p["protected"] for p in data["parent_chain"])


def test_request_when_disabled_is_refused_and_audited(app, machine, fake_os):
    proc = record(machine, fake_os)
    with pytest.raises(pc.ControlDisabledError):
        pc.request_stop(proc.pk, actor="cli")
    (event,) = events("process.stop_refused")
    assert event.details["actor"] == "cli" and event.details["stage"] == "request"
    assert event.entity_id == str(proc.pk)


@pytest.mark.parametrize(
    ("setup", "expected"),
    [
        (lambda f: f.add(4242, "node", user="bob", uid=1001), "belongs to another user"),
        (lambda f: f.add(4242, "node", user=None), "could not be read"),
        (lambda f: f.add(4242, "node", user="root", uid=0), "system account"),
        (lambda f: f.add(4242, "node", user="_postgres", uid=216), "system account"),
        (lambda f: f.add(4242, "node", ppid=2), "kernel thread"),
        (lambda f: f.add(4242, "systemd"), "critical system process"),
        (lambda f: f.add(4242, "docker-proxy"), "Docker's port proxy"),
    ],
)
def test_protected_rules(app, machine, fake_os, on, setup, expected):
    live = setup(fake_os)
    observe(
        machine,
        [raw_tcp(3000, 4242)],
        [pinfo(4242, live.name, create_time=live.create_time, username=live.username)],
    )
    proc = ProcessInstance.objects.get(pid=4242)
    data = pc.preview(proc.pk)
    assert not data["allowed"]
    assert any(expected in r for r in data["reasons"]), data["reasons"]
    with pytest.raises(pc.StopRefusedError):
        pc.request_stop(proc.pk)
    assert events("process.stop_refused")


def test_daemon_its_parents_and_client_ancestors_are_protected(app, machine, fake_os, on):
    observe(
        machine,
        [raw_tcp(8765, DAEMON_PID), raw_tcp(3000, 4242)],
        [pinfo(DAEMON_PID, "python", create_time=20.0, username=ME)],
    )
    daemon = ProcessInstance.objects.get(pid=DAEMON_PID)
    data = pc.preview(daemon.pk)
    assert not data["allowed"] and "PortRegistry daemon itself" in data["reasons"][0]
    assert data["commands"] == []  # no kill commands for PortRegistry itself

    proc = record(machine, fake_os, pid=4300, port=3001)
    blocked = pc.preview(proc.pk, client_ancestors=(4300, 77))
    assert any("to make this request" in r for r in blocked["reasons"])
    assert pc.preview(proc.pk)["allowed"]


def test_core_pids_and_windows_services_are_protected(app, machine, fake_os, on):
    fake_os.platform = "windows"
    fake_os.services = frozenset({4242})
    proc = record(machine, fake_os, user="DESKTOP\\alice")
    fake_os.procs[DAEMON_PID] = fake_os.procs[DAEMON_PID].__class__(
        **{**fake_os.procs[DAEMON_PID].__dict__, "username": "DESKTOP\\alice"}
    )
    data = pc.preview(proc.pk)
    assert any("Windows service" in r for r in data["reasons"])
    assert data["commands"] == []
    fake_os.services = frozenset()
    fake_os.add(4242, "svc", user="NT AUTHORITY\\SYSTEM")
    assert any("system account" in r for r in pc.preview(proc.pk)["reasons"])


def test_other_user_allowed_only_when_elevated_and_enabled(app, machine, fake_os):
    proc = record(machine, fake_os, user="bob", uid=1001)
    enable_control(app, allow_other_users=True, elevated=False)
    assert not pc.preview(proc.pk)["allowed"]
    enable_control(app, allow_other_users=True, elevated=True)
    data = pc.preview(proc.pk)
    assert data["allowed"] and any("another user" in w for w in data["warnings"])


def test_identity_mismatch_and_incomplete_identity(app, machine, fake_os, on):
    proc = record(machine, fake_os)
    fake_os.add(4242, "node", create_time=5000.0)  # PID reused by a newer process
    data = pc.preview(proc.pk)
    assert not data["live"] and "different process" in data["reasons"][0]
    ProcessInstance.objects.filter(pk=proc.pk).update(create_time=None, identity_complete=False)
    assert "cannot be verified" in pc.preview(proc.pk)["reasons"][0]


def test_tree_lists_members_children_first_and_one_protected_member_blocks(
    app, machine, fake_os, on
):
    proc = record(machine, fake_os, pid=4242, name="npm")
    fake_os.add(4243, "node", ppid=4242)
    fake_os.add(4244, "esbuild", ppid=4243)
    observe(
        machine,
        [raw_tcp(3000, 4242), raw_tcp(5173, 4243)],
        [pinfo(4242, "npm", username=ME), pinfo(4243, "node", username=ME)],
    )
    data = pc.preview(proc.pk, mode="tree")
    assert data["allowed"] and data["stop_order"] == [4244, 4243, 4242]
    assert data["impact"]["processes"] == 3
    assert sorted(data["impact"]["ports"]) == ["tcp 0.0.0.0:3000", "tcp 0.0.0.0:5173"]
    single = pc.preview(proc.pk, mode="process")
    assert single["stop_order"] == [4242]

    fake_os.add(4245, "helper", ppid=4243, user="bob", uid=1001)
    blocked = pc.preview(proc.pk, mode="tree")
    assert not blocked["allowed"]
    assert any(r.startswith("In the tree:") and "bob" in r for r in blocked["reasons"])


def test_tree_impact_includes_registered_services(app, machine, fake_os, on):
    proc = record(machine, fake_os)
    from portregistry.services import registry, reservations

    svc = registry.create_service(machine, {"name": "shop"})
    reservations.create_reservation(machine, {"port": 3000, "protocol": "tcp", "service": svc.pk})
    Service.objects.create(
        machine=machine,
        name="by-exe",
        expected_executable="/usr/bin/node",
        expected_working_directory="/srv",
    )
    services = pc.preview(proc.pk)["impact"]["services"]
    assert any(s.startswith("shop (reserves") for s in services)
    assert any(s.startswith("by-exe") for s in services)


def test_windows_methods_are_labelled_honestly(app, machine, fake_os, on):
    fake_os.platform = "windows"
    proc = record(machine, fake_os)
    data = pc.preview(proc.pk)
    assert data["method"] == "immediate" and "Immediate stop" in data["method_label"]
    assert not data["graceful"]
    assert data["commands"][0]["command"] == "taskkill /PID 4242"
    fake_os.windows.add(4242)
    assert pc.preview(proc.pk)["method"] == "graceful"
    assert pc.preview(proc.pk, force=True)["method"] == "forced"
    assert "/T /F" in pc.preview(proc.pk, mode="tree")["commands"][1]["command"]


def test_docker_proxy_shows_docker_command(app, machine, fake_os, on):
    from datetime import UTC, datetime

    from portregistry.django_app.models import DockerContainer, DockerPortMapping

    now = datetime.now(UTC)
    ctr = DockerContainer.objects.create(
        machine=machine,
        container_id="abc123def4567890",
        name="shop-db",
        status="running",
        first_seen=now,
        last_seen=now,
    )
    DockerPortMapping.objects.create(
        container=ctr, key="5432/tcp", container_port=5432, protocol="tcp", host_port=5432
    )
    proc = record(machine, fake_os, name="docker-proxy", port=5432)
    data = pc.preview(proc.pk)
    assert not data["allowed"] and data["commands"] == []
    assert data["docker"][0]["command"] == "docker stop shop-db"


# --------------------------------------------------------- two-step flow


def test_full_flow_records_request_and_stop(app, machine, fake_os, on):
    proc = record(machine, fake_os)
    issued = pc.request_stop(proc.pk, actor="tui")
    assert issued["expires_in"] == 30 and issued["code"]
    op = pc.confirm_stop(issued["code"], pid="4242", actor="tui")
    assert op["state"] == "done" and op["outcome"] == "stopped"
    assert op["members"][0]["result"] == "stopped"
    assert fake_os.sent == [(4242, "graceful")] and 4242 in fake_os.closed
    (requested,) = events("process.stop_requested")
    (stopped,) = events("process.stopped")
    assert requested.details["actor"] == "tui"
    assert stopped.details["actor"] == "tui" and stopped.details["method"] == "graceful"
    assert stopped.details["identity"]["cmdline"] == ["node"]
    assert stopped.severity == "warning" and not stopped.noise
    assert pc.get_operation(op["id"])["outcome"] == "stopped"


def test_code_is_single_use(app, machine, fake_os, on):
    proc = record(machine, fake_os)
    fake_os.behaviour[4242] = "ignore"
    code = pc.request_stop(proc.pk)["code"]
    pc.confirm_stop(code, pid=4242)
    with pytest.raises(pc.StopCodeError, match="already-used"):
        pc.confirm_stop(code, pid=4242)
    assert len(events("process.stop_refused")) == 1


def test_code_expires(app, machine, fake_os, on):
    app.control_codes = ActionNonces(ttl_seconds=0.01)
    proc = record(machine, fake_os)
    code = pc.request_stop(proc.pk)["code"]
    time.sleep(0.05)
    with pytest.raises(pc.StopCodeError, match="expired"):
        pc.confirm_stop(code, pid=4242)
    assert fake_os.sent == []
    assert events("process.stop_refused")[0].entity_id == str(proc.pk)


def test_wrong_pid_and_wrong_interface_are_refused(app, machine, fake_os, on):
    proc = record(machine, fake_os)
    code = pc.request_stop(proc.pk, actor="gui")["code"]
    with pytest.raises(pc.StopRefusedError, match="does not match"):
        pc.confirm_stop(code, pid="4243", actor="gui")
    with pytest.raises(pc.StopCodeError):  # consumed by the failed attempt
        pc.confirm_stop(code, pid="4242", actor="gui")
    code = pc.request_stop(proc.pk, actor="gui")["code"]
    with pytest.raises(pc.StopRefusedError, match="issued to the GUI"):
        pc.confirm_stop(code, pid="4242", actor="cli")
    assert fake_os.sent == []
    assert len(events("process.stop_refused")) == 3


def test_tree_change_between_review_and_confirm_is_refused(app, machine, fake_os, on):
    proc = record(machine, fake_os)
    code = pc.request_stop(proc.pk, mode="tree")["code"]
    fake_os.add(4250, "worker", ppid=4242)
    with pytest.raises(pc.StopRefusedError, match="tree changed"):
        pc.confirm_stop(code, pid=4242)
    assert fake_os.sent == []


def test_process_replaced_between_review_and_confirm_is_refused(app, machine, fake_os, on):
    proc = record(machine, fake_os)
    code = pc.request_stop(proc.pk)["code"]
    fake_os.add(4242, "node", create_time=9999.0)
    with pytest.raises(pc.StopRefusedError, match="different process"):
        pc.confirm_stop(code, pid=4242)
    assert fake_os.sent == []


def test_graceful_timeout_is_never_forced(app, machine, fake_os, on):
    proc = record(machine, fake_os)
    fake_os.behaviour[4242] = "ignore"
    op = pc.confirm_stop(pc.request_stop(proc.pk)["code"], pid=4242)
    assert op["outcome"] == "timeout" and op["members"][0]["result"] == "still_running"
    assert fake_os.sent == [(4242, "graceful")]
    assert events("process.stop_timeout")
    forced = pc.confirm_stop(pc.request_stop(proc.pk, force=True)["code"], pid=4242)
    assert forced["outcome"] == "stopped" and fake_os.sent[-1] == (4242, "forced")


def test_tree_stop_sends_children_first(app, machine, fake_os, on):
    proc = record(machine, fake_os)
    fake_os.add(4243, "node", ppid=4242)
    fake_os.add(4244, "esbuild", ppid=4243)
    op = pc.confirm_stop(pc.request_stop(proc.pk, mode="tree")["code"], pid=4242)
    assert [pid for pid, _ in fake_os.sent] == [4244, 4243, 4242]
    assert op["outcome"] == "stopped" and len(op["members"]) == 3


def test_access_denied_is_reported_as_failure(app, machine, fake_os, on):
    proc = record(machine, fake_os)
    fake_os.behaviour[4242] = "deny"
    op = pc.confirm_stop(pc.request_stop(proc.pk)["code"], pid=4242)
    assert op["outcome"] == "failed" and "denied" in op["members"][0]["detail"]
    assert events("process.stop_failed")[0].severity == "error"


def test_code_store_limits_pending_codes():
    store = ActionNonces(ttl_seconds=30, max_pending=2)
    a, b = store.issue("a"), store.issue("b")
    assert a and b and store.issue("c") is None
    assert store.consume(a) == ("ok", "a")
    assert store.consume(a) == ("unknown", None)
    assert store.issue("c") is not None


def test_parse_ancestors_is_bounded_and_ignores_junk():
    assert pc.parse_ancestors("1, 2,x,-3,4") == (1, 2, 4)
    assert len(pc.parse_ancestors(",".join(str(i) for i in range(500)))) == pc.MAX_ANCESTORS
    assert pc.parse_ancestors(None) == ()


def test_alerts_never_carry_command_lines():
    spec = EventSpec(
        "process.stopped",
        "Stopped node",
        severity="warning",
        details={
            "actor": "cli",
            "members": [{"pid": 1}],
            "identity": {"pid": 1, "name": "node", "cmdline": ["node", "--token=s3cret"]},
        },
    )
    alert = alert_for(spec)
    assert alert is not None and alert[0] == "process.stopped"
    assert "cmdline" not in alert[1]["identity"] and "members" not in alert[1]
    assert "s3cret" not in str(alert)
