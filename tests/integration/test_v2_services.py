"""Integration tests for v0.2 services against the database."""

from __future__ import annotations

import socket
from datetime import timedelta

import pytest
from django.utils import timezone

from portregistry.django_app.models import Conflict, Event, PortReservation, Service, Socket
from portregistry.exceptions import ValidationError
from portregistry.services import (
    adopt,
    diagnostics,
    free_ports,
    ignore_rules,
    manifest,
    preferences,
    registry,
    reservations,
    timeline,
)
from portregistry.services.conflict_store import refresh_conflicts
from portregistry.services.history import cleanup, query_events
from portregistry.services.reconcile import apply_native_scan, begin_scan
from tests.conftest import pinfo, raw_tcp, raw_udp, scan_result

pytestmark = pytest.mark.django_db


def observe(machine, sockets, processes):
    result = scan_result(sockets, processes)
    scan = begin_scan(machine, kind="native", trigger="test", provider="fake", scope=result.scope)
    summary = apply_native_scan(machine, scan, result)
    refresh_conflicts(machine)
    return summary


def unregistered(machine):
    return set(
        Conflict.objects.filter(
            machine=machine, active=True, type="unregistered_listener"
        ).values_list("port", flat=True)
    )


# ------------------------------------------------------------------ noise


class TestNoise:
    def test_ephemeral_udp_not_flagged_and_history_quiet(self, app, machine):
        observe(machine, [raw_tcp(8080, 1)], [pinfo(1, "web")])  # baseline
        observe(
            machine,
            [raw_tcp(8080, 1), raw_udp(60001, 2), raw_udp(5353, 2)],
            [pinfo(1, "web"), pinfo(2, "chrome")],
        )
        assert unregistered(machine) == {8080, 5353}
        ev = Event.objects.get(type="endpoint.appeared", details__port=60001)
        assert ev.noise
        assert not Event.objects.get(type="endpoint.appeared", details__port=5353).noise
        visible = list(query_events(type_prefix="endpoint").values_list("details__port", flat=True))
        assert 60001 not in visible and 5353 in visible

    def test_flapping_endpoint_marked_noise_retroactively(self, app, machine):
        observe(machine, [], [])
        observe(machine, [raw_tcp(7000, 3)], [pinfo(3, "short")])
        appeared = Event.objects.get(type="endpoint.appeared")
        assert not appeared.noise
        observe(machine, [], [])  # gone within the flap window
        appeared.refresh_from_db()
        assert appeared.noise
        assert Event.objects.get(type="endpoint.disappeared").noise
        assert Event.objects.get(type="process.disappeared").noise
        assert Event.objects.get(type="process.appeared").noise

    def test_long_lived_endpoint_not_flap(self, app, machine):
        observe(machine, [], [])
        observe(machine, [raw_tcp(7000, 3)], [pinfo(3, "svc")])
        Event.objects.filter(type="endpoint.appeared").update(
            timestamp=timezone.now() - timedelta(hours=1)
        )
        Event.objects.filter(type="process.appeared").update(
            timestamp=timezone.now() - timedelta(hours=1)
        )
        observe(machine, [], [])
        assert not Event.objects.get(type="endpoint.disappeared").noise

    def test_ignore_rule_suppresses_unregistered_but_not_reservations(self, app, machine):
        observe(machine, [raw_tcp(8080, 1), raw_tcp(9000, 1)], [pinfo(1, "node")])
        rule = ignore_rules.create_rule(machine, {"name": "node dev", "process_name": "node"})
        assert unregistered(machine) == set()
        _, conflicts = reservations.create_reservation(machine, {"port": 8080})
        assert [c.type for c in conflicts] == ["occupied_reservation"]  # intent is never hidden
        ignore_rules.update_rule(rule, {"enabled": False})
        assert unregistered(machine) == {9000}
        ignore_rules.delete_rule(rule)
        assert Event.objects.filter(type="ignore.deleted").exists()

    def test_mark_known(self, app, machine):
        observe(machine, [raw_tcp(8080, 1), raw_tcp(9000, 1)], [pinfo(1, "node")])
        sock = Socket.objects.get(port=8080)
        rule = ignore_rules.mark_socket_known(sock)
        assert (rule.process_name, rule.protocol, rule.port_min, rule.port_max) == (
            "node",
            "tcp",
            8080,
            8080,
        )
        assert unregistered(machine) == {9000}
        ignore_rules.mark_process_known(sock.process)
        assert unregistered(machine) == set()

    @pytest.mark.parametrize(
        ("data", "field"),
        [
            ({"name": "x"}, "non_field_errors"),
            ({"name": "x", "protocol": "icmp"}, "protocol"),
            ({"name": "x", "port_min": 10, "port_max": 5}, "port_max"),
            ({"name": "x", "address": "localhost"}, "address"),
            ({"name": "", "protocol": "tcp"}, "name"),
            ({"name": "x", "protocol": "tcp", "enabled": "maybe"}, "enabled"),
        ],
    )
    def test_rule_validation(self, app, machine, data, field):
        with pytest.raises(ValidationError) as exc:
            ignore_rules.create_rule(machine, data)
        assert field in exc.value.field_errors

    def test_noise_retention(self, app, machine):
        observe(machine, [], [])
        observe(machine, [raw_udp(60002, 2)], [pinfo(2, "chrome")])
        Event.objects.filter(noise=True).update(timestamp=timezone.now() - timedelta(days=5))
        counts = cleanup(30, noise_retention_days=3)
        assert counts["noise_events"] >= 1
        assert not Event.objects.filter(noise=True).exists()


# ------------------------------------------------------------- projects


def test_project_fields_persisted(app, machine):
    info = pinfo(5, "python")
    info.project_name, info.project_root = "myapp", "/src/myapp"
    observe(machine, [raw_tcp(8000, 5)], [info])
    proc = Socket.objects.get(port=8000).process
    assert (proc.project_name, proc.project_root) == ("myapp", "/src/myapp")


# ---------------------------------------------------------------- adopt


class TestAdopt:
    def test_propose_and_apply_from_process(self, app, machine):
        info = pinfo(5, "python.exe", exe=r"C:\Py\python.exe", cwd=r"C:\src\shop")
        info.project_name = "shop"
        observe(machine, [raw_tcp(8000, 5), raw_udp(9999, 5)], [info])
        sock = Socket.objects.get(port=8000)
        proposal = adopt.propose(socket_id=sock.pk)
        svc = proposal["service"]
        assert svc["name"] == "shop" and svc["expected_executable"] == "python.exe"
        assert svc["expected_working_directory"] == r"C:\src\shop" and svc["category"] == "dev-tool"
        assert {e["port"] for e in proposal["endpoints"]} == {8000, 9999}
        result = adopt.apply(
            machine,
            {
                "service": svc,
                "socket_ids": [e["socket_id"] for e in proposal["endpoints"] if e["selected"]],
            },
        )
        assert result["service"].name == "shop"
        assert sorted(r.port for r in result["reservations"]) == [8000, 9999]
        # The adopted service matches its own process: no mismatch/occupied conflicts.
        assert not Conflict.objects.filter(
            active=True, type__in=["service_mismatch", "occupied_reservation"]
        ).exists()
        # Name suggestions stay unique.
        assert adopt.propose(socket_id=sock.pk)["service"]["name"] == "shop-2"

    def test_apply_is_all_or_nothing(self, app, machine):
        observe(machine, [raw_tcp(8000, 5)], [pinfo(5, "x")])
        with pytest.raises(ValidationError):
            adopt.apply(machine, {"service": {"name": "a"}, "socket_ids": [999999]})
        assert not Service.objects.exists()
        with pytest.raises(ValidationError):
            adopt.apply(machine, {"service": {"name": ""}, "socket_ids": []})

    def test_propose_requires_target(self, app, machine):
        with pytest.raises(ValidationError):
            adopt.propose()


# ----------------------------------------------------------- free ports


class TestFreePorts:
    def test_excludes_observed_reserved_and_bound(self, app, machine):
        held = socket.socket()
        held.bind(("127.0.0.1", 0))
        held.listen()
        held_port = held.getsockname()[1]
        try:
            start = 20000
            observe(machine, [raw_tcp(start, 1)], [pinfo(1, "a")])
            reservations.create_reservation(machine, {"port": start + 1})
            query = free_ports.parse_query({"range": f"{start}-{start + 50}", "count": 3})
            found = [p["port"] for p in free_ports.find_free_ports(machine, query)["ports"]]
            assert start not in found and start + 1 not in found and len(found) == 3
            # A socket discovery never saw is still caught by the bind test.
            q2 = free_ports.parse_query(
                {
                    "range": f"{held_port}-{held_port}",
                    "address": "127.0.0.1",
                    "count": 1,
                    "include_ephemeral": "1",
                }
            )
            result = free_ports.find_free_ports(machine, q2)
            assert result["ports"] == [] and result["skipped"]["bind_failed"] == 1
            q3 = free_ports.parse_query(
                {
                    "range": f"{held_port}-{held_port}",
                    "address": "127.0.0.1",
                    "count": 1,
                    "include_ephemeral": "1",
                    "verify": "0",
                }
            )
            assert [p["port"] for p in free_ports.find_free_ports(machine, q3)["ports"]] == [
                held_port
            ]
        finally:
            held.close()

    def test_udp_independent_of_tcp(self, app, machine):
        observe(machine, [raw_tcp(21000, 1)], [pinfo(1, "a")])
        q = free_ports.parse_query(
            {"range": "21000-21000", "protocol": "udp", "count": 1, "verify": "0"}
        )
        assert [p["port"] for p in free_ports.find_free_ports(machine, q)["ports"]] == [21000]

    @pytest.mark.parametrize(
        "params",
        [
            {"range": "5000-4000"},
            {"count": 0},
            {"protocol": "icmp"},
            {"address": "nope"},
            {"range": "0-10"},
        ],
    )
    def test_query_validation(self, app, machine, params):
        with pytest.raises(ValidationError):
            free_ports.parse_query(params)

    def test_privileged_and_ephemeral_skipped_by_default(self, app, machine):
        q = free_ports.parse_query(
            {"range": "1000-1030", "count": 1, "verify": "0", "include_privileged": "0"}
        )
        assert free_ports.find_free_ports(machine, q)["ports"][0]["port"] == 1024


# -------------------------------------------------------------- timeline


def test_timeline_reconstructs_owner_intervals(app, machine):
    observe(machine, [raw_tcp(8080, 1)], [pinfo(1, "old", create_time=1.0)])  # baseline owner
    observe(machine, [raw_tcp(8080, 2)], [pinfo(2, "new", create_time=2.0)])  # owner change
    observe(machine, [], [])  # closed
    observe(machine, [raw_tcp(8080, 2)], [pinfo(2, "new", create_time=2.0)])  # reopened
    reservations.create_reservation(machine, {"port": 8080})
    data = timeline.build_timeline(machine, 8080, "tcp", 7)
    owners = {lane["owner"]: lane for lane in data["lanes"]}
    assert set(owners) == {"old (pid 1)", "new (pid 2)"}
    assert len(owners["new (pid 2)"]["intervals"]) == 2
    assert owners["new (pid 2)"]["intervals"][-1]["ongoing"] is True
    assert owners["old (pid 1)"]["intervals"][0]["ongoing"] is False
    assert data["reservations"][0]["ongoing"] and data["label"] == "HTTP (alt) / proxy"
    laid = timeline.layout(data)
    assert all(0 <= i["x"] <= 100 for lane in laid["lanes"] for i in lane["intervals"])
    assert len(laid["ticks"]) == 8
    with pytest.raises(ValidationError):
        timeline.parse_params({"port": "", "days": "500"})


# --------------------------------------------------------------- manifest


DOC = {
    "version": 1,
    "service": [
        {
            "name": "web",
            "expected_executable": "node",
            "port": [{"port": 3000}, {"port": 3001, "protocol": "udp"}],
        },
        {"name": "db", "port": [{"port": 5432, "address": "127.0.0.1"}]},
    ],
    "reservation": [{"port": 6379, "description": "shared redis"}],
}


class TestManifest:
    def test_dry_run_apply_idempotent_and_prune(self, app, machine):
        plan = manifest.apply_manifest(machine, DOC, "/repo/portregistry.toml", dry_run=True)
        assert plan["services"]["create"] == ["web", "db"] and not plan["applied"]
        assert not Service.objects.exists()
        applied = manifest.apply_manifest(machine, DOC, "/repo/portregistry.toml")
        assert applied["applied"] and applied["changes"] == 6
        assert PortReservation.objects.filter(status="active").count() == 4
        assert set(Service.objects.values_list("managed_source", flat=True)) == {
            "/repo/portregistry.toml"
        }
        again = manifest.apply_manifest(machine, DOC, "/repo/portregistry.toml")
        assert again["changes"] == 0 and not again["applied"]
        smaller = {"version": 1, "service": [DOC["service"][0]]}
        pruned = manifest.apply_manifest(machine, smaller, "/repo/portregistry.toml", prune=True)
        assert pruned["services"]["prune"] == ["db"]
        assert set(pruned["reservations"]["release"]) == {"tcp 127.0.0.1:5432", "tcp *:6379"}
        assert not Service.objects.filter(name="db").exists()
        assert Event.objects.filter(type="manifest.applied").count() == 2

    def test_prune_never_touches_other_sources(self, app, machine):
        registry.create_service(machine, {"name": "manual"})
        reservations.create_reservation(machine, {"port": 9999})
        manifest.apply_manifest(machine, {"version": 1}, "/a.toml", prune=True)
        assert Service.objects.filter(name="manual").exists()
        assert PortReservation.objects.filter(port=9999, status="active").exists()

    def test_updates_and_reactivates(self, app, machine):
        manifest.apply_manifest(machine, DOC, "/r.toml")
        res = PortReservation.objects.get(port=3000)
        reservations.release_reservation(res)
        changed = {
            **DOC,
            "service": [{**DOC["service"][0], "description": "Front"}, DOC["service"][1]],
        }
        result = manifest.apply_manifest(machine, changed, "/r.toml")
        assert result["services"]["update"] == [{"name": "web", "fields": ["description"]}]
        res.refresh_from_db()
        assert res.status == "active" and res.released_at is None

    @pytest.mark.parametrize(
        "doc",
        [
            {"version": 2},
            {"bogus": 1},
            {"service": [{"name": "a"}, {"name": "A"}]},
            {"service": [{"name": "a", "port": [{"port": 0}]}]},
            {"service": [{"expected_executable": "x"}]},
            {"service": [{"name": "a", "wat": 1}]},
            {"service": "nope"},
        ],
    )
    def test_validation_writes_nothing(self, app, machine, doc):
        with pytest.raises(ValidationError):
            manifest.apply_manifest(machine, doc, "/x.toml")
        assert not Service.objects.exists() and not PortReservation.objects.exists()

    def test_export_round_trip(self, app, machine):
        manifest.apply_manifest(machine, DOC, "/r.toml")
        exported = manifest.export_registry(machine)
        assert {s["name"] for s in exported["service"]} == {"web", "db"}
        Service.objects.all().delete()
        PortReservation.objects.all().delete()
        manifest.apply_manifest(machine, exported, "/restore.toml")
        assert Service.objects.count() == 2 and PortReservation.objects.count() == 4
        only = manifest.export_registry(machine, service="db")
        assert [s["name"] for s in only["service"]] == ["db"] and "reservation" not in only


# ----------------------------------------------------- preferences & doctor


def test_saved_filters_whitelist(app, machine):
    saved = preferences.create_filter(
        machine, {"name": "web", "page": "ports", "querystring": "?q=node&protocol=tcp&evil=1"}
    )
    assert saved.querystring == "q=node&protocol=tcp"
    assert preferences.get_filter(machine, "WEB", "ports") == saved
    again = preferences.create_filter(
        machine, {"name": "web", "page": "ports", "querystring": "q=x"}
    )
    assert again.pk == saved.pk and again.querystring == "q=x"
    with pytest.raises(ValidationError):
        preferences.create_filter(machine, {"name": "x", "page": "ports", "querystring": "evil=1"})
    with pytest.raises(ValidationError):
        preferences.create_filter(machine, {"name": "x", "page": "admin", "querystring": "q=1"})


def test_onboarding_progress(app, machine):
    observe(machine, [raw_tcp(8080, 1)], [pinfo(1, "node")])
    state = preferences.onboarding_state(machine, autostart_installed=False)
    steps = {s["key"]: s for s in state["steps"]}
    assert steps["scan"]["done"] and not steps["service"]["done"]
    assert steps["service"]["link"].startswith("/adopt/?socket=")
    assert not state["complete"]
    registry.create_service(machine, {"name": "x"})
    reservations.create_reservation(machine, {"port": 1234})
    assert preferences.onboarding_state(machine)["complete"]
    preferences.set_setting("onboarding_dismissed", True)
    assert preferences.onboarding_state(machine)["dismissed"]


def test_diagnostics(app, machine):
    observe(machine, [raw_tcp(8080, 1)], [pinfo(1, "node")])
    report = diagnostics.run_diagnostics(machine)
    by_name = {c["name"]: c for c in report["checks"]}
    assert by_name["database.integrity"]["status"] == "ok"
    assert by_name["discovery.native"]["status"] == "ok"
    assert "never elevates" in report["elevation_hint"]


# ----------------------------------------------------------------- alerts


def test_conflicts_publish_alert_events(app, machine, django_capture_on_commit_callbacks):
    seen = []
    app.bus.add_listener(lambda e: seen.append((e.topic, e.type, e.data.get("severity"))))
    with django_capture_on_commit_callbacks(execute=True):
        observe(machine, [raw_tcp(8080, 1)], [pinfo(1, "node")])
        reservations.create_reservation(machine, {"port": 8080})
    assert ("alerts", "conflict.detected", "warning") in seen
    seen.clear()
    with django_capture_on_commit_callbacks(execute=True):
        observe(machine, [], [])
    assert ("alerts", "conflict.resolved", "warning") in seen
