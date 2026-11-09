"""API tests for v0.2 endpoints."""

from __future__ import annotations

import json

import pytest
from django.test import Client

from portregistry.config import read_token
from portregistry.django_app.models import Socket
from portregistry.services.conflict_store import refresh_conflicts
from portregistry.services.reconcile import apply_native_scan, begin_scan
from tests.conftest import TEST_TOKEN, pinfo, raw_tcp, raw_udp, scan_result

pytestmark = pytest.mark.django_db


class Api:
    def __init__(self, token=TEST_TOKEN):
        self.client = Client()
        self.auth = {"HTTP_AUTHORIZATION": f"Bearer {token}"}

    def get(self, path, **params):
        return self.client.get(f"/api/v1/{path}", params, **self.auth)

    def post(self, path, body=None):
        return self.client.post(
            f"/api/v1/{path}", json.dumps(body or {}), content_type="application/json", **self.auth
        )

    def patch(self, path, body):
        return self.client.patch(
            f"/api/v1/{path}", json.dumps(body), content_type="application/json", **self.auth
        )

    def delete(self, path):
        return self.client.delete(f"/api/v1/{path}", **self.auth)


@pytest.fixture
def api(app, machine):
    return Api()


def observe(machine, sockets, processes):
    result = scan_result(sockets, processes)
    scan = begin_scan(machine, kind="native", trigger="t", provider="fake", scope=result.scope)
    apply_native_scan(machine, scan, result)
    refresh_conflicts(machine)


def test_ports_include_label_project_and_ignored(api, machine):
    info = pinfo(1, "postgres")
    info.project_name = "db"
    observe(machine, [raw_tcp(5432, 1), raw_udp(60010, 1)], [info])
    rows = {p["port"]: p for p in api.get("ports/").json()["results"]}
    assert rows[5432]["label"] == "PostgreSQL" and rows[5432]["process"]["project"] == "db"
    assert rows[5432]["ignored"] is None and rows[60010]["ignored"] == "ephemeral UDP port"


def test_ignore_rules_and_known(api, machine):
    observe(machine, [raw_tcp(8080, 1)], [pinfo(1, "node")])
    sock = Socket.objects.get(port=8080)
    created = api.post(f"ports/{sock.pk}/known/")
    assert created.status_code == 201 and created.json()["port_min"] == 8080
    rid = created.json()["id"]
    assert api.get("conflicts/", type="unregistered_listener").json()["count"] == 0
    assert api.get("ports/").json()["results"][0]["ignored"].startswith("known:")
    assert api.patch(f"ignore-rules/{rid}/", {"enabled": False}).json()["enabled"] is False
    assert api.get("conflicts/", type="unregistered_listener").json()["count"] == 1
    assert api.get("ignore-rules/").json()["count"] == 1
    assert api.delete(f"ignore-rules/{rid}/").status_code == 200
    bad = api.post("ignore-rules/", {"name": "x"})
    assert bad.status_code == 400 and "non_field_errors" in bad.json()["error"]["details"]["fields"]
    assert api.post(f"processes/{sock.process_id}/known/").status_code == 201


def test_history_hides_noise_and_reports_count(api, machine):
    observe(machine, [], [])
    observe(machine, [raw_udp(60011, 2), raw_tcp(9000, 2)], [pinfo(2, "chrome")])
    data = api.get("history/", type="endpoint").json()
    assert [e["details"]["port"] for e in data["results"]] == [9000]
    assert data["hidden_noise"] == 1
    everything = api.get("history/", type="endpoint", noise="1").json()
    assert {e["details"]["port"] for e in everything["results"]} == {9000, 60011}
    assert "hidden_noise" not in everything


def test_adopt_flow(api, machine):
    observe(machine, [raw_tcp(3000, 7)], [pinfo(7, "node")])
    sock = Socket.objects.get(port=3000)
    proposal = api.get("services/adopt/", socket=sock.pk).json()
    assert proposal["service"]["expected_executable"] and proposal["endpoints"][0]["selected"]
    created = api.post("services/adopt/", {"service": proposal["service"], "socket_ids": [sock.pk]})
    assert created.status_code == 201
    assert created.json()["reservations"][0]["port"] == 3000
    assert api.get("services/adopt/").status_code == 400
    assert api.get("services/adopt/", socket=999999).status_code == 404


def test_free_ports_and_timeline(api, machine):
    observe(machine, [raw_tcp(23000, 1)], [pinfo(1, "a")])
    free = api.get("ports/free/", range="23000-23010", count=2, verify="0").json()
    assert [p["port"] for p in free["ports"]] == [23001, 23002] and free["advisory"]
    assert api.get("ports/free/", range="9-1").status_code == 400
    tl = api.get("ports/timeline/", port=23000, protocol="tcp").json()
    assert tl["lanes"][0]["owner"] == "a (pid 1)"
    assert api.get("ports/timeline/").status_code == 400


def test_diagnostics_marks_doctor_ran(api, machine):
    observe(machine, [raw_tcp(1, 1)], [pinfo(1)])
    assert api.get("onboarding/").json()["steps"][-1]["done"] is False
    report = api.post("diagnostics/").json()
    assert any(c["name"] == "database.integrity" for c in report["checks"])
    assert api.get("onboarding/").json()["steps"][-1]["done"] is True
    assert api.post("onboarding/dismiss/").json() == {"dismissed": True}


def test_token_rotation_revokes_old_token(app, machine):
    app.config.paths.config_dir.mkdir(parents=True, exist_ok=True)
    api = Api()
    result = api.post("auth/rotate-token/").json()
    assert result["rotated"] and "token" not in result
    assert api.get("status/").status_code == 401  # old token is dead
    new = read_token(app.config.paths)
    assert new and new != TEST_TOKEN
    assert Api(new).get("status/").status_code == 200


def test_manifest_apply_export(api, machine):
    doc = {"version": 1, "service": [{"name": "web", "port": [{"port": 3000}]}]}
    dry = api.post(
        "registry/apply/", {"document": doc, "source": "/r.toml", "dry_run": True}
    ).json()
    assert dry["services"]["create"] == ["web"] and not dry["applied"]
    applied = api.post("registry/apply/", {"document": doc, "source": "/r.toml"}).json()
    assert applied["applied"]
    exported = api.get("registry/export/").json()
    assert exported["service"][0]["port"][0]["port"] == 3000
    bad = api.post("registry/apply/", {"document": {"version": 9}, "source": "/r.toml"})
    assert bad.status_code == 400


def test_alerts_endpoints_without_webhooks(api, app):
    assert api.get("alerts/").json() == {"webhooks": []}
    assert api.post("alerts/test/").status_code == 400


def test_saved_filters_api(api):
    created = api.post("filters/", {"name": "pg", "page": "ports", "querystring": "q=postgres&x=1"})
    assert created.status_code == 201 and created.json()["querystring"] == "q=postgres"
    assert api.get("filters/", page="ports").json()["count"] == 1
    assert api.get("filters/pg/").json()["name"] == "pg"
    assert api.delete("filters/pg/").status_code == 200
    assert api.get("filters/pg/").status_code == 404


def test_autostart_status(api):
    data = api.get("autostart/").json()
    assert {"mechanism", "installed", "tray_installed"} <= set(data)
