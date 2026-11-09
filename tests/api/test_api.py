import asyncio
import json

import pytest
from django.test import AsyncClient, Client

from portregistry.django_app.api.auth import get_owner_user
from portregistry.services.conflict_store import refresh_conflicts
from portregistry.services.reconcile import apply_native_scan, begin_scan
from tests.conftest import TEST_TOKEN, pinfo, raw_tcp, raw_udp, scan_result

pytestmark = pytest.mark.django_db

AUTH = {"HTTP_AUTHORIZATION": f"Bearer {TEST_TOKEN}"}


@pytest.fixture
def api(app, machine):
    client = Client()

    class Api:
        def get(self, path, **params):
            return client.get(f"/api/v1/{path}", params, **AUTH)

        def post(self, path, body=None):
            return client.post(
                f"/api/v1/{path}", json.dumps(body or {}), content_type="application/json", **AUTH
            )

        def patch(self, path, body):
            return client.patch(
                f"/api/v1/{path}", json.dumps(body), content_type="application/json", **AUTH
            )

        def put(self, path, body):
            return client.put(
                f"/api/v1/{path}", json.dumps(body), content_type="application/json", **AUTH
            )

        def delete(self, path):
            return client.delete(f"/api/v1/{path}", **AUTH)

    return Api()


def observe(machine, sockets, processes):
    result = scan_result(sockets, processes)
    scan = begin_scan(machine, kind="native", trigger="test", provider="fake", scope=result.scope)
    apply_native_scan(machine, scan, result)
    refresh_conflicts(machine)


def assert_error(response, status, code):
    assert response.status_code == status, response.content
    body = response.json()
    assert set(body) == {"error"}
    assert body["error"]["code"] == code
    assert body["error"]["message"]
    return body["error"]


class TestAuth:
    def test_health_is_public_and_not_sensitive(self, app):
        response = Client().get("/api/v1/health/")
        assert response.status_code == 200
        assert response.json() == {
            "status": "ok",
            "service": "portregistry",
            "version": app.version,
            "api": "v1",
        }

    def test_requires_authentication(self, app, machine):
        response = Client().get("/api/v1/status/")
        assert_error(response, 401, "not_authenticated")
        assert response["WWW-Authenticate"].startswith("Bearer")

    @pytest.mark.parametrize("header", ["Bearer wrong", "Token abc", "Bearer"])
    def test_bad_token_rejected(self, app, machine, header):
        response = Client().get("/api/v1/status/", HTTP_AUTHORIZATION=header)
        assert_error(response, 401, "authentication_failed")

    def test_session_auth_requires_csrf_for_mutations(self, app, machine):
        client = Client(enforce_csrf_checks=True)
        client.force_login(get_owner_user())
        assert client.get("/api/v1/services/").status_code == 200
        response = client.post(
            "/api/v1/services/", json.dumps({"name": "x"}), content_type="application/json"
        )
        error = assert_error(response, 403, "permission_denied")
        assert "CSRF" in error["message"]
        client.get("/login/")  # any page that sets the CSRF cookie
        token = client.cookies["portregistry_csrftoken"].value
        response = client.post(
            "/api/v1/services/",
            json.dumps({"name": "x"}),
            content_type="application/json",
            HTTP_X_CSRFTOKEN=token,
        )
        assert response.status_code == 201

    def test_disallowed_host_rejected(self, app, machine):
        response = Client().get("/api/v1/health/", HTTP_HOST="evil.example.com")
        assert response.status_code == 400


class TestObservations:
    def test_status(self, api, machine):
        observe(machine, [raw_tcp(8080, 1)], [pinfo(1, "node")])
        data = api.get("status/").json()
        assert data["machine"]["uuid"] == str(machine.uuid)
        assert data["summary"]["endpoints"]["total"] == 1
        assert data["discovery"]["last_scan_status"] == "complete"
        assert data["providers"]["docker"]["state"] == "disabled"

    def test_ports_filters_and_pagination(self, api, machine):
        observe(
            machine,
            [raw_tcp(8080, 1), raw_tcp(8081, 1), raw_udp(5353, 2, "::")],
            [pinfo(1, "node"), pinfo(2, "mdns")],
        )
        page = api.get("ports/", limit=2).json()
        assert page["count"] == 3 and len(page["results"]) == 2 and page["next"]
        tcp = api.get("ports/", protocol="tcp").json()["results"]
        assert {p["port"] for p in tcp} == {8080, 8081}
        assert tcp[0]["process"]["name"] == "node"
        by_name = api.get("ports/", q="mdns").json()["results"]
        assert [p["endpoint"] for p in by_name] == ["udp [::]:5353"]
        assert api.get("ports/", port=8081).json()["count"] == 1
        assert api.get("ports/", family="ipv6").json()["count"] == 1

    def test_invalid_filter(self, api, machine):
        error = assert_error(api.get("ports/", protocol="sctp"), 400, "validation_error")
        assert "protocol" in error["details"]["fields"]

    def test_port_and_process_detail(self, api, machine):
        observe(machine, [raw_tcp(8080, 1)], [pinfo(1, "node", cmdline=["node", "server.js"])])
        port = api.get("ports/").json()["results"][0]
        detail = api.get(f"ports/{port['id']}/").json()
        assert detail["process"]["cmdline"] == ["node", "server.js"]
        assert detail["conflicts"][0]["type"] == "unregistered_listener"
        proc = api.get(f"processes/{detail['process']['id']}/").json()
        assert proc["identity_complete"] and proc["sockets"][0]["port"] == 8080
        assert api.get("processes/").json()["count"] == 1

    def test_not_found_is_json(self, api):
        assert_error(api.get("ports/999/"), 404, "not_found")
        assert_error(api.get("nonexistent/"), 404, "not_found")

    def test_machines_and_history(self, api, machine):
        assert api.get("machines/").json()["results"][0]["hostname"] == "testhost"
        observe(machine, [raw_tcp(1, 1)], [pinfo(1)])
        events = api.get("history/", type="discovery").json()["results"]
        assert events[0]["type"] == "discovery.baseline"
        assert_error(api.get("history/", since="yesterday"), 400, "validation_error")

    def test_containers_empty_with_provider_state(self, api):
        data = api.get("containers/").json()
        assert data["results"] == [] and data["docker"]["state"] == "disabled"


class TestRegistryApi:
    def test_service_crud(self, api):
        created = api.post("services/", {"name": "web", "expected_executable": "nginx"})
        assert created.status_code == 201
        sid = created.json()["id"]
        assert api.get("services/").json()["count"] == 1
        assert api.patch(f"services/{sid}/", {"notes": "hi"}).json()["notes"] == "hi"
        replaced = api.put(f"services/{sid}/", {"name": "web2"}).json()
        assert (
            replaced["name"] == "web2"
            and replaced["notes"] == ""
            and replaced["expected_executable"] == ""
        )
        assert api.get("services/web2/").json()["id"] == sid
        deleted = api.delete(f"services/{sid}/").json()
        assert deleted["deleted"]["name"] == "web2"
        assert_error(api.get(f"services/{sid}/"), 404, "not_found")

    def test_service_validation_error_shape(self, api):
        error = assert_error(api.post("services/", {"name": ""}), 400, "validation_error")
        assert "name" in error["details"]["fields"]

    def test_non_object_body(self, api):
        response = Client().post(
            "/api/v1/services/", json.dumps([1, 2]), content_type="application/json", **AUTH
        )
        assert_error(response, 400, "validation_error")

    def test_malformed_json(self, api):
        response = Client().post(
            "/api/v1/services/", "{nope", content_type="application/json", **AUTH
        )
        assert_error(response, 400, "parse_error")

    def test_reservation_flow(self, api, machine):
        observe(machine, [raw_tcp(8080, 1)], [pinfo(1, "node")])
        created = api.post("reservations/", {"port": 8080, "description": "demo"})
        assert created.status_code == 201
        data = created.json()
        assert data["advisory"] is True and data["display_status"] == "attention"
        assert [c["type"] for c in data["conflicts"]] == ["occupied_reservation"]
        rid = data["id"]
        listed = api.get("reservations/").json()["results"]
        assert listed[0]["attention"] is True
        released = api.post(f"reservations/{rid}/release/").json()
        assert released["status"] == "released" and released["conflicts"] == []
        assert api.get("reservations/").json()["count"] == 0
        assert api.get("reservations/", status="all").json()["count"] == 1
        patched = api.patch(f"reservations/{rid}/", {"status": "active", "protocol": "udp"}).json()
        assert patched["status"] == "active" and patched["conflicts"] == []
        assert api.delete(f"reservations/{rid}/").json()["deleted"]["id"] == rid

    def test_reservation_check_dry_run(self, api, machine):
        observe(machine, [raw_tcp(8080, 1)], [pinfo(1, "node")])
        data = api.post("reservations/check/", {"port": 8080}).json()
        assert data["conflict_free"] is False
        assert data["findings"][0]["type"] == "occupied_reservation"
        assert api.post("reservations/check/", {"port": 8080, "protocol": "udp"}).json()[
            "conflict_free"
        ]
        assert api.get("reservations/", status="all").json()["count"] == 0

    def test_reservation_validation(self, api):
        error = assert_error(api.post("reservations/", {"port": 0}), 400, "validation_error")
        assert "port" in error["details"]["fields"]

    def test_conflicts_endpoint_filters(self, api, machine):
        observe(machine, [raw_tcp(8080, 1), raw_tcp(9000, 1)], [pinfo(1, "node")])
        api.post("reservations/", {"port": 8080})
        everything = api.get("conflicts/").json()["results"]
        assert {c["type"] for c in everything} >= {"occupied_reservation", "unregistered_listener"}
        actionable = api.get("conflicts/", min_severity="warning").json()["results"]
        assert [c["type"] for c in actionable] == ["occupied_reservation"]
        assert actionable[0]["explanation"]


class TestDiscoveryApi:
    def test_scan_requests_coalesce(self, api, app):
        first = api.post("discovery/scan/", {"protocol": "tcp"})
        assert first.status_code == 202 and first.json()["coalesced"] is False
        second = api.post("discovery/scan/", {})
        assert (
            second.json()["ticket"] == first.json()["ticket"] and second.json()["coalesced"] is True
        )
        ticket = api.get(f"discovery/scan/{first.json()['ticket']}/").json()
        assert ticket["status"] == "queued"
        assert_error(api.get("discovery/scan/999/"), 404, "not_found")

    def test_scan_validation(self, api):
        assert_error(api.post("discovery/scan/", {"port": 0}), 400, "validation_error")
        assert_error(api.post("discovery/scan/", {"protocol": "icmp"}), 400, "validation_error")

    def test_scans_listing(self, api, machine):
        observe(machine, [raw_tcp(1, 1)], [pinfo(1)])
        scans = api.get("discovery/scans/").json()["results"]
        assert scans[0]["status"] == "complete" and scans[0]["socket_count"] == 1
        assert api.get(f"discovery/scans/{scans[0]['id']}/").json()["id"] == scans[0]["id"]

    def test_gui_link_issues_single_use_nonce(self, api, app):
        url = api.post("auth/gui-link/").json()["url"]
        assert url.startswith(app.config.base_url + "/login/link/")
        nonce = url.rstrip("/").rsplit("/", 1)[-1]
        assert app.links.consume(nonce) is True
        assert app.links.consume(nonce) is False


class TestEvents:
    def test_events_published_after_commit(
        self, api, app, machine, django_capture_on_commit_callbacks
    ):
        seen = []
        app.bus.add_listener(lambda e: seen.append((e.topic, e.type)))
        with django_capture_on_commit_callbacks(execute=False) as callbacks:
            api.post("services/", {"name": "svc"})
            assert seen == []  # nothing published before commit
        for callback in callbacks:
            callback()
        assert ("registry", "history.recorded") in seen

    def test_sse_requires_auth(self, app):
        assert Client().get("/api/v1/events/stream/").status_code == 401

    def test_sse_stream(self, app):
        async def scenario():
            response = await AsyncClient().get(
                "/api/v1/events/stream/", headers={"Authorization": f"Bearer {TEST_TOKEN}"}
            )
            assert response.status_code == 200
            assert response["Content-Type"] == "text/event-stream"
            chunks = response.streaming_content.__aiter__()
            assert (await chunks.__anext__()).startswith(b"retry:")
            hello = await chunks.__anext__()
            assert b"event: hello" in hello and b'"resync":true' in hello
            app.bus.publish("ports", "ports.changed", {"scan_id": 7})
            frame = await asyncio.wait_for(chunks.__anext__(), 2)
            assert b"event: ports" in frame and b'"scan_id":7' in frame
            app.bus.close()
            final = await asyncio.wait_for(chunks.__anext__(), 2)
            assert b"daemon.stopping" in final

        asyncio.run(scenario())
