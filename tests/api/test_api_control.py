"""API tests for process control (fake OS; nothing real is stopped)."""

from __future__ import annotations

import json

import pytest
from django.test import Client

from portregistry.django_app.api.auth import get_owner_user
from portregistry.django_app.models import Event, ProcessInstance
from portregistry.services.conflict_store import refresh_conflicts
from portregistry.services.reconcile import apply_native_scan, begin_scan
from tests.conftest import TEST_TOKEN, pinfo, raw_tcp, scan_result
from tests.control_fakes import ME, enable_control

pytestmark = pytest.mark.django_db


class Api:
    def __init__(self, **headers):
        self.client = Client()
        self.headers = {"HTTP_AUTHORIZATION": f"Bearer {TEST_TOKEN}", **headers}

    def get(self, path, **params):
        return self.client.get(f"/api/v1/{path}", params, **self.headers)

    def post(self, path, body=None):
        return self.client.post(
            f"/api/v1/{path}",
            json.dumps(body or {}),
            content_type="application/json",
            **self.headers,
        )


@pytest.fixture
def api(app, machine):
    return Api(HTTP_X_PORTREGISTRY_CLIENT="cli")


@pytest.fixture
def proc(machine, fake_os):
    live = fake_os.add(4242, "node")
    result = scan_result(
        [raw_tcp(3000, 4242)], [pinfo(4242, "node", create_time=live.create_time, username=ME)]
    )
    scan = begin_scan(machine, kind="native", trigger="t", provider="fake", scope=result.scope)
    apply_native_scan(machine, scan, result)
    refresh_conflicts(machine)
    return ProcessInstance.objects.get(pid=4242)


def test_disabled_preview_works_but_request_is_403(api, proc):
    preview = api.get(f"processes/{proc.pk}/stop/preview/")
    assert preview.status_code == 200
    data = preview.json()
    assert data["control_enabled"] is False and data["commands"]
    resp = api.post(f"processes/{proc.pk}/stop/request/")
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "control_disabled"
    event = Event.objects.get(type="process.stop_refused")
    assert event.details["actor"] == "cli"


def test_status_and_control_endpoint_report_state(api, app, proc):
    assert api.get("control/").json()["enabled"] is False
    enable_control(app)
    assert api.get("control/").json()["enabled"] is True
    assert api.get("status/").json()["control"]["enabled"] is True


def test_two_step_flow(api, app, proc, fake_os):
    enable_control(app)
    issued = api.post(f"processes/{proc.pk}/stop/request/", {"mode": "process"})
    assert issued.status_code == 201
    body = issued.json()
    assert body["expires_in"] == 30 and body["assessment"]["can_request"]
    done = api.post("processes/stop/confirm/", {"code": body["code"], "pid": 4242})
    assert done.status_code == 200
    op = done.json()
    assert op["outcome"] == "stopped" and op["actor"] == "cli"
    assert api.get(f"processes/stop/operations/{op['id']}/").json()["id"] == op["id"]
    assert api.get("processes/stop/operations/nope/").status_code == 404
    reuse = api.post("processes/stop/confirm/", {"code": body["code"], "pid": 4242})
    assert reuse.status_code == 409
    assert reuse.json()["error"]["code"] == "stop_code_invalid"
    types = list(Event.objects.order_by("id").values_list("type", flat=True))
    assert [t for t in types if t.startswith("process.stop")] == [
        "process.stop_requested",
        "process.stopped",
        "process.stop_refused",
    ]


def test_confirm_requires_matching_pid(api, app, proc, fake_os):
    enable_control(app)
    code = api.post(f"processes/{proc.pk}/stop/request/").json()["code"]
    resp = api.post("processes/stop/confirm/", {"code": code})
    assert resp.status_code == 409 and "does not match" in resp.json()["error"]["message"]
    assert fake_os.sent == []


def test_refusal_is_409_with_reasons(api, app, proc):
    enable_control(app)
    blocked = Api(HTTP_X_PORTREGISTRY_CLIENT_ANCESTORS="4242,1")
    resp = blocked.post(f"processes/{proc.pk}/stop/request/")
    assert resp.status_code == 409
    err = resp.json()["error"]
    assert err["code"] == "stop_refused" and err["details"]["reasons"]
    assert err["details"]["assessment"]["allowed"] is False


def test_token_clients_cannot_claim_to_be_the_gui(app, proc):
    enable_control(app)
    api = Api(HTTP_X_PORTREGISTRY_CLIENT="gui")
    api.post(f"processes/{proc.pk}/stop/request/")
    assert Event.objects.get(type="process.stop_requested").details["actor"] == "api"


def test_browser_session_needs_csrf_and_is_recorded_as_gui(app, proc):
    enable_control(app)
    browser = Client(enforce_csrf_checks=True)
    browser.force_login(get_owner_user())
    resp = browser.post(
        f"/api/v1/processes/{proc.pk}/stop/request/", "{}", content_type="application/json"
    )
    assert resp.status_code == 403
    assert not Event.objects.filter(type="process.stop_requested").exists()

    browser.get("/")  # obtain a CSRF cookie
    token = browser.cookies["portregistry_csrftoken"].value
    resp = browser.post(
        f"/api/v1/processes/{proc.pk}/stop/request/",
        "{}",
        content_type="application/json",
        HTTP_X_CSRFTOKEN=token,
    )
    assert resp.status_code == 201
    assert Event.objects.get(type="process.stop_requested").details["actor"] == "gui"


def test_foreign_host_header_is_rejected(api, app, proc):
    enable_control(app)
    resp = api.client.post(
        f"/api/v1/processes/{proc.pk}/stop/request/",
        "{}",
        content_type="application/json",
        HTTP_HOST="evil.example",
        **api.headers,
    )
    assert resp.status_code == 400
    assert not Event.objects.filter(type__startswith="process.stop").exists()


def test_unauthenticated_requests_are_rejected(app, proc):
    resp = Client().post(
        f"/api/v1/processes/{proc.pk}/stop/request/", "{}", content_type="application/json"
    )
    assert resp.status_code in (401, 403)
