"""GUI tests for the Stop pages (fake OS; nothing real is stopped)."""

from __future__ import annotations

import re

import pytest
from django.test import Client

from portregistry.django_app.api.auth import get_owner_user
from portregistry.django_app.models import Event, ProcessInstance, Socket
from portregistry.services.conflict_store import refresh_conflicts
from portregistry.services.reconcile import apply_native_scan, begin_scan
from tests.conftest import pinfo, raw_tcp, scan_result
from tests.control_fakes import ME, enable_control

pytestmark = pytest.mark.django_db


@pytest.fixture
def browser(app, machine):
    client = Client()
    client.force_login(get_owner_user())
    return client


@pytest.fixture
def proc(machine, fake_os):
    live = fake_os.add(4242, "node", cmdline=("node", "<script>alert(1)</script>"))
    info = pinfo(
        4242, "node", create_time=live.create_time, username=ME, cmdline=list(live.cmdline)
    )
    result = scan_result([raw_tcp(3000, 4242)], [info])
    scan = begin_scan(machine, kind="native", trigger="t", provider="fake", scope=result.scope)
    apply_native_scan(machine, scan, result)
    refresh_conflicts(machine)
    return ProcessInstance.objects.get(pid=4242)


def html(resp):
    return resp.content.decode()


def test_disabled_shows_how_to_stop_with_commands_only(browser, proc):
    page = html(browser.get(f"/processes/{proc.pk}/"))
    assert "How to stop this" in page and "Stop…" not in page
    review = html(browser.get(f"/processes/{proc.pk}/stop/"))
    assert "kill -TERM 4242" in review and "Process control is off" in review
    assert "Continue to confirmation" not in review
    port = Socket.objects.get(port=3000)
    assert "How to stop this" in html(browser.get(f"/ports/{port.pk}/"))
    # A forged POST is refused and audited.
    resp = browser.post(f"/processes/{proc.pk}/stop/", {"mode": "process"})
    assert "Nothing was stopped" in html(resp)
    assert Event.objects.get(type="process.stop_refused").details["actor"] == "gui"


def test_review_confirm_and_result(browser, app, proc, fake_os):
    enable_control(app)
    assert "Stop owning process" in html(browser.get(f"/ports/{Socket.objects.get().pk}/"))
    review = html(browser.get(f"/processes/{proc.pk}/stop/"))
    assert "Continue to confirmation" in review
    assert "&lt;script&gt;" in review and "<script>alert" not in review  # escaped cmdline
    confirm = html(browser.post(f"/processes/{proc.pk}/stop/", {"mode": "process"}))
    assert "Type the PID" in confirm
    code = re.search(r'name="code" value="([^"]+)"', confirm).group(1)

    wrong = browser.post(
        "/processes/stop/confirm/", {"code": code, "pid": "1", "process_id": proc.pk}
    )
    assert wrong.status_code == 302 and wrong["Location"].endswith(f"/processes/{proc.pk}/stop/")
    assert fake_os.sent == []
    assert "does not match" in Event.objects.get(type="process.stop_refused").summary

    confirm = html(browser.post(f"/processes/{proc.pk}/stop/", {"mode": "process"}))
    code = re.search(r'name="code" value="([^"]+)"', confirm).group(1)
    done = browser.post(
        "/processes/stop/confirm/", {"code": code, "pid": "4242", "process_id": proc.pk}
    )
    assert done.status_code == 302
    result = html(browser.get(done["Location"]))
    assert "Stopped." in result and "stopped" in result
    partial = html(browser.get(done["Location"], HTTP_HX_REQUEST="true"))
    assert "<html" not in partial and "hx-trigger" not in partial
    assert fake_os.sent == [(4242, "graceful")]
    stopped = Event.objects.get(type="process.stopped")
    assert stopped.details["actor"] == "gui"


def test_tree_review_lists_members(browser, app, proc, fake_os):
    enable_control(app)
    fake_os.add(4243, "esbuild", ppid=4242)
    page = html(browser.get(f"/processes/{proc.pk}/stop/?mode=tree"))
    assert "Stop order (children first)" in page and "esbuild" in page
    assert "2 processes" in page


def test_refused_process_has_no_continue_button(browser, app, proc, fake_os):
    enable_control(app)
    fake_os.add(4242, "node", user="bob", uid=1001)
    page = html(browser.get(f"/processes/{proc.pk}/stop/"))
    assert "belongs to another user" in page and "Continue to confirmation" not in page


def test_confirm_requires_csrf(app, proc):
    enable_control(app)
    client = Client(enforce_csrf_checks=True)
    client.force_login(get_owner_user())
    assert client.post(f"/processes/{proc.pk}/stop/", {"mode": "process"}).status_code == 403
    assert client.post("/processes/stop/confirm/", {"code": "x", "pid": "4242"}).status_code == 403


def test_machine_page_shows_control_state(browser, app):
    assert "Stopping processes" in html(browser.get("/machine/"))
    enable_control(app)
    assert "two-step confirmation" in html(browser.get("/machine/"))
