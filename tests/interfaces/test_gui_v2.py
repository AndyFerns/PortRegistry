"""GUI tests for v0.2 pages: adopt, ignore rules, timeline, onboarding,
saved filters, noise toggle, free-port suggestion and grouping."""

from __future__ import annotations

import pytest
from django.test import Client

from portregistry.django_app.api.auth import get_owner_user
from portregistry.django_app.models import IgnoreRule, SavedFilter, Service, Socket
from portregistry.services.conflict_store import refresh_conflicts
from portregistry.services.reconcile import apply_native_scan, begin_scan
from tests.conftest import pinfo, raw_tcp, raw_udp, scan_result

pytestmark = pytest.mark.django_db


@pytest.fixture
def browser(app, machine):
    client = Client()
    client.force_login(get_owner_user())
    return client


def observe(machine, sockets, processes):
    result = scan_result(sockets, processes)
    scan = begin_scan(machine, kind="native", trigger="t", provider="fake", scope=result.scope)
    apply_native_scan(machine, scan, result)
    refresh_conflicts(machine)


@pytest.fixture
def populated(machine):
    info = pinfo(5, "node", cwd="/src/shop")
    info.project_name, info.project_root = "shop", "/src/shop"
    observe(
        machine,
        [raw_tcp(5432, 9), raw_tcp(3000, 5), raw_udp(60020, 5)],
        [info, pinfo(9, "postgres")],
    )
    return Socket.objects.get(port=3000)


@pytest.mark.parametrize(
    "path",
    [
        "/settings/ignore/",
        "/ports/timeline/",
        "/ports/timeline/?port=3000",
        "/ports/?group=project",
        "/ports/?group=process",
    ],
)
def test_new_pages_render(browser, populated, path):
    assert browser.get(path).status_code == 200


def test_ports_show_labels_projects_and_ephemeral(browser, populated):
    html = browser.get("/ports/").content.decode()
    assert "PostgreSQL" in html and "shop" in html and ">ephemeral<" in html
    grouped = browser.get("/ports/", {"group": "project"}).content.decode()
    assert "group-row" in grouped and "No project detected" in grouped


def test_adopt_flow(browser, populated):
    html = browser.get("/adopt/", {"socket": populated.pk}).content.decode()
    assert 'value="shop"' in html and "Reserve these endpoints" in html
    response = browser.post(
        "/adopt/",
        {
            "socket": populated.pk,
            "name": "shop",
            "expected_executable": "node",
            "socket_ids": [populated.pk],
        },
    )
    assert response.status_code == 302
    svc = Service.objects.get(name="shop")
    assert svc.reservations.get().port == 3000
    # Validation errors re-render the form with the message.
    again = browser.post("/adopt/", {"socket": populated.pk, "name": "shop"}).content.decode()
    assert "already exists" in again
    assert browser.get("/adopt/", {"socket": 999999}).status_code == 404


def test_mark_known_and_ignore_rule_management(browser, populated):
    response = browser.post(f"/ports/{populated.pk}/known/", HTTP_REFERER=f"/ports/{populated.pk}/")
    assert response.status_code == 302
    rule = IgnoreRule.objects.get()
    assert rule.process_name == "node" and rule.port_min == 3000
    assert ">known<" in browser.get("/ports/").content.decode()
    assert browser.post(f"/settings/ignore/{rule.pk}/toggle/").status_code == 302
    rule.refresh_from_db()
    assert not rule.enabled
    created = browser.post(
        "/settings/ignore/",
        {
            "name": "pg",
            "process_name": "postgres",
            "suppress_conflicts": "on",
            "quiet_history": "on",
        },
    )
    assert created.status_code == 302 and IgnoreRule.objects.filter(name="pg").exists()
    invalid = browser.post("/settings/ignore/", {"name": "x"}).content.decode()
    assert "at least one condition" in invalid
    assert browser.post(f"/settings/ignore/{rule.pk}/delete/").status_code == 302
    proc_resp = browser.post(f"/processes/{populated.process_id}/known/")
    assert proc_resp.status_code == 302


def test_timeline_page(browser, populated):
    html = browser.get("/ports/timeline/", {"port": 3000, "protocol": "tcp"}).content.decode()
    assert "node (pid 5)" in html and "tl-bar" in html
    assert (
        "Invalid timeline query"
        in browser.get("/ports/timeline/", {"port": "abc"}).content.decode()
    )


def test_history_noise_toggle(browser, machine):
    observe(machine, [], [])
    observe(machine, [raw_udp(60021, 2), raw_tcp(9100, 2)], [pinfo(2, "chrome")])
    html = browser.get("/history/").content.decode()
    assert "9100" in html and "60021" not in html and "hidden" in html
    noisy = browser.get("/history/", {"noise": "1"}).content.decode()
    assert "60021" in noisy and ">noise<" in noisy


def test_onboarding_card_and_dismiss(browser, populated):
    html = browser.get("/").content.decode()
    assert "Getting started" in html and "/adopt/?socket=" in html
    assert browser.post("/onboarding/dismiss/").status_code == 302
    assert "Getting started" not in browser.get("/").content.decode()


def test_saved_filters(browser, populated):
    html = browser.get("/ports/", {"q": "node"}).content.decode()
    assert "Save filter" in html
    response = browser.post(
        "/filters/save/", {"page": "ports", "name": "Node", "querystring": "q=node&evil=1"}
    )
    assert response.status_code == 302 and response["Location"] == "/ports/?q=node"
    saved = SavedFilter.objects.get()
    assert ">Node<" in browser.get("/ports/").content.decode()
    assert browser.post(f"/filters/{saved.pk}/delete/").status_code == 302
    assert not SavedFilter.objects.exists()


def test_suggest_free_port_partial(browser, populated):
    html = browser.get(
        "/reservations/suggest-port/", {"protocol": "tcp", "bind_address": "*"}
    ).content.decode()
    assert 'name="port"' in html and 'hx-swap-oob="true"' in html and "Suggested free port" in html
    assert "Suggest free port" in browser.get("/reservations/new/").content.decode()


def test_machine_page_shows_autostart_and_hint(browser, populated):
    html = browser.get("/machine/").content.decode()
    assert "Start at login" in html and "portregistry daemon install" in html
