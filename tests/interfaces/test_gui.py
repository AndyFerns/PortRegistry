"""Django test-client coverage of GUI routes, auth and escaping."""

import pytest
from django.test import Client

from portregistry.django_app.api.auth import get_owner_user
from portregistry.django_app.models import PortReservation, Service
from portregistry.services import registry, reservations
from portregistry.services.conflict_store import refresh_conflicts
from portregistry.services.reconcile import apply_native_scan, begin_scan
from tests.conftest import TEST_TOKEN, pinfo, raw_tcp, raw_udp, scan_result

pytestmark = pytest.mark.django_db

PAGES = [
    "/",
    "/ports/",
    "/services/",
    "/services/new/",
    "/reservations/",
    "/reservations/new/",
    "/conflicts/",
    "/conflicts/?info=1",
    "/history/",
    "/containers/",
    "/machine/",
]


@pytest.fixture
def populated(app, machine):
    result = scan_result(
        [raw_tcp(8080, 100), raw_udp(5353, 200, "::")],
        [pinfo(100, "node", cmdline=["node", "server.js"]), pinfo(200, "mdns")],
    )
    scan = begin_scan(machine, kind="native", trigger="test", provider="fake", scope=result.scope)
    apply_native_scan(machine, scan, result)
    refresh_conflicts(machine)
    svc = registry.create_service(machine, {"name": "web", "expected_executable": "nginx"})
    res, _ = reservations.create_reservation(machine, {"port": 8080, "service": "web"})
    return {"service": svc, "reservation": res}


@pytest.fixture
def browser(app, machine):
    client = Client()
    client.force_login(get_owner_user())
    return client


class TestAuth:
    @pytest.mark.parametrize("path", PAGES)
    def test_pages_require_login(self, app, machine, path):
        response = Client().get(path)
        assert response.status_code == 302 and response["Location"].startswith("/login/")

    def test_htmx_partial_without_session_asks_for_redirect(self, app, machine):
        response = Client().get("/partials/status-bar/", HTTP_HX_REQUEST="true")
        assert response.status_code == 401 and response["HX-Redirect"] == "/login/"

    def test_token_login(self, app, machine):
        client = Client()
        assert client.post("/login/", {"token": "nope"}).status_code == 401
        response = client.post("/login/", {"token": TEST_TOKEN, "next": "/ports/"})
        assert response.status_code == 302 and response["Location"] == "/ports/"
        assert client.get("/ports/").status_code == 200

    def test_open_redirect_blocked(self, app, machine):
        response = Client().post("/login/", {"token": TEST_TOKEN, "next": "https://evil.example/"})
        assert response["Location"] == "/"

    def test_one_time_link(self, app, machine):
        nonce = app.links.issue()
        client = Client()
        assert client.get(f"/login/link/{nonce}/").status_code == 302
        assert client.get("/").status_code == 200
        assert Client().get(f"/login/link/{nonce}/").status_code == 401  # single use

    def test_logout_requires_post(self, browser):
        assert browser.get("/logout/").status_code == 405
        assert browser.post("/logout/").status_code == 302
        assert browser.get("/").status_code == 302

    def test_security_headers(self, browser):
        response = browser.get("/")
        assert "script-src 'self'" in response["Content-Security-Policy"]
        assert response["X-Frame-Options"] == "DENY"


class TestPages:
    @pytest.mark.parametrize("path", PAGES)
    def test_pages_render(self, browser, populated, path):
        response = browser.get(path)
        assert response.status_code == 200, path

    def test_dashboard_shows_real_counts(self, browser, populated):
        html = browser.get("/").content.decode()
        assert "Endpoints" in html and "service_mismatch" in html  # node owns web's port
        assert "Recent changes" in html

    def test_ports_explorer_finds_process(self, browser, populated):
        html = browser.get("/ports/", {"q": "node"}).content.decode()
        assert "node" in html and "8080" in html and "5353" not in html
        partial = browser.get(
            "/ports/", {"protocol": "udp"}, HTTP_HX_REQUEST="true"
        ).content.decode()
        assert "<html" not in partial and "5353" in partial

    def test_invalid_port_filter_shows_error(self, browser, populated):
        html = browser.get("/ports/", {"protocol": "bogus"}).content.decode()
        assert "Invalid filter" in html

    def test_detail_pages(self, browser, populated):
        sock = populated["reservation"].machine.socket_set.get(port=8080)
        html = browser.get(f"/ports/{sock.pk}/").content.decode()
        assert "node server.js" in html and "reservation #" in html
        assert browser.get(f"/processes/{sock.process_id}/").status_code == 200
        assert browser.get(f"/services/{populated['service'].pk}/").status_code == 200
        assert browser.get(f"/reservations/{populated['reservation'].pk}/").status_code == 200
        assert browser.get("/ports/99999/").status_code == 404

    def test_partials(self, browser, populated):
        assert "Scanned" in browser.get("/partials/status-bar/").content.decode()
        assert browser.get("/partials/dashboard/").status_code == 200
        assert browser.get("/partials/recent-events/").status_code == 200

    def test_static_assets_served(self, browser):
        assert browser.get("/static/portregistry/app.css").status_code == 200
        assert browser.get("/static/portregistry/vendor/htmx.min.js").status_code == 200


class TestEscaping:
    def test_user_values_are_escaped(self, browser, app, machine):
        registry.create_service(machine, {"name": "<script>alert(1)</script>", "notes": "<b>x</b>"})
        html = browser.get("/services/").content.decode()
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html

    def test_process_metadata_escaped(self, browser, app, machine):
        result = scan_result([raw_tcp(9999, 5)], [pinfo(5, "<img src=x onerror=alert(1)>")])
        scan = begin_scan(machine, kind="native", trigger="t", provider="fake", scope=result.scope)
        apply_native_scan(machine, scan, result)
        html = browser.get("/ports/").content.decode()
        assert "<img src=x" not in html and "&lt;img src=x" in html


class TestMutations:
    def test_create_service_via_form(self, browser, app, machine):
        response = browser.post("/services/new/", {"name": "api", "expected_executable": "node"})
        assert response.status_code == 302
        assert Service.objects.filter(name="api").exists()

    def test_service_form_shows_validation_errors(self, browser, app, machine):
        registry.create_service(machine, {"name": "dup"})
        html = browser.post("/services/new/", {"name": "DUP"}).content.decode()
        assert "already exists" in html

    def test_reservation_create_release_delete(self, browser, populated, machine):
        response = browser.post(
            "/reservations/new/", {"port": 9090, "protocol": "udp", "bind_address": "*"}
        )
        assert response.status_code == 302
        res = PortReservation.objects.get(port=9090)
        assert res.protocol == "udp"
        assert browser.post(f"/reservations/{res.pk}/release/").status_code == 302
        res.refresh_from_db()
        assert res.status == "released"
        assert (
            "Permanently delete" in browser.get(f"/reservations/{res.pk}/delete/").content.decode()
        )
        assert browser.post(f"/reservations/{res.pk}/delete/").status_code == 302
        assert not PortReservation.objects.filter(pk=res.pk).exists()

    def test_reservation_live_check(self, browser, populated):
        html = browser.post(
            "/reservations/check/", {"port": 8080, "protocol": "tcp", "bind_address": "*"}
        ).content.decode()
        assert "in use" in html or "not owned" in html
        html = browser.post(
            "/reservations/check/", {"port": 8080, "protocol": "udp", "bind_address": "*"}
        ).content.decode()
        assert "No current occupant" in html

    def test_service_delete_confirmation(self, browser, populated):
        svc = populated["service"]
        assert "kept" in browser.get(f"/services/{svc.pk}/delete/").content.decode()
        assert browser.post(f"/services/{svc.pk}/delete/").status_code == 302
        assert PortReservation.objects.get(pk=populated["reservation"].pk).service is None

    def test_scan_button_queues_scan(self, browser, app):
        html = browser.post("/scan/").content.decode()
        assert "Scan #" in html and "queued" in html

    def test_gui_mutations_require_csrf(self, app, machine):
        client = Client(enforce_csrf_checks=True)
        client.force_login(get_owner_user())
        assert client.post("/services/new/", {"name": "x"}).status_code == 403
