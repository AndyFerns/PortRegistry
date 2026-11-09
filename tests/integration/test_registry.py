import pytest

from portregistry.django_app.models import Conflict, Event, PortReservation, Service
from portregistry.exceptions import NotFoundError, ValidationError
from portregistry.services import registry, reservations
from portregistry.services.conflict_store import refresh_conflicts
from portregistry.services.reconcile import apply_native_scan, begin_scan
from tests.conftest import pinfo, raw_tcp, raw_udp, scan_result

pytestmark = pytest.mark.django_db


def observe(machine, sockets, processes):
    result = scan_result(sockets, processes)
    scan = begin_scan(machine, kind="native", trigger="test", provider="fake", scope=result.scope)
    apply_native_scan(machine, scan, result)
    refresh_conflicts(machine)


class TestServices:
    def test_crud_and_history(self, machine):
        svc = registry.create_service(
            machine,
            {
                "name": "api",
                "category": "web",
                "expected_executable": "node",
                "documentation_url": "https://example.com/docs",
            },
        )
        assert svc.pk and svc.machine == machine
        registry.update_service(svc, {"description": "Public API"})
        svc.refresh_from_db()
        assert svc.description == "Public API"
        assert registry.get_service("API") == svc  # name lookup is case-insensitive
        types = list(Event.objects.values_list("type", flat=True))
        assert "service.created" in types and "service.updated" in types

    @pytest.mark.parametrize(
        ("data", "field"),
        [
            ({}, "name"),
            ({"name": "   "}, "name"),
            ({"name": "x" * 101}, "name"),
            ({"name": "a", "documentation_url": "javascript:alert(1)"}, "documentation_url"),
            ({"name": "a", "bogus": 1}, "bogus"),
            ({"name": 42}, "name"),
            ({"name": "a", "machine": "00000000-0000-0000-0000-000000000000"}, "machine"),
        ],
    )
    def test_validation(self, machine, data, field):
        with pytest.raises(ValidationError) as exc:
            registry.create_service(machine, data)
        assert field in exc.value.field_errors

    def test_duplicate_name_rejected_case_insensitive(self, machine):
        registry.create_service(machine, {"name": "Redis"})
        with pytest.raises(ValidationError) as exc:
            registry.create_service(machine, {"name": "redis"})
        assert "already exists" in exc.value.field_errors["name"][0]

    def test_delete_keeps_reservations_and_history(self, machine):
        svc = registry.create_service(machine, {"name": "db"})
        res, _ = reservations.create_reservation(machine, {"port": 5432, "service": "db"})
        result = registry.delete_service(svc)
        assert result["unlinked_reservations"] == [res.pk]
        res.refresh_from_db()
        assert res.service is None and res.status == "active"
        assert Event.objects.filter(type="service.created").exists()  # history not deleted
        deleted = Event.objects.get(type="service.deleted")
        assert deleted.details["unlinked_reservations"] == [res.pk]

    def test_get_missing_service(self, machine):
        with pytest.raises(NotFoundError):
            registry.get_service(999)


class TestReservations:
    def test_create_defaults_and_normalization(self, machine):
        res, conflicts = reservations.create_reservation(
            machine, {"port": "8080", "protocol": "TCP", "bind_address": "::ffff:127.0.0.1"}
        )
        assert (res.port, res.protocol, res.bind_address, res.status) == (
            8080,
            "tcp",
            "127.0.0.1",
            "active",
        )
        assert conflicts == []
        res2, _ = reservations.create_reservation(machine, {"port": 9090})
        assert res2.bind_address == "*" and res2.protocol == "tcp"

    @pytest.mark.parametrize(
        ("data", "field"),
        [
            ({"port": 0}, "port"),
            ({"port": 65536}, "port"),
            ({"port": True}, "port"),
            ({"port": "abc"}, "port"),
            ({}, "port"),
            ({"port": 80, "protocol": "sctp"}, "protocol"),
            ({"port": 80, "bind_address": "localhost"}, "bind_address"),
            ({"port": 80, "service": "nope"}, "service"),
            ({"port": 80, "status": "released"}, "status"),
            ({"port": 80, "description": "x" * 1001}, "description"),
        ],
    )
    def test_validation(self, machine, data, field):
        with pytest.raises(ValidationError) as exc:
            reservations.create_reservation(machine, data)
        assert field in exc.value.field_errors

    def test_occupied_reservation_detected_on_create(self, machine):
        observe(machine, [raw_tcp(8080, 100)], [pinfo(100, "node")])
        res, conflicts = reservations.create_reservation(machine, {"port": 8080})
        assert [c.type for c in conflicts] == ["occupied_reservation"]
        assert conflicts[0].reservation_id == res.pk
        assert Event.objects.filter(type="conflict.detected").exists()

    def test_tcp_reservation_not_occupied_by_udp(self, machine):
        observe(machine, [raw_udp(8080, 100)], [pinfo(100, "dns")])
        _, conflicts = reservations.create_reservation(machine, {"port": 8080, "protocol": "tcp"})
        assert conflicts == []

    def test_overlap_reported_on_both_reservations(self, machine):
        a, _ = reservations.create_reservation(machine, {"port": 80, "bind_address": "0.0.0.0"})
        b, conflicts = reservations.create_reservation(
            machine, {"port": 80, "bind_address": "127.0.0.1"}
        )
        assert [c.type for c in conflicts] == ["overlapping_reservation"]
        assert [c.type for c in reservations.conflicts_for(a)] == ["overlapping_reservation"]

    def test_release_resolves_conflict_and_keeps_record(self, machine):
        observe(machine, [raw_tcp(8080, 100)], [pinfo(100, "node")])
        res, _ = reservations.create_reservation(machine, {"port": 8080})
        reservations.release_reservation(res)
        res.refresh_from_db()
        assert res.status == "released" and res.released_at is not None
        assert not Conflict.objects.filter(active=True, reservation=res).exists()
        assert Conflict.objects.filter(
            active=False, reservation=res, resolved_at__isnull=False
        ).exists()
        assert Event.objects.filter(type="conflict.resolved").exists()
        # Releasing twice is a no-op.
        reservations.release_reservation(res)
        assert Event.objects.filter(type="reservation.released").count() == 1

    def test_update_and_reactivate(self, machine):
        res, _ = reservations.create_reservation(machine, {"port": 8080})
        reservations.release_reservation(res)
        res, _ = reservations.update_reservation(res, {"status": "active", "port": 8081})
        assert res.status == "active" and res.port == 8081 and res.released_at is None
        event = Event.objects.filter(type="reservation.updated").latest("id")
        assert set(event.details["changes"]) == {"status", "port"}

    def test_delete_is_hard_delete_with_history_snapshot(self, machine):
        res, _ = reservations.create_reservation(machine, {"port": 8080, "description": "temp"})
        rid = res.pk
        reservations.delete_reservation(res)
        assert not PortReservation.objects.filter(pk=rid).exists()
        event = Event.objects.get(type="reservation.deleted")
        assert event.details["description"] == "temp" and event.entity_id == str(rid)
        assert Event.objects.filter(type="reservation.created", entity_id=str(rid)).exists()

    def test_dry_run_check_does_not_write(self, machine):
        observe(machine, [raw_tcp(3000, 7)], [pinfo(7, "vite")])
        before = (PortReservation.objects.count(), Event.objects.count())
        findings = reservations.check_reservation(machine, {"port": 3000})
        assert [f.type.value for f in findings] == ["occupied_reservation"]
        assert (PortReservation.objects.count(), Event.objects.count()) == before

    def test_service_mismatch_through_database(self, machine):
        observe(machine, [raw_tcp(5432, 100)], [pinfo(100, "mysqld")])
        registry.create_service(machine, {"name": "pg", "expected_executable": "postgres"})
        _, conflicts = reservations.create_reservation(machine, {"port": 5432, "service": "pg"})
        assert [c.type for c in conflicts] == ["service_mismatch"]
        # Fixing the expectation resolves the conflict on the next refresh.
        registry.update_service(Service.objects.get(name="pg"), {"expected_executable": "mysqld"})
        assert not Conflict.objects.filter(active=True, type="service_mismatch").exists()

    def test_listener_disappearing_resolves_and_reports_missing_service(self, machine):
        observe(machine, [raw_tcp(5432, 100)], [pinfo(100, "postgres")])
        registry.create_service(machine, {"name": "pg", "expected_executable": "postgres"})
        reservations.create_reservation(machine, {"port": 5432, "service": "pg"})
        assert (
            not Conflict.objects.filter(active=True).exclude(type="incomplete_discovery").exists()
        )
        observe(machine, [], [])
        missing = Conflict.objects.get(active=True, type="missing_expected_service")
        assert missing.certainty == "definite"

    def test_conflict_rows_not_duplicated_across_refreshes(self, machine):
        observe(machine, [raw_tcp(8080, 100)], [pinfo(100, "node")])
        reservations.create_reservation(machine, {"port": 8080})
        for _ in range(3):
            refresh_conflicts(machine)
        assert Conflict.objects.filter(type="occupied_reservation").count() == 1
        assert Event.objects.filter(type="conflict.detected").count() == 1
