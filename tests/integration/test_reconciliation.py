import pytest

from portregistry.core.types import ScanScope
from portregistry.django_app.models import DiscoveryScan, Event, ProcessInstance, Socket
from portregistry.services.reconcile import apply_native_scan, begin_scan, fail_interrupted_scans
from tests.conftest import pinfo, raw_tcp, raw_udp, scan_result


def run(machine, result, trigger="scheduled"):
    scan = begin_scan(machine, kind="native", trigger=trigger, provider="fake", scope=result.scope)
    return apply_native_scan(machine, scan, result)


def event_types(since_id=0):
    return list(Event.objects.filter(id__gt=since_id).order_by("id").values_list("type", flat=True))


def last_event_id():
    last = Event.objects.order_by("-id").first()
    return last.id if last else 0


@pytest.mark.django_db
class TestNativeReconciliation:
    def test_first_scan_persists_and_records_single_baseline_event(self, machine):
        summary = run(
            machine,
            scan_result(
                [raw_tcp(8080, 100), raw_udp(5353, 200)], [pinfo(100, "web"), pinfo(200, "mdns")]
            ),
        )
        assert summary.baseline and summary.socket_count == 2
        assert Socket.objects.filter(active=True).count() == 2
        web = ProcessInstance.objects.get(pid=100)
        assert web.identity_complete and web.identity_key == "100:1000.000"
        assert len(web.identity_hash) == 32
        assert event_types() == ["discovery.baseline"]
        scan = DiscoveryScan.objects.get(pk=summary.scan_id)
        assert scan.status == "complete" and scan.socket_count == 2

    def test_unchanged_polling_creates_no_rows_or_events(self, machine):
        result = scan_result([raw_tcp(8080, 100)], [pinfo(100, "web")])
        run(machine, result)
        marker = last_event_id()
        for _ in range(3):
            summary = run(machine, scan_result([raw_tcp(8080, 100)], [pinfo(100, "web")]))
            assert not summary.changed
        assert Socket.objects.count() == 1
        assert ProcessInstance.objects.count() == 1
        assert event_types(marker) == []
        sock = Socket.objects.get()
        assert sock.last_scan_id == summary.scan_id

    def test_disappearance_after_complete_scan(self, machine):
        run(
            machine,
            scan_result([raw_tcp(8080, 100), raw_tcp(9090, 101)], [pinfo(100), pinfo(101, "api")]),
        )
        marker = last_event_id()
        summary = run(machine, scan_result([raw_tcp(8080, 100)], [pinfo(100)]))
        assert summary.disappeared == 1 and summary.processes_disappeared == 1
        gone = Socket.objects.get(port=9090)
        assert not gone.active and gone.ended_at is not None
        assert not ProcessInstance.objects.get(pid=101).active
        assert event_types(marker) == ["endpoint.disappeared", "process.disappeared"]

    def test_new_endpoint_after_baseline_records_appearance(self, machine):
        run(machine, scan_result([raw_tcp(8080, 100)], [pinfo(100)]))
        marker = last_event_id()
        run(
            machine,
            scan_result([raw_tcp(8080, 100), raw_udp(9999, 300)], [pinfo(100), pinfo(300, "udpd")]),
        )
        assert event_types(marker) == ["endpoint.appeared", "process.appeared"]
        summary_text = Event.objects.get(type="endpoint.appeared").summary
        assert "udp 0.0.0.0:9999" in summary_text and "udpd" in summary_text

    def test_failed_scan_never_marks_absence(self, machine):
        run(machine, scan_result([raw_tcp(8080, 100)], [pinfo(100)]))
        summary = run(machine, scan_result([], [], error="RuntimeError: provider broke"))
        assert summary.status == "failed"
        assert Socket.objects.get().active
        assert ProcessInstance.objects.get().active
        assert "scan.status_changed" in event_types()

    def test_partial_scan_preserves_unobserved_state(self, machine):
        run(
            machine, scan_result([raw_tcp(8080, 100), raw_tcp(9090, 101)], [pinfo(100), pinfo(101)])
        )
        # Fallback enumeration only saw pid 100's sockets; pid 101 was not readable.
        summary = run(
            machine,
            scan_result([], [], complete=False, enumerated_pids=frozenset({100})),
        )
        assert summary.status == "partial"
        assert not Socket.objects.get(port=8080).active  # authoritative for pid 100
        assert Socket.objects.get(port=9090).active  # not authoritative for pid 101
        assert summary.preserved == 1

    def test_scope_limited_scan_only_reconciles_its_scope(self, machine):
        run(machine, scan_result([raw_tcp(8080, 100), raw_udp(5353, 100)], [pinfo(100)]))
        run(machine, scan_result([], [], scope=ScanScope.build("tcp")))
        assert not Socket.objects.get(protocol="tcp").active
        assert Socket.objects.get(protocol="udp").active
        assert ProcessInstance.objects.get().active  # still owns the UDP socket

    def test_pid_reuse_creates_new_process_instance_and_owner_change(self, machine):
        run(machine, scan_result([raw_tcp(8080, 100)], [pinfo(100, "old", create_time=1000.0)]))
        marker = last_event_id()
        run(machine, scan_result([raw_tcp(8080, 100)], [pinfo(100, "new", create_time=2000.0)]))
        instances = ProcessInstance.objects.filter(pid=100).order_by("create_time")
        assert [p.name for p in instances] == ["old", "new"]
        assert [p.active for p in instances] == [False, True]
        assert Socket.objects.filter(port=8080).count() == 2
        types = event_types(marker)
        assert "endpoint.owner_changed" in types
        assert "endpoint.appeared" not in types and "endpoint.disappeared" not in types

    def test_incomplete_identity_not_merged_across_gaps(self, machine):
        result = lambda: scan_result([raw_tcp(7000, 50)], [pinfo(50, "mystery", create_time=None)])  # noqa: E731
        run(machine, result())
        run(machine, result())
        assert ProcessInstance.objects.filter(pid=50).count() == 1
        proc = ProcessInstance.objects.get(pid=50)
        assert not proc.identity_complete and proc.create_time is None
        run(machine, scan_result([], []))  # gone
        run(machine, result())  # PID seen again: cannot prove it is the same process
        assert ProcessInstance.objects.filter(pid=50).count() == 2

    def test_reappearing_endpoint_reactivates_same_row(self, machine):
        run(machine, scan_result([raw_tcp(8080, 100)], [pinfo(100)]))
        run(machine, scan_result([], []))
        run(machine, scan_result([raw_tcp(8080, 100)], [pinfo(100)]))
        assert Socket.objects.count() == 1 and Socket.objects.get().active
        assert ProcessInstance.objects.count() == 1 and ProcessInstance.objects.get().active

    def test_exited_process_socket_kept_with_unresolved_owner(self, machine):
        info = pinfo(77, create_time=None)
        info.exited = True
        run(machine, scan_result([raw_tcp(6000, 77)], [info]))
        sock = Socket.objects.get(port=6000)
        assert sock.process is None and sock.pid == 77 and sock.key.endswith("pid:77")

    def test_unknown_owner_socket(self, machine):
        summary = run(machine, scan_result([raw_tcp(135, None)], []))
        assert summary.unknown_owners == 1
        assert Socket.objects.get().key.endswith("|unknown")

    def test_metadata_never_erased_by_later_access_denied(self, machine):
        run(machine, scan_result([raw_tcp(8080, 100)], [pinfo(100, exe="/opt/web")]))
        denied = pinfo(100, exe=None)
        denied.exe = None
        denied.errors = {"exe": "access_denied"}
        run(machine, scan_result([raw_tcp(8080, 100)], [denied]))
        proc = ProcessInstance.objects.get()
        assert proc.exe == "/opt/web"
        assert proc.metadata_errors == {"exe": "access_denied"}

    def test_status_transition_events_only_on_change(self, machine):
        run(machine, scan_result([raw_tcp(1, 1)], [pinfo(1)]))
        marker = last_event_id()
        for _ in range(3):
            run(machine, scan_result([], [], error="boom"))
        assert event_types(marker) == ["scan.status_changed"]
        run(machine, scan_result([raw_tcp(1, 1)], [pinfo(1)]))
        assert event_types(marker) == ["scan.status_changed", "scan.status_changed"]

    def test_interrupted_scans_marked_failed(self, machine):
        begin_scan(machine, kind="native", trigger="scheduled", provider="fake")
        assert fail_interrupted_scans(machine) == 1
        assert DiscoveryScan.objects.get().status == "failed"
