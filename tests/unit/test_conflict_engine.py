from portregistry.services.conflicts import (
    ConflictType,
    DiscoveryView,
    DockerMappingView,
    ReservationView,
    ServiceView,
    Snapshot,
    SocketView,
    check_candidate,
    detect_conflicts,
    directory_matches,
    executable_matches,
)

FRESH = DiscoveryView(
    native_status="complete",
    complete_protocols=frozenset({"tcp", "udp"}),
    last_complete_age=1.0,
    stale_after=35.0,
)


def sock(
    id_,
    port,
    address="0.0.0.0",
    protocol="tcp",
    name="node",
    exe=None,
    pid=100,
    cwd=None,
    family=None,
):
    return SocketView(
        id=id_,
        protocol=protocol,
        family=family or ("ipv6" if ":" in address else "ipv4"),
        address=address,
        port=port,
        pid=pid,
        process_id=pid,
        process_name=name,
        exe=exe or (f"/usr/bin/{name}" if name else None),
        cwd=cwd,
    )


def res(id_, port, address="*", protocol="tcp", service_id=None):
    return ReservationView(
        id=id_, protocol=protocol, bind_address=address, port=port, service_id=service_id
    )


def types(findings):
    return [f.type for f in findings if f.type is not ConflictType.INCOMPLETE_DISCOVERY]


def by_type(findings, t):
    return [f for f in findings if f.type is t]


class TestMatching:
    def test_executable_basename_match_case_insensitive_and_exe_suffix(self):
        assert executable_matches("postgres", r"C:\PG\bin\postgres.exe", "postgres.exe") is True
        assert (
            executable_matches("Postgres.EXE", "/usr/lib/postgresql/16/bin/postgres", None) is True
        )
        assert executable_matches("postgres", "/usr/sbin/mysqld", "mysqld") is False

    def test_executable_full_path(self):
        assert executable_matches("/opt/app/server", "/opt/app/server", "server") is True
        assert executable_matches("/opt/app/server", "/opt/other/server", "server") is False
        # Path expectation but exe unreadable and name matches: cannot verify.
        assert executable_matches("/opt/app/server", None, "server") is None
        assert executable_matches("/opt/app/server", None, "nginx") is False

    def test_unknown_metadata_is_not_a_mismatch(self):
        assert executable_matches("postgres", None, None) is None
        assert executable_matches("", "/x", "x") is None

    def test_directory_match(self):
        assert directory_matches("C:\\srv\\app\\", "c:/srv/app") is True
        assert directory_matches("/srv/a", "/srv/b") is False
        assert directory_matches("/srv/a", None) is None


class TestReservationConflicts:
    def test_occupied_reservation_without_service(self):
        snap = Snapshot(sockets=[sock(1, 8080)], reservations=[res(1, 8080)], discovery=FRESH)
        findings = detect_conflicts(snap)
        occupied = by_type(findings, ConflictType.OCCUPIED_RESERVATION)
        assert len(occupied) == 1
        f = occupied[0]
        assert f.severity == "warning" and f.certainty == "definite"
        assert "node (pid 100)" in f.explanation
        assert f.evidence["occupants"][0]["socket_id"] == 1
        # Covered by a reservation -> not an unregistered listener.
        assert not by_type(findings, ConflictType.UNREGISTERED_LISTENER)

    def test_tcp_and_udp_on_same_port_do_not_conflict(self):
        snap = Snapshot(
            sockets=[sock(1, 53, protocol="udp")],
            reservations=[res(1, 53, protocol="tcp")],
            discovery=FRESH,
        )
        findings = detect_conflicts(snap)
        assert not by_type(findings, ConflictType.OCCUPIED_RESERVATION)
        assert by_type(findings, ConflictType.UNREGISTERED_LISTENER)  # the UDP socket is uncovered

    def test_ipv4_wildcard_listener_overlaps_loopback_reservation(self):
        snap = Snapshot(
            sockets=[sock(1, 5000, "0.0.0.0")],
            reservations=[res(1, 5000, "127.0.0.1")],
            discovery=FRESH,
        )
        f = by_type(detect_conflicts(snap), ConflictType.OCCUPIED_RESERVATION)[0]
        assert f.certainty == "definite"
        assert "wildcard 0.0.0.0" in f.evidence["occupants"][0]["overlap_reason"]

    def test_ipv6_wildcard_vs_ipv4_is_potential(self):
        snap = Snapshot(
            sockets=[sock(1, 5000, "::")], reservations=[res(1, 5000, "127.0.0.1")], discovery=FRESH
        )
        f = by_type(detect_conflicts(snap), ConflictType.OCCUPIED_RESERVATION)[0]
        assert f.certainty == "potential"
        assert "dual-stack" in f.explanation

    def test_different_specific_addresses_do_not_conflict(self):
        snap = Snapshot(
            sockets=[sock(1, 5000, "192.168.1.5")],
            reservations=[res(1, 5000, "127.0.0.1")],
            discovery=FRESH,
        )
        assert not by_type(detect_conflicts(snap), ConflictType.OCCUPIED_RESERVATION)

    def test_service_match_produces_no_conflict(self):
        svc = ServiceView(1, "db", expected_executable="postgres")
        snap = Snapshot(
            sockets=[sock(1, 5432, name="postgres")],
            reservations=[res(1, 5432, service_id=1)],
            services={1: svc},
            discovery=FRESH,
        )
        assert types(detect_conflicts(snap)) == []

    def test_service_mismatch(self):
        svc = ServiceView(1, "db", expected_executable="postgres")
        snap = Snapshot(
            sockets=[sock(1, 5432, name="mysqld"), sock(2, 5432, "::", name="mysqld")],
            reservations=[res(1, 5432, service_id=1)],
            services={1: svc},
            discovery=FRESH,
        )
        f = by_type(detect_conflicts(snap), ConflictType.SERVICE_MISMATCH)[0]
        assert f.severity == "error" and f.certainty == "definite"
        assert f.explanation.count("expected executable 'postgres'") == 1  # de-duplicated
        assert f.evidence["expected_executable"] == "postgres"

    def test_working_directory_mismatch(self):
        svc = ServiceView(
            1, "api", expected_executable="python", expected_working_directory="/srv/api"
        )
        snap = Snapshot(
            sockets=[sock(1, 8000, name="python", cwd="/srv/other")],
            reservations=[res(1, 8000, service_id=1)],
            services={1: svc},
            discovery=FRESH,
        )
        f = by_type(detect_conflicts(snap), ConflictType.SERVICE_MISMATCH)[0]
        assert "working directory" in f.explanation

    def test_unverifiable_owner_is_potential_not_mismatch(self):
        svc = ServiceView(1, "db", expected_executable="postgres")
        hidden = SocketView(
            id=1, protocol="tcp", family="ipv4", address="0.0.0.0", port=5432, pid=4
        )
        snap = Snapshot(
            sockets=[hidden],
            reservations=[res(1, 5432, service_id=1)],
            services={1: svc},
            discovery=FRESH,
        )
        findings = detect_conflicts(snap)
        assert not by_type(findings, ConflictType.SERVICE_MISMATCH)
        f = by_type(findings, ConflictType.OCCUPIED_RESERVATION)[0]
        assert f.certainty == "potential" and f.severity == "warning"

    def test_service_without_expectations_is_informational(self):
        svc = ServiceView(1, "thing")
        snap = Snapshot(
            sockets=[sock(1, 9000)],
            reservations=[res(1, 9000, service_id=1)],
            services={1: svc},
            discovery=FRESH,
        )
        f = by_type(detect_conflicts(snap), ConflictType.OCCUPIED_RESERVATION)[0]
        assert f.severity == "info"
        assert "Add an expected executable" in f.explanation


class TestMissingService:
    def test_missing_expected_service_definite_after_complete_scan(self):
        svc = ServiceView(1, "db", expected_executable="postgres")
        snap = Snapshot(
            reservations=[res(1, 5432, service_id=1)], services={1: svc}, discovery=FRESH
        )
        f = by_type(detect_conflicts(snap), ConflictType.MISSING_EXPECTED_SERVICE)[0]
        assert f.certainty == "definite" and f.severity == "warning"

    def test_missing_service_only_potential_when_scan_partial(self):
        partial = DiscoveryView(
            native_status="partial", complete_protocols=frozenset(), last_complete_age=1.0
        )
        svc = ServiceView(1, "db")
        snap = Snapshot(
            reservations=[res(1, 5432, service_id=1)], services={1: svc}, discovery=partial
        )
        f = by_type(detect_conflicts(snap), ConflictType.MISSING_EXPECTED_SERVICE)[0]
        assert f.certainty == "potential" and f.severity == "info"
        assert "not certain" in f.explanation

    def test_missing_service_potential_when_stale(self):
        stale = DiscoveryView(
            native_status="complete",
            complete_protocols=frozenset({"tcp", "udp"}),
            last_complete_age=999,
            stale_after=30,
        )
        svc = ServiceView(1, "db")
        snap = Snapshot(
            reservations=[res(1, 5432, service_id=1)], services={1: svc}, discovery=stale
        )
        f = by_type(detect_conflicts(snap), ConflictType.MISSING_EXPECTED_SERVICE)[0]
        assert f.certainty == "potential" and "stale" in f.explanation

    def test_reservation_without_service_and_no_listener_is_fine(self):
        snap = Snapshot(reservations=[res(1, 5432)], discovery=FRESH)
        assert types(detect_conflicts(snap)) == []


class TestOverlaps:
    def test_duplicate_reservation(self):
        snap = Snapshot(reservations=[res(1, 80), res(2, 80)], discovery=FRESH)
        f = by_type(detect_conflicts(snap), ConflictType.OVERLAPPING_RESERVATION)[0]
        assert f.title.startswith("Duplicate reservation") and f.evidence["duplicate"]
        assert (f.reservation_id, f.related_reservation_id) == (1, 2)

    def test_wildcard_overlap_between_reservations(self):
        snap = Snapshot(
            reservations=[
                res(1, 80, "0.0.0.0", service_id=1),
                res(2, 80, "127.0.0.1", service_id=2),
            ],
            discovery=FRESH,
        )
        f = by_type(detect_conflicts(snap), ConflictType.OVERLAPPING_RESERVATION)[0]
        assert f.certainty == "definite" and f.severity == "warning"

    def test_ipv6_wildcard_reservation_vs_ipv4_potential(self):
        snap = Snapshot(reservations=[res(1, 80, "::"), res(2, 80, "0.0.0.0")], discovery=FRESH)
        f = by_type(detect_conflicts(snap), ConflictType.OVERLAPPING_RESERVATION)[0]
        assert f.certainty == "potential" and f.severity == "info"

    def test_tcp_udp_reservations_independent(self):
        snap = Snapshot(
            reservations=[res(1, 53, protocol="tcp"), res(2, 53, protocol="udp")], discovery=FRESH
        )
        assert types(detect_conflicts(snap)) == []

    def test_candidate_check_reports_overlap_with_existing(self):
        snap = Snapshot(sockets=[sock(1, 80)], reservations=[res(5, 80)], discovery=FRESH)
        findings = check_candidate(res(0, 80, "127.0.0.1"), snap)
        kinds = {f.type for f in findings}
        assert ConflictType.OCCUPIED_RESERVATION in kinds
        assert ConflictType.OVERLAPPING_RESERVATION in kinds
        assert all(
            "proposed reservation" in f.explanation or "reservation #5" in f.explanation
            for f in findings
        )


class TestUnregisteredAndDiscovery:
    def test_unregistered_listener_is_info(self):
        snap = Snapshot(sockets=[sock(1, 3000)], discovery=FRESH)
        f = by_type(detect_conflicts(snap), ConflictType.UNREGISTERED_LISTENER)[0]
        assert f.severity == "info" and f.socket_id == 1 and "listening on" in f.explanation

    def test_udp_wording(self):
        snap = Snapshot(sockets=[sock(1, 5353, protocol="udp")], discovery=FRESH)
        assert (
            "bound to"
            in by_type(detect_conflicts(snap), ConflictType.UNREGISTERED_LISTENER)[0].explanation
        )

    def test_incomplete_discovery_findings(self):
        view = DiscoveryView(
            native_status="failed",
            native_message="boom",
            last_complete_age=None,
            unknown_owner_count=2,
            restricted_process_count=3,
            docker_enabled=True,
            docker_state="unavailable",
            docker_message="Docker daemon is not reachable.",
        )
        fps = {f.fingerprint for f in detect_conflicts(Snapshot(discovery=view))}
        assert fps == {
            "incomplete:native:failed",
            "incomplete:native:stale",
            "incomplete:native:resolution",
            "incomplete:docker",
        }

    def test_never_scanned(self):
        fps = {f.fingerprint for f in detect_conflicts(Snapshot())}
        assert "incomplete:native:none" in fps


class TestDocker:
    def mapping(self, name="web", image="nginx:alpine", port=8080):
        return DockerMappingView(
            id=1,
            container_db_id=1,
            container_id="abcdef1234567890",
            container_name=name,
            image_ref=image,
            protocol="tcp",
            host_ip="0.0.0.0",
            host_port=port,
            container_port=80,
        )

    def test_docker_mapping_occupies_reservation(self):
        snap = Snapshot(
            reservations=[res(1, 8080)], docker_mappings=[self.mapping()], discovery=FRESH
        )
        f = by_type(detect_conflicts(snap), ConflictType.OCCUPIED_RESERVATION)[0]
        assert f.evidence["occupants"][0]["kind"] == "docker"
        assert "container web" in f.explanation

    def test_docker_expectation_matches_container_and_proxy_socket(self):
        svc = ServiceView(1, "web", expected_executable="docker:nginx")
        proxy = sock(9, 8080, name="docker-proxy")
        snap = Snapshot(
            sockets=[proxy],
            reservations=[res(1, 8080, service_id=1)],
            services={1: svc},
            docker_mappings=[self.mapping()],
            discovery=FRESH,
        )
        assert types(detect_conflicts(snap)) == []

    def test_docker_expectation_mismatch(self):
        svc = ServiceView(1, "web", expected_executable="docker:redis")
        snap = Snapshot(
            reservations=[res(1, 8080, service_id=1)],
            services={1: svc},
            docker_mappings=[self.mapping()],
            discovery=FRESH,
        )
        assert by_type(detect_conflicts(snap), ConflictType.SERVICE_MISMATCH)


def test_findings_sorted_by_severity():
    svc = ServiceView(1, "db", expected_executable="postgres")
    snap = Snapshot(
        sockets=[sock(1, 5432, name="mysqld"), sock(2, 3000)],
        reservations=[res(1, 5432, service_id=1)],
        services={1: svc},
        discovery=FRESH,
    )
    severities = [f.severity for f in detect_conflicts(snap)]
    assert severities == sorted(severities, key={"error": 0, "warning": 1, "info": 2}.get)
