"""E5 fleet-simulator tests: the FR-012 fleet thresholds measured against
the in-process simulator — p99 convergence ≤5 minutes, 100% digest
reporting, sessions pinned to one manifest, candidate state namespaced
and unable to write incumbent memory."""

from __future__ import annotations

import pytest
from tests.release.conftest import digest

from evoruntime.release import (
    CANDIDATE_NAMESPACE,
    INCUMBENT_NAMESPACE,
    CompressedClock,
    DigestReportingError,
    InProcessFleetSimulator,
    NamespaceViolationError,
    SessionPinError,
    UnknownSessionError,
)


class TestConvergence:
    def test_p99_convergence_within_5_minutes(
        self, fleet: InProcessFleetSimulator, clock: CompressedClock
    ) -> None:
        # FR-012: fleet p99 convergence to the prior manifest ≤5 minutes.
        # The seeded latency distribution has a realistic tail (5% of
        # workers take 120–290s); the measured p99 must still fit.
        fleet.set_active(digest(2))
        fleet.invalidate_caches(digest(2))
        clock.advance(300.0)

        p99 = fleet.p99_convergence_seconds()
        assert fleet.converged_fraction() == 1.0
        assert p99 <= 300.0, f"p99 convergence {p99:.1f}s exceeds the 5-minute bound"

    def test_convergence_is_gradual_not_instant(
        self, fleet: InProcessFleetSimulator, clock: CompressedClock
    ) -> None:
        fleet.set_active(digest(2))
        fleet.invalidate_caches(digest(2))

        # No time has passed: workers are still holding stale caches.
        assert fleet.converged_fraction() < 1.0

        clock.advance(300.0)
        assert fleet.converged_fraction() == 1.0

    def test_workers_converge_to_the_invalidated_digest(
        self, fleet: InProcessFleetSimulator, clock: CompressedClock
    ) -> None:
        fleet.set_active(digest(1))
        fleet.invalidate_caches(digest(1))
        clock.advance(300.0)
        assert fleet.converged_workers() == fleet.worker_count

        fleet.invalidate_caches(digest(3))
        assert fleet.converged_fraction() == 0.0
        clock.advance(300.0)
        assert fleet.converged_fraction() == 1.0


class TestDigestReporting:
    def test_all_sessions_report_their_resolved_digest(
        self, fleet: InProcessFleetSimulator
    ) -> None:
        # FR-012: 100% of reachable workers report the resolved digest.
        for i in range(20):
            session_id = f"session-{i}"
            fleet.pin_session(session_id, digest(1))
            fleet.report_digest(session_id, fleet.resolve_manifest(session_id))

        assert fleet.digest_report_coverage() == 1.0
        assert len(fleet.digest_reports()) == 20
        assert all(r.reported_digest == digest(1) for r in fleet.digest_reports())

    def test_contradictory_report_refused(self, fleet: InProcessFleetSimulator) -> None:
        fleet.pin_session("session-1", digest(1))

        with pytest.raises(DigestReportingError, match="reported digest"):
            fleet.report_digest("session-1", digest(2))

        # The refused report left no entry — the honesty ledger stays clean.
        assert fleet.digest_reports() == ()

    def test_unpinned_session_refused(self, fleet: InProcessFleetSimulator) -> None:
        with pytest.raises(UnknownSessionError, match="not pinned"):
            fleet.resolve_manifest("ghost-session")


class TestSessionPinning:
    def test_session_cannot_repin_to_a_different_manifest(
        self, fleet: InProcessFleetSimulator
    ) -> None:
        fleet.pin_session("session-1", digest(1))

        with pytest.raises(SessionPinError, match="pinned to"):
            fleet.pin_session("session-1", digest(2))

        assert fleet.resolve_manifest("session-1") == digest(1)

    def test_pinned_session_holds_its_manifest_after_pointer_moves(
        self, fleet: InProcessFleetSimulator, clock: CompressedClock
    ) -> None:
        fleet.pin_session("session-1", digest(1))

        # The pointer moves and the fleet converges to the new digest;
        # the pinned session keeps serving what it was pinned to.
        fleet.invalidate_caches(digest(2))
        clock.advance(300.0)

        assert fleet.resolve_manifest("session-1") == digest(1)

    def test_repin_to_same_manifest_is_a_noop(self, fleet: InProcessFleetSimulator) -> None:
        fleet.pin_session("session-1", digest(1))
        fleet.pin_session("session-1", digest(1))

        assert fleet.resolve_manifest("session-1") == digest(1)


class TestNamespacedCandidateState:
    def test_candidate_session_cannot_write_incumbent_memory(
        self, fleet: InProcessFleetSimulator
    ) -> None:
        fleet.pin_session("cand-1", digest(2), arm="candidate")

        with pytest.raises(NamespaceViolationError, match="incumbent"):
            fleet.write_state("cand-1", "poison", "value", namespace=INCUMBENT_NAMESPACE)

        # Incumbent memory is untouched.
        assert fleet.memory_keys(namespace=INCUMBENT_NAMESPACE) == ()

    def test_candidate_state_lands_in_the_candidate_namespace(
        self, fleet: InProcessFleetSimulator
    ) -> None:
        fleet.pin_session("cand-1", digest(2), arm="candidate")
        fleet.pin_session("inc-1", digest(1), arm="incumbent")

        fleet.write_state("cand-1", "scratch", {"k": 1}, namespace=CANDIDATE_NAMESPACE)
        fleet.write_state("inc-1", "official", {"k": 2}, namespace=INCUMBENT_NAMESPACE)

        assert fleet.read_state("scratch", namespace=CANDIDATE_NAMESPACE) == {"k": 1}
        assert fleet.read_state("scratch", namespace=INCUMBENT_NAMESPACE) is None
        assert fleet.read_state("official", namespace=INCUMBENT_NAMESPACE) == {"k": 2}
        assert fleet.read_state("official", namespace=CANDIDATE_NAMESPACE) is None

    def test_incumbent_session_writes_incumbent_namespace(
        self, fleet: InProcessFleetSimulator
    ) -> None:
        fleet.pin_session("inc-1", digest(1), arm="incumbent")

        with pytest.raises(NamespaceViolationError, match="candidate"):
            fleet.write_state("inc-1", "x", 1, namespace=CANDIDATE_NAMESPACE)
