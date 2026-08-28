"""E5 rollback-under-load tests: a rollback issued while the fleet is
actively serving both canary arms moves the pointer atomically, converges
the fleet back to the incumbent within the FR-012 p99 bound, keeps pinned
sessions on their manifests, and never leaves a session resolving a mix."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.release.conftest import digest, make_manifest

from evoruntime.release import (
    CompressedClock,
    InProcessFleetSimulator,
    ReleaseController,
    SignedReleaseManifest,
)


def _mid_canary_state(
    controller: ReleaseController,
    fleet: InProcessFleetSimulator,
    clock: CompressedClock,
    signing_key: Ed25519PrivateKey,
) -> tuple[SignedReleaseManifest, SignedReleaseManifest, list[str], list[str]]:
    """A canary in flight: incumbent active, candidate activated, both
    arms pinned, some tasks run, fleet not yet converged to the candidate."""
    incumbent = make_manifest(signing_key, artifact_digests=[digest(1), digest(2)])
    controller.activate(incumbent)
    candidate = make_manifest(
        signing_key,
        artifact_digests=[digest(3), digest(4)],
        prior_release_digest=incumbent.manifest_digest,
    )
    controller.activate(candidate)

    incumbent_sessions = [f"inc-{i}" for i in range(8)]
    candidate_sessions = [f"cand-{i}" for i in range(4)]
    for session_id in incumbent_sessions:
        fleet.pin_session(session_id, incumbent.manifest_digest, arm="incumbent")
    for session_id in candidate_sessions:
        fleet.pin_session(session_id, candidate.manifest_digest, arm="candidate")

    # Some work happened under the candidate; the fleet is mid-flight.
    clock.advance(60.0)
    return incumbent, candidate, incumbent_sessions, candidate_sessions


class TestRollbackUnderLoad:
    def test_rollback_mid_canary_restores_incumbent(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent, candidate, _, _ = _mid_canary_state(controller, fleet, clock, signing_key)

        controller.rollback(candidate)

        assert controller.active_digest() == incumbent.manifest_digest

    def test_pinned_sessions_keep_their_manifest_through_rollback(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent, candidate, incumbent_sessions, candidate_sessions = _mid_canary_state(
            controller, fleet, clock, signing_key
        )
        controller.rollback(candidate)
        fleet.invalidate_caches(incumbent.manifest_digest)
        clock.advance(300.0)

        # Pinning is a safety property, not a convenience: in-flight
        # sessions finish on the manifest they started with.
        for session_id in incumbent_sessions:
            assert fleet.resolve_manifest(session_id) == incumbent.manifest_digest
        for session_id in candidate_sessions:
            assert fleet.resolve_manifest(session_id) == candidate.manifest_digest

    def test_new_sessions_resolve_incumbent_after_rollback(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent, candidate, _, _ = _mid_canary_state(controller, fleet, clock, signing_key)
        controller.rollback(candidate)
        fleet.invalidate_caches(incumbent.manifest_digest)
        clock.advance(300.0)

        for i in range(10):
            session_id = f"post-rollback-{i}"
            fleet.pin_session(session_id, controller.active_digest())
            assert fleet.resolve_manifest(session_id) == incumbent.manifest_digest
            assert fleet.resolve_manifest(session_id) != candidate.manifest_digest

    def test_fleet_converges_to_incumbent_within_p99_bound(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent, candidate, _, _ = _mid_canary_state(controller, fleet, clock, signing_key)
        controller.rollback(candidate)
        fleet.invalidate_caches(incumbent.manifest_digest)

        clock.advance(300.0)

        assert fleet.converged_fraction() == 1.0
        assert fleet.p99_convergence_seconds() <= 300.0

    def test_digest_reporting_stays_100_percent_after_rollback(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent, candidate, incumbent_sessions, candidate_sessions = _mid_canary_state(
            controller, fleet, clock, signing_key
        )
        controller.rollback(candidate)
        fleet.invalidate_caches(incumbent.manifest_digest)
        clock.advance(300.0)

        # Every live session — incumbent and surviving candidate arms —
        # reports the digest it actually resolved.
        for session_id in incumbent_sessions + candidate_sessions:
            fleet.report_digest(session_id, fleet.resolve_manifest(session_id))

        assert fleet.digest_report_coverage() == 1.0
        reported = {r.session_id: r.reported_digest for r in fleet.digest_reports()}
        assert reported["inc-0"] == incumbent.manifest_digest
        assert reported["cand-0"] == candidate.manifest_digest

    def test_no_session_ever_resolves_a_mixed_manifest(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent, candidate, incumbent_sessions, candidate_sessions = _mid_canary_state(
            controller, fleet, clock, signing_key
        )
        controller.rollback(candidate)
        fleet.invalidate_caches(incumbent.manifest_digest)
        clock.advance(300.0)

        # A session resolves exactly one digest — never a blend of the
        # candidate's artifacts and the incumbent's.
        for session_id in incumbent_sessions + candidate_sessions:
            resolved = fleet.resolve_manifest(session_id)
            assert resolved in (incumbent.manifest_digest, candidate.manifest_digest)
