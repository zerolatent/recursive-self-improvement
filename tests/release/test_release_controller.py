"""E5 release-controller tests: the controller is the sole identity
permitted to CAS the active release pointer (FR-011), the signed manifest
is the atomic activation and rollback unit (PRD §9.2), and the pointer
CAS completes within 30 seconds (FR-012)."""

from __future__ import annotations

import dataclasses
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.release.conftest import (
    CANDIDATE_IDENTITY,
    EVALUATOR_IDENTITY,
    digest,
    make_manifest,
)

from evoruntime.release import (
    ReleaseController,
    RollbackUnavailableError,
    SignedReleaseManifest,
    UnsignedManifestError,
    verify_release_manifest,
)
from evoruntime.security.identities import WorkloadIdentity
from evoruntime.security.policy import PermissionDeniedError
from evoruntime.selection import CasConflictError, ReleasePointerStore


def _activate_incumbent(
    controller: ReleaseController, key: Ed25519PrivateKey
) -> SignedReleaseManifest:
    incumbent = make_manifest(key, artifact_digests=[digest(1), digest(2)])
    controller.activate(incumbent)
    return incumbent


class TestActivation:
    def test_activate_moves_pointer_to_the_whole_manifest(
        self, controller: ReleaseController, signing_key: Ed25519PrivateKey
    ) -> None:
        manifest = make_manifest(signing_key, artifact_digests=[digest(1), digest(2)])

        controller.activate(manifest)

        assert controller.active_digest() == manifest.manifest_digest

    def test_activation_is_one_atomic_cas(
        self,
        controller: ReleaseController,
        pointer_store: ReleasePointerStore,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        manifest = make_manifest(signing_key, artifact_digests=[digest(1), digest(2)])

        controller.activate(manifest)

        # One allowed CAS, one audit entry — the manifest moved as a unit;
        # there is no per-artifact pointer to move piecewise.
        entries = pointer_store.audit_log.entries()
        assert [e.outcome for e in entries] == ["allowed"]
        assert entries[0].new_digest == manifest.manifest_digest

    def test_cas_completes_within_30_seconds(
        self, controller: ReleaseController, signing_key: Ed25519PrivateKey
    ) -> None:
        # FR-012: active-pointer CAS ≤30s. Measured on the real clock over
        # a manifest with a realistic artifact count — signature
        # verification plus CAS, not just an empty-pointer fast path.
        manifest = make_manifest(signing_key, artifact_digests=[digest(i) for i in range(50)])

        start = time.monotonic()
        controller.activate(manifest)
        elapsed = time.monotonic() - start

        assert controller.active_digest() == manifest.manifest_digest
        assert elapsed < 30.0, f"activation took {elapsed:.3f}s — FR-012 allows ≤30s"

    def test_unsigned_manifest_refused_and_pointer_untouched(
        self, controller: ReleaseController, signing_key: Ed25519PrivateKey
    ) -> None:
        incumbent = _activate_incumbent(controller, signing_key)
        candidate = make_manifest(
            signing_key,
            artifact_digests=[digest(9)],
            prior_release_digest=incumbent.manifest_digest,
        )
        tampered = dataclasses.replace(candidate, signature=b"not-a-signature")

        with pytest.raises(UnsignedManifestError, match="no valid signature"):
            controller.activate(tampered)

        assert controller.active_digest() == incumbent.manifest_digest

    def test_tampered_body_refused(
        self, controller: ReleaseController, signing_key: Ed25519PrivateKey
    ) -> None:
        _activate_incumbent(controller, signing_key)
        candidate = make_manifest(signing_key, artifact_digests=[digest(9)])
        # Swap the resolved artifacts after signing — the signature no
        # longer covers the body, and the controller must notice.
        forged = dataclasses.replace(candidate, artifact_digests=(digest(10), digest(11)))

        with pytest.raises(UnsignedManifestError):
            verify_release_manifest(forged)
        with pytest.raises(UnsignedManifestError):
            controller.activate(forged)


class TestRollback:
    def test_rollback_returns_to_prior_release(
        self, controller: ReleaseController, signing_key: Ed25519PrivateKey
    ) -> None:
        incumbent = _activate_incumbent(controller, signing_key)
        candidate = make_manifest(
            signing_key,
            artifact_digests=[digest(9)],
            prior_release_digest=incumbent.manifest_digest,
        )
        controller.activate(candidate)

        controller.rollback(candidate)

        assert controller.active_digest() == incumbent.manifest_digest

    def test_rollback_without_prior_release_refused(
        self, controller: ReleaseController, signing_key: Ed25519PrivateKey
    ) -> None:
        root = make_manifest(signing_key, artifact_digests=[digest(1)])
        controller.activate(root)

        with pytest.raises(RollbackUnavailableError, match="no prior release"):
            controller.rollback(root)

    def test_rollback_conflicts_when_pointer_moved(
        self, controller: ReleaseController, signing_key: Ed25519PrivateKey
    ) -> None:
        incumbent = _activate_incumbent(controller, signing_key)
        first = make_manifest(
            signing_key,
            artifact_digests=[digest(9)],
            prior_release_digest=incumbent.manifest_digest,
        )
        second = make_manifest(
            signing_key,
            artifact_digests=[digest(10)],
            prior_release_digest=first.manifest_digest,
        )
        controller.activate(first)
        controller.activate(second)

        # Rolling back the *first* candidate now would move the pointer
        # from a release it is not at — refused; re-read reality instead.
        with pytest.raises(CasConflictError):
            controller.rollback(first)
        assert controller.active_digest() == second.manifest_digest


class TestCasAuthority:
    """The controller is the sole identity permitted to CAS (FR-011)."""

    @pytest.mark.parametrize("identity", [EVALUATOR_IDENTITY, CANDIDATE_IDENTITY])
    def test_non_controller_cas_denied_and_audited(
        self,
        controller: ReleaseController,
        pointer_store: ReleasePointerStore,
        signing_key: Ed25519PrivateKey,
        identity: WorkloadIdentity,
    ) -> None:
        incumbent = _activate_incumbent(controller, signing_key)

        with pytest.raises(PermissionDeniedError, match="compare-and-swap"):
            pointer_store.compare_and_swap(identity, incumbent.manifest_digest, digest(99))

        # Denied AND audited: evidence left, pointer did not move.
        entries = pointer_store.audit_log.entries()
        denial = entries[-1]
        assert denial.outcome == "denied"
        assert denial.actor_subject == identity.subject
        assert controller.active_digest() == incumbent.manifest_digest

    def test_controller_refuses_non_controller_identity(
        self, pointer_store: ReleasePointerStore
    ) -> None:
        with pytest.raises(PermissionDeniedError, match="operate the release controller"):
            ReleaseController(pointer_store, EVALUATOR_IDENTITY)

    def test_every_pointer_move_is_audited(
        self,
        controller: ReleaseController,
        pointer_store: ReleasePointerStore,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent = _activate_incumbent(controller, signing_key)
        candidate = make_manifest(
            signing_key,
            artifact_digests=[digest(9)],
            prior_release_digest=incumbent.manifest_digest,
        )
        controller.activate(candidate)
        controller.rollback(candidate)

        outcomes = [e.outcome for e in pointer_store.audit_log.entries()]
        # Three pointer moves, three audited CAS entries: activate the
        # incumbent, activate the candidate, roll back to the incumbent.
        assert outcomes == ["allowed", "allowed", "allowed"]
