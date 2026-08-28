"""E5 FR-021 invalidation tests: one test per invalidation trigger —
model alias drift, tool/API change, dependency CVE, evaluator change,
expiry, environment drift — each mapped to its policy action
(re-evaluate / quarantine / rollback), plus the executor's pointer and
cache behavior for the rollback action."""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.release.conftest import digest, make_manifest

from evoruntime.release import (
    DEFAULT_INVALIDATION_POLICY,
    CompressedClock,
    InProcessFleetSimulator,
    InvalidationAction,
    InvalidationDecision,
    InvalidationSignal,
    InvalidationTrigger,
    ReleaseController,
    ReleaseInvalidator,
    SignedReleaseManifest,
    strongest_action,
)

OBSERVED_AT = "2026-08-28T12:00:00Z"


def _active_release(
    controller: ReleaseController, signing_key: Ed25519PrivateKey
) -> SignedReleaseManifest:
    incumbent = make_manifest(signing_key, artifact_digests=[digest(1), digest(2)])
    controller.activate(incumbent)
    return incumbent


def _invalidator(
    controller: ReleaseController, fleet: InProcessFleetSimulator
) -> ReleaseInvalidator:
    return ReleaseInvalidator(controller=controller, fleet=fleet)


def _signal(trigger: InvalidationTrigger, detail: str) -> InvalidationSignal:
    return InvalidationSignal(trigger=trigger, observed_at=OBSERVED_AT, detail=detail)


def _decision(action: InvalidationAction) -> InvalidationDecision:
    return InvalidationDecision(
        manifest_digest=digest(0), trigger=InvalidationTrigger.EXPIRY, action=action
    )


class TestInvalidationTriggers:
    """One test per FR-021 trigger, each asserting its policy action."""

    def test_model_alias_drift_triggers_re_evaluate(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent = _active_release(controller, signing_key)
        invalidator = _invalidator(controller, fleet)

        decisions = invalidator.handle(
            incumbent,
            [_signal(InvalidationTrigger.MODEL_ALIAS_DRIFT, "alias 'fast' now resolves elsewhere")],
        )

        assert len(decisions) == 1
        assert decisions[0].action is InvalidationAction.RE_EVALUATE
        assert decisions[0].trigger is InvalidationTrigger.MODEL_ALIAS_DRIFT

    def test_tool_api_change_triggers_quarantine(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent = _active_release(controller, signing_key)
        invalidator = _invalidator(controller, fleet)

        decisions = invalidator.handle(
            incumbent,
            [_signal(InvalidationTrigger.TOOL_API_CHANGE, "tool 'repo.search' signature changed")],
        )

        assert decisions[0].action is InvalidationAction.QUARANTINE

    def test_dependency_cve_triggers_rollback(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent = _active_release(controller, signing_key)
        candidate = make_manifest(
            signing_key,
            artifact_digests=[digest(9)],
            prior_release_digest=incumbent.manifest_digest,
        )
        controller.activate(candidate)
        invalidator = _invalidator(controller, fleet)

        decisions = invalidator.handle(
            candidate,
            [_signal(InvalidationTrigger.DEPENDENCY_CVE, "CVE-2026-1234 in pinned dependency")],
        )

        assert decisions[0].action is InvalidationAction.ROLLBACK
        assert controller.active_digest() == incumbent.manifest_digest

    def test_evaluator_change_triggers_re_evaluate(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent = _active_release(controller, signing_key)
        invalidator = _invalidator(controller, fleet)

        decisions = invalidator.handle(
            incumbent,
            [_signal(InvalidationTrigger.EVALUATOR_CHANGE, "evaluator bundle digest changed")],
        )

        assert decisions[0].action is InvalidationAction.RE_EVALUATE

    def test_expiry_triggers_quarantine(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent = _active_release(controller, signing_key)
        invalidator = _invalidator(controller, fleet)

        decisions = invalidator.handle(
            incumbent, [_signal(InvalidationTrigger.EXPIRY, "release TTL elapsed")]
        )

        assert decisions[0].action is InvalidationAction.QUARANTINE

    def test_environment_drift_triggers_rollback(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent = _active_release(controller, signing_key)
        candidate = make_manifest(
            signing_key,
            artifact_digests=[digest(9)],
            prior_release_digest=incumbent.manifest_digest,
        )
        controller.activate(candidate)
        invalidator = _invalidator(controller, fleet)

        decisions = invalidator.handle(
            candidate,
            [_signal(InvalidationTrigger.ENVIRONMENT_DRIFT, "base image digest drifted")],
        )

        assert decisions[0].action is InvalidationAction.ROLLBACK
        assert controller.active_digest() == incumbent.manifest_digest


class TestInvalidationPolicy:
    def test_every_trigger_has_a_policy_entry(self) -> None:
        # A new trigger without a policy would silently no-op — refuse it.
        assert set(DEFAULT_INVALIDATION_POLICY) == set(InvalidationTrigger)

    def test_strongest_action_wins_when_triggers_co_occur(self) -> None:
        decisions = [
            _decision(InvalidationAction.RE_EVALUATE),
            _decision(InvalidationAction.QUARANTINE),
            _decision(InvalidationAction.ROLLBACK),
        ]
        assert strongest_action(decisions) is InvalidationAction.ROLLBACK
        assert (
            strongest_action(
                [
                    _decision(InvalidationAction.RE_EVALUATE),
                    _decision(InvalidationAction.QUARANTINE),
                ]
            )
            is InvalidationAction.QUARANTINE
        )
        assert strongest_action([]) is None

    def test_rollback_action_invalidates_fleet_caches(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent = _active_release(controller, signing_key)
        candidate = make_manifest(
            signing_key,
            artifact_digests=[digest(9)],
            prior_release_digest=incumbent.manifest_digest,
        )
        controller.activate(candidate)
        invalidator = _invalidator(controller, fleet)

        invalidator.handle(
            candidate, [_signal(InvalidationTrigger.DEPENDENCY_CVE, "CVE-2026-1234")]
        )
        clock.advance(300.0)

        # The rollback is not just a pointer move: the fleet is told to
        # drop caches and converges back to the incumbent.
        assert fleet.converged_fraction() == 1.0
        assert fleet.p99_convergence_seconds() <= 300.0

    def test_quarantine_does_not_move_the_pointer(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent = _active_release(controller, signing_key)
        invalidator = _invalidator(controller, fleet)

        decisions = invalidator.handle(
            incumbent, [_signal(InvalidationTrigger.EXPIRY, "TTL elapsed")]
        )

        assert decisions[0].action is InvalidationAction.QUARANTINE
        assert controller.active_digest() == incumbent.manifest_digest
