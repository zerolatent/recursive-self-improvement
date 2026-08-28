"""FR-021 invalidation triggers: the policy that un-serves a release.

A release is only as valid as the world it was evaluated in. When that
world moves — the model behind an alias changes, a tool's API breaks, a
dependency ships a CVE, the evaluator changes, the release expires, the
environment drifts — the release's evidence no longer covers it, and the
policy decides the response: re-evaluate, quarantine, or roll back.

The mapping is policy *data*, not scattered conditionals: one table says
which trigger fires which action, and the executor applies it. Rollback
is the only action that touches the pointer, and it goes through the
release controller — the same root-of-trust CAS as activation, so an
invalidation can never move the release by a path the audit log missed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from evoruntime.release.controller import ReleaseController
from evoruntime.release.fleet import FleetAdapter
from evoruntime.release.manifest import SignedReleaseManifest


class InvalidationTrigger(StrEnum):
    """The FR-021 conditions that invalidate a release's evidence."""

    MODEL_ALIAS_DRIFT = "model_alias_drift"
    """The model behind a routed alias changed under the release."""

    TOOL_API_CHANGE = "tool_api_change"
    """A tool the release depends on changed its API."""

    DEPENDENCY_CVE = "dependency_cve"
    """A dependency in the release's resolved set has a known CVE."""

    EVALUATOR_CHANGE = "evaluator_change"
    """The evaluation instrument changed — old evidence no longer measures
    this release."""

    EXPIRY = "expiry"
    """The release's evaluation has aged past its validity window."""

    ENVIRONMENT_DRIFT = "environment_drift"
    """The runtime environment no longer matches what was evaluated."""


class InvalidationAction(StrEnum):
    """The FR-021 responses, ordered by how much they restrict the release."""

    RE_EVALUATE = "re_evaluate"
    """Evidence is stale but nothing is wrong: re-run evaluation before
    the release is trusted again."""

    QUARANTINE = "quarantine"
    """Pull the release from circulation pending re-evaluation — it may
    not serve new traffic, but the pointer does not move."""

    ROLLBACK = "roll_back"
    """The release is unsafe or its environment is gone: return to the
    prior release immediately."""


#: The default FR-021 policy: which trigger fires which action. Security
#: and environment-integrity triggers roll back; measurement-integrity
#: triggers re-evaluate; availability-integrity triggers quarantine.
DEFAULT_INVALIDATION_POLICY: Final[Mapping[InvalidationTrigger, InvalidationAction]] = {
    InvalidationTrigger.MODEL_ALIAS_DRIFT: InvalidationAction.RE_EVALUATE,
    InvalidationTrigger.TOOL_API_CHANGE: InvalidationAction.QUARANTINE,
    InvalidationTrigger.DEPENDENCY_CVE: InvalidationAction.ROLLBACK,
    InvalidationTrigger.EVALUATOR_CHANGE: InvalidationAction.RE_EVALUATE,
    InvalidationTrigger.EXPIRY: InvalidationAction.QUARANTINE,
    InvalidationTrigger.ENVIRONMENT_DRIFT: InvalidationAction.ROLLBACK,
}


@dataclass(frozen=True, slots=True)
class InvalidationSignal:
    """One observed trigger, with when and what."""

    trigger: InvalidationTrigger
    observed_at: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class InvalidationDecision:
    """One trigger's policy outcome for one manifest."""

    manifest_digest: str
    trigger: InvalidationTrigger
    action: InvalidationAction
    detail: str = ""


#: Strongest action wins when several signals land at once: rollback
#: restricts most, quarantine next, re-evaluate least.
_ACTION_SEVERITY: Final[Mapping[InvalidationAction, int]] = {
    InvalidationAction.RE_EVALUATE: 0,
    InvalidationAction.QUARANTINE: 1,
    InvalidationAction.ROLLBACK: 2,
}


def evaluate_invalidation(
    policy: Mapping[InvalidationTrigger, InvalidationAction],
    manifest: SignedReleaseManifest,
    signals: Sequence[InvalidationSignal],
) -> tuple[InvalidationDecision, ...]:
    """Map each signal to its policy action for ``manifest``.

    Pure function: signals in, decisions out, no state touched. A
    trigger missing from the policy is a KeyError by design — a policy
    that cannot answer for a trigger is a gap to fix, not a default to
    guess.
    """
    return tuple(
        InvalidationDecision(
            manifest_digest=manifest.manifest_digest,
            trigger=signal.trigger,
            action=policy[signal.trigger],
            detail=signal.detail,
        )
        for signal in signals
    )


def strongest_action(decisions: Sequence[InvalidationDecision]) -> InvalidationAction | None:
    """The most restrictive action among the decisions (None if empty)."""
    if not decisions:
        return None
    return max(decisions, key=lambda d: _ACTION_SEVERITY[d.action]).action


class ReleaseInvalidator:
    """Applies FR-021 invalidation decisions to a live release.

    Only ROLLBACK touches the pointer — through the release controller's
    CAS, so the move is atomic and audited like every other pointer
    move. Quarantine and re-evaluate are recorded decisions: they
    restrict the release through the evaluation plane, not the pointer.
    """

    def __init__(self, controller: ReleaseController, fleet: FleetAdapter) -> None:
        self._controller = controller
        self._fleet = fleet

    def handle(
        self,
        manifest: SignedReleaseManifest,
        signals: Sequence[InvalidationSignal],
        *,
        policy: Mapping[InvalidationTrigger, InvalidationAction] | None = None,
    ) -> tuple[InvalidationDecision, ...]:
        """Evaluate the signals and apply the resulting policy.

        A rollback decision CASes the pointer back to the manifest's
        prior release and invalidates fleet caches so workers converge
        to it. Returns every decision taken, in signal order.
        """
        decisions = evaluate_invalidation(policy or DEFAULT_INVALIDATION_POLICY, manifest, signals)
        if strongest_action(decisions) is InvalidationAction.ROLLBACK:
            self._controller.rollback(manifest)
            prior = manifest.prior_release_digest
            if prior is not None:
                self._fleet.invalidate_caches(prior)
        return decisions


__all__ = [
    "DEFAULT_INVALIDATION_POLICY",
    "InvalidationAction",
    "InvalidationDecision",
    "InvalidationSignal",
    "InvalidationTrigger",
    "ReleaseInvalidator",
    "evaluate_invalidation",
    "strongest_action",
]
