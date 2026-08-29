"""The §12.6 recursive-claim gate, as policy code.

The gate's conditions — two successive promoted generations under a
shared preregistered error budget, causal inheritance, a matched-compute
one-shot advantage, a no-inheritance control arm, and (Phase 3, G4) the
RI-3/RI-4 fixed-editor advantage — are checked here, by code, so the
claim is a *verdict* rather than an adjective.

But a satisfied gate is still not enough to earn the label. Locked
decision #8: Phase 1 results are labeled "artifact optimization", never
"recursive improvement" — and Phase 3 (G4/G6) makes the enablement
*per-environment policy data* instead of a compile-time constant: the
tenant's :class:`~evoruntime.tenancy.policy.TenantPolicyDocument` carries
``recursive_claims_enabled``, its constructor refuses to enable the claim
in a production tenant, and the gate reads it from there. A tenant with
no policy document is unmapped, and unmapped is production (fail closed).
:func:`claim_label` is the only place a result's label is decided, so the
policy and the verdict cannot drift.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from evoruntime.selection.errors import RecursiveClaimDeniedError
from evoruntime.tenancy.policy import TenantPolicyDocument

ARTIFACT_OPTIMIZATION_LABEL = "artifact optimization"
RECURSIVE_IMPROVEMENT_LABEL = "recursive improvement"


@dataclass(frozen=True, slots=True)
class RecursiveClaimEvidence:
    """What the §12.6 gate is judged on."""

    successive_promoted_generations: bool
    """Two generations in a row were promoted, each via the full gate."""

    shared_error_budget: bool
    """Both generations ran under one preregistered error budget."""

    causal_inheritance: bool
    """Generation N+1's gain is causally attributable to inheriting
    generation N's artifacts (not to re-running the same search)."""

    matched_compute_one_shot_advantage: bool
    """The inherited line beats a one-shot control at matched compute."""

    no_inheritance_control_arm: bool
    """A control arm that did *not* inherit was run and did not show the
    same advantage."""

    fixed_editor_control_arm: bool = False
    """The incumbent scaffold was also evaluated under the frozen editor
    (the strategy plugin pinned at its incumbent-generation version) — the
    RI-3/RI-4 control arm. Without it the campaign has no denominator that
    separates the optimizer's contribution from the editor's."""

    fixed_editor_advantage: float | None = None
    """The numeric advantage of the inherited line over the fixed-editor
    arm, at matched compute. `None` means it was never measured — and an
    unmeasured advantage is not an advantage."""

    fixed_editor_minimum_effect: float | None = None
    """The preregistered minimum effect (RI-3): the advantage must clear
    this floor, fixed before any run. `None` means nothing was
    preregistered, so there is no floor to clear and the condition fails —
    an unpinned threshold defaults to failing, never to passing."""

    fixed_editor_holm_significant: bool = False
    """The fixed-editor comparison survived the shared Holm family
    adjustment (RI-4): its p-value was one member of the same
    multiplicity family as the campaign's other comparisons, and it
    remained significant after the step-down correction."""


@dataclass(frozen=True, slots=True)
class RecursiveClaimCondition:
    """One named §12.6 condition and the evidence that decided it."""

    condition: str
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class RecursiveClaimVerdict:
    """The gate's verdict over its conditions."""

    conditions: tuple[RecursiveClaimCondition, ...]

    @property
    def satisfied(self) -> bool:
        """True only when every §12.6 condition holds."""
        return bool(self.conditions) and all(c.passed for c in self.conditions)


def _fixed_editor_advantage_holds(evidence: RecursiveClaimEvidence) -> bool:
    """The §12.6 RI-3/RI-4 condition, as one predicate.

    Three facts must all hold: the control arm ran, the advantage is a
    real number above the preregistered minimum effect, and the comparison
    survived the shared Holm family. A `None` advantage, a NaN, or an
    unpreregistered minimum each fail — "numeric" is the spec's word, and
    a non-number or an unpinned floor cannot back a recursion claim.
    """
    if not evidence.fixed_editor_control_arm:
        return False
    advantage = evidence.fixed_editor_advantage
    minimum = evidence.fixed_editor_minimum_effect
    if advantage is None or minimum is None:
        return False
    if not math.isfinite(advantage) or not math.isfinite(minimum):
        return False
    if not advantage > minimum:
        return False
    return evidence.fixed_editor_holm_significant


def evaluate_recursive_claim(evidence: RecursiveClaimEvidence) -> RecursiveClaimVerdict:
    """Evaluate the §12.6 conditions. Pure policy code: no I/O, no
    thresholds to tune — each condition is a recorded fact or it is false."""
    conditions = (
        RecursiveClaimCondition(
            "two_successive_promoted_generations",
            evidence.successive_promoted_generations,
            "two generations in a row promoted through the full gate",
        ),
        RecursiveClaimCondition(
            "shared_preregistered_error_budget",
            evidence.shared_error_budget,
            "both generations ran under one preregistered error budget",
        ),
        RecursiveClaimCondition(
            "causal_inheritance",
            evidence.causal_inheritance,
            "the gain is attributable to inheriting the prior generation",
        ),
        RecursiveClaimCondition(
            "matched_compute_advantage_with_control",
            evidence.matched_compute_one_shot_advantage and evidence.no_inheritance_control_arm,
            "one-shot advantage at matched compute, with a no-inheritance control arm",
        ),
        RecursiveClaimCondition(
            "fixed_editor_advantage",
            _fixed_editor_advantage_holds(evidence),
            "numeric advantage over the frozen-editor control arm, above the "
            "preregistered minimum effect, inside the shared Holm family "
            "(§12.6 RI-3/RI-4)",
        ),
    )
    return RecursiveClaimVerdict(conditions=conditions)


def claim_label(
    verdict: RecursiveClaimVerdict | None,
    *,
    tenant_policy: TenantPolicyDocument | None = None,
) -> str:
    """The honest label for a result.

    "recursive improvement" requires the gate to be satisfied *and* the
    tenant's policy data to enable recursive claims (G4/G6). An absent
    policy document is an unmapped tenant, treated as production (fail
    closed): recursive-improvement claims are research-only, so a caller
    that cannot say which environment it is in does not get the label.
    A research tenant whose policy has not enabled the claim earns
    "artifact optimization" too — the environment is necessary, never
    sufficient; the enablement is the tenant's own policy decision.
    """
    if verdict is not None and verdict.satisfied and _claims_enabled(tenant_policy):
        return RECURSIVE_IMPROVEMENT_LABEL
    return ARTIFACT_OPTIMIZATION_LABEL


def assert_label_allowed(
    label: str,
    verdict: RecursiveClaimVerdict | None,
    *,
    tenant_policy: TenantPolicyDocument | None = None,
) -> None:
    """Refuse a 'recursive improvement' label the gate or the tenant's
    policy data does not back.

    Anything that renders a result — API, UI, report — routes its label
    through here, so a claim cannot slip past :func:`claim_label`. The
    policy check (G4/G6) is the recursive-label boundary: the label is
    refused unless the tenant's own policy document enables it, and an
    unmapped tenant (no document) counts as production (fail closed).
    """
    if label != RECURSIVE_IMPROVEMENT_LABEL:
        return
    if not _claims_enabled(tenant_policy):
        raise RecursiveClaimDeniedError(
            "recursive-improvement claims are research-only (G4/G6) — the tenant's "
            "policy data does not enable them (an unmapped tenant counts as "
            "production), so the honest label is 'artifact optimization'"
        )
    if verdict is None or not verdict.satisfied:
        raise RecursiveClaimDeniedError(
            "'recursive improvement' requires a satisfied §12.6 gate — "
            "the evidence does not back the claim"
        )


def _claims_enabled(tenant_policy: TenantPolicyDocument | None) -> bool:
    """True only when an explicitly research tenant's policy enables the
    claim (fail closed).

    The document's own validation refuses a production tenant that pins
    ``recursive_claims_enabled`` — so an enabled document is already a
    research document — but the environment is re-checked here rather
    than trusted, because this function is the boundary.
    """
    if tenant_policy is None:
        return False
    if not tenant_policy.recursive_claims_enabled:
        return False
    return tenant_policy.environment.value == "research"


__all__ = [
    "ARTIFACT_OPTIMIZATION_LABEL",
    "RECURSIVE_IMPROVEMENT_LABEL",
    "RecursiveClaimCondition",
    "RecursiveClaimEvidence",
    "RecursiveClaimVerdict",
    "assert_label_allowed",
    "claim_label",
    "evaluate_recursive_claim",
]
