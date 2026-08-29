"""The §12.6 recursive-claim gate, as policy code.

The gate's four conditions — two successive promoted generations under a
shared preregistered error budget, causal inheritance, a matched-compute
one-shot advantage, and a no-inheritance control arm — are checked here,
by code, so the claim is a *verdict* rather than an adjective.

But a satisfied gate is still not enough to earn the label in Phase 1.
Locked decision #8: Phase 1 results are labeled "artifact optimization",
never "recursive improvement". :data:`RECURSIVE_CLAIM_ENABLED` is the
runtime-level switch that keeps that promise — the gate logic ships and is
tested, and the label switch stays off until a later phase turns it on
deliberately. :func:`claim_label` is the only place a result's label is
decided, so the two cannot drift.
"""

from __future__ import annotations

from dataclasses import dataclass

from evoruntime.selection.errors import RecursiveClaimDeniedError
from evoruntime.tenancy.environment import TenantEnvironment

ARTIFACT_OPTIMIZATION_LABEL = "artifact optimization"
RECURSIVE_IMPROVEMENT_LABEL = "recursive improvement"

RECURSIVE_CLAIM_ENABLED = False
"""Locked decision #8: no Phase 1 result is ever labeled 'recursive
improvement'. Flipping this is a deliberate, reviewed act — not something
a passing gate does on its own."""


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


@dataclass(frozen=True, slots=True)
class RecursiveClaimCondition:
    """One named §12.6 condition and the evidence that decided it."""

    condition: str
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class RecursiveClaimVerdict:
    """The gate's verdict over its four conditions."""

    conditions: tuple[RecursiveClaimCondition, ...]

    @property
    def satisfied(self) -> bool:
        """True only when every §12.6 condition holds."""
        return bool(self.conditions) and all(c.passed for c in self.conditions)


def evaluate_recursive_claim(evidence: RecursiveClaimEvidence) -> RecursiveClaimVerdict:
    """Evaluate the four §12.6 conditions. Pure policy code: no I/O, no
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
    )
    return RecursiveClaimVerdict(conditions=conditions)


def claim_label(
    verdict: RecursiveClaimVerdict | None,
    *,
    tenant_environment: TenantEnvironment | str | None = None,
) -> str:
    """The honest label for a result.

    "recursive improvement" requires the gate to be satisfied, the
    phase-level claim switch to be on, *and* — Phase 3 (G6) — the result
    to belong to a research tenant. An absent environment is treated as
    production (fail closed): recursive-improvement claims are
    research-only, so a caller that cannot say which environment it is
    in does not get the label. In Phase 1 the switch is off, so every
    result — gate satisfied or not — is labeled "artifact optimization".
    """
    if (
        verdict is not None
        and verdict.satisfied
        and RECURSIVE_CLAIM_ENABLED
        and _is_research(tenant_environment)
    ):
        return RECURSIVE_IMPROVEMENT_LABEL
    return ARTIFACT_OPTIMIZATION_LABEL


def assert_label_allowed(
    label: str,
    verdict: RecursiveClaimVerdict | None,
    *,
    tenant_environment: TenantEnvironment | str | None = None,
) -> None:
    """Refuse a 'recursive improvement' label the gate, phase, or tenant
    environment does not back.

    Anything that renders a result — API, UI, report — routes its label
    through here, so a claim cannot slip past :func:`claim_label`. The
    environment check (G6) is the recursive-label boundary: the label is
    refused outside a research tenant, and an absent environment counts
    as production (fail closed).
    """
    if label != RECURSIVE_IMPROVEMENT_LABEL:
        return
    if not RECURSIVE_CLAIM_ENABLED:
        raise RecursiveClaimDeniedError(
            "Phase 1 never labels a result 'recursive improvement' (locked "
            "decision #8) — the honest label is 'artifact optimization'"
        )
    if not _is_research(tenant_environment):
        raise RecursiveClaimDeniedError(
            "recursive-improvement claims are research-only (G6) — a production "
            "tenant (or an unmapped one) cannot earn the label"
        )
    if verdict is None or not verdict.satisfied:
        raise RecursiveClaimDeniedError(
            "'recursive improvement' requires a satisfied §12.6 gate — "
            "the evidence does not back the claim"
        )


def _is_research(tenant_environment: TenantEnvironment | str | None) -> bool:
    """True only for an explicitly research environment (fail closed)."""
    if tenant_environment is None:
        return False
    return TenantEnvironment(tenant_environment) is TenantEnvironment.RESEARCH


__all__ = [
    "ARTIFACT_OPTIMIZATION_LABEL",
    "RECURSIVE_CLAIM_ENABLED",
    "RECURSIVE_IMPROVEMENT_LABEL",
    "RecursiveClaimCondition",
    "RecursiveClaimEvidence",
    "RecursiveClaimVerdict",
    "assert_label_allowed",
    "claim_label",
    "evaluate_recursive_claim",
]
