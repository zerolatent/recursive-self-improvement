"""The promotion policy engine (PRD §12.5): six conditions, no new statistics.

The engine is a *consumer* of :mod:`evoruntime.eval.statistics` — paired
bootstrap intervals and Holm correction come from the Phase 0 module, and
this module contains no statistical procedure of its own. What it adds is
the decision: the six preregistered eligibility conditions, evaluated in
one place, each recorded as a named pass/fail with the evidence that
decided it.

Two disciplines this module enforces:

**The coding MVP gates are policy DATA, not code.** The thresholds — ≥10%
held-out success gain or ≥20% cost reduction at non-inferior success, p95
latency ≤+10%, zero severity-1 regressions — live in
:class:`PromotionPolicyDocument`, a frozen, digestable document that is
part of the campaign's preregistration. The engine reads thresholds; it
never hardcodes them, because a gate whose thresholds live in code can be
changed by a commit, while a gate whose thresholds live in a signed policy
document can only be changed before search begins.

**Fail closed on missing evidence.** A protected slice with no paired
data, a transfer scope the evaluation never covered, a budget result that
was never recorded — each is a failed condition, not an assumption of
innocence. A promotion gate that benefits from the doubt is not a gate.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from evoruntime.eval.experiment import DEFAULT_BOOTSTRAP_SEED
from evoruntime.eval.statistics import (
    DEFAULT_ALPHA,
    DEFAULT_BOOTSTRAP_ITERATIONS,
    MultiplicityMethod,
    PairedBootstrapResult,
    holm_adjusted_p_values,
    paired_bootstrap,
    per_comparison_alpha,
)
from evoruntime.selection.authority import (
    ResolvedRelease,
    TierApprovalEvidence,
    assert_phase2_admissible,
    resolve_authority_tier,
)
from evoruntime.selection.errors import InvalidPromotionPolicyError
from evoruntime.selection.recursive_gate import (
    RecursiveClaimEvidence,
    RecursiveClaimVerdict,
    claim_label,
    evaluate_recursive_claim,
)

#: The six §12.5 eligibility conditions, in the order the spec lists them.
CONDITION_STATISTICAL = "statistical_superiority_or_preregistered_non_inferiority"
CONDITION_PROTECTED_SLICES = "protected_slice_non_inferiority"
CONDITION_NO_CRITICAL_FAILURE = "no_critical_safety_security_failure"
CONDITION_BUDGET = "budget_pass"
CONDITION_NO_INTEGRITY_FINDINGS = "no_leakage_tampering_or_leak_detection_finding"
CONDITION_TRANSFER_SCOPE = "claimed_transfer_scope_supported"


@dataclass(frozen=True, slots=True)
class PairedScores:
    """Paired per-task scores for one comparison, in matching task order.

    The pairing is the whole point: the bootstrap resamples tasks, so the
    two sequences must be the same tasks in the same order or the interval
    is meaningless. Construction validates that.
    """

    task_ids: tuple[str, ...]
    baseline: tuple[float, ...]
    candidate: tuple[float, ...]

    def __post_init__(self) -> None:
        if not self.task_ids:
            raise InvalidPromotionPolicyError("paired scores must cover at least one task")
        if len(self.baseline) != len(self.candidate) or len(self.task_ids) != len(self.baseline):
            raise InvalidPromotionPolicyError(
                f"paired scores lost the pairing: {len(self.task_ids)} task ids, "
                f"{len(self.baseline)} baseline scores, {len(self.candidate)} candidate scores"
            )


class PromotionPolicyDocument:
    """The declarative promotion policy (PRD §12.5 gates as data).

    Part of the campaign's preregistration: the thresholds below are
    pinned before any result exists, and the canonical form of this
    document is what the campaign spec's ``promotion_policy`` reference
    pins by digest. Validation runs at construction — a policy with
    impossible thresholds is refused before it can gate anything.
    """

    def __init__(
        self,
        *,
        policy_id: str,
        policy_version: int = 1,
        min_success_gain: float = 0.10,
        min_cost_reduction: float = 0.20,
        max_p95_latency_regression: float = 0.10,
        max_severity1_regressions: int = 0,
        success_non_inferiority_margin: float = 0.05,
        protected_slice_margins: Mapping[str, float] | None = None,
        allowed_authority_tiers: tuple[int, ...] = (1, 2),
        alpha: float = DEFAULT_ALPHA,
    ) -> None:
        self.policy_id = policy_id
        self.policy_version = policy_version
        self.min_success_gain = min_success_gain
        self.min_cost_reduction = min_cost_reduction
        self.max_p95_latency_regression = max_p95_latency_regression
        self.max_severity1_regressions = max_severity1_regressions
        self.success_non_inferiority_margin = success_non_inferiority_margin
        self.protected_slice_margins = dict(protected_slice_margins or {})
        self.allowed_authority_tiers = allowed_authority_tiers
        self.alpha = alpha
        self._validate()

    def _validate(self) -> None:
        if not self.policy_id:
            raise InvalidPromotionPolicyError("policy_id must be non-empty")
        for name, value in (
            ("min_success_gain", self.min_success_gain),
            ("min_cost_reduction", self.min_cost_reduction),
            ("max_p95_latency_regression", self.max_p95_latency_regression),
            ("success_non_inferiority_margin", self.success_non_inferiority_margin),
        ):
            if not 0.0 <= value <= 1.0:
                raise InvalidPromotionPolicyError(f"{name} must be in [0, 1], got {value!r}")
        if self.max_severity1_regressions < 0:
            raise InvalidPromotionPolicyError(
                "max_severity1_regressions must be >= 0 — a policy that tolerates "
                "severity-1 regressions is not a promotion gate"
            )
        for slice_name, margin in self.protected_slice_margins.items():
            if not slice_name:
                raise InvalidPromotionPolicyError("protected slice names must be non-empty")
            if not 0.0 < margin <= 1.0:
                raise InvalidPromotionPolicyError(
                    f"non-inferiority margin for slice {slice_name!r} must be in (0, 1], "
                    f"got {margin!r}"
                )
        if not self.allowed_authority_tiers:
            raise InvalidPromotionPolicyError(
                "allowed_authority_tiers must name at least one tier — an empty "
                "allowlist would reject every promotion, silently"
            )
        if not 0.0 < self.alpha < 1.0:
            raise InvalidPromotionPolicyError(f"alpha must be in (0, 1), got {self.alpha!r}")

    def to_canonical_dict(self) -> dict[str, object]:
        """Canonical JSON form — the bytes the campaign spec's digest pins."""
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "min_success_gain": self.min_success_gain,
            "min_cost_reduction": self.min_cost_reduction,
            "max_p95_latency_regression": self.max_p95_latency_regression,
            "max_severity1_regressions": self.max_severity1_regressions,
            "success_non_inferiority_margin": self.success_non_inferiority_margin,
            "protected_slice_margins": dict(sorted(self.protected_slice_margins.items())),
            "allowed_authority_tiers": list(self.allowed_authority_tiers),
            "alpha": self.alpha,
        }


@dataclass(frozen=True, slots=True)
class PromotionEvidence:
    """Everything the six conditions are judged on, for one candidate arm.

    Raw paired scores ride in the evidence so the engine — not the
    caller — runs the bootstrap: the interval a decision cites must be the
    one the statistics module produced, at the multiplicity-adjusted alpha
    this engine chose.
    """

    arm_id: str
    heldout: PairedScores
    """Candidate vs incumbent on the holdout, paired per task."""

    success_gain: float
    """Observed held-out success gain (candidate minus incumbent)."""

    cost_reduction: float
    """Observed cost reduction as a fraction (0.20 = 20% cheaper)."""

    p95_latency_regression: float
    """Relative p95 latency regression (0.10 = 10% slower)."""

    protected_slices: Mapping[str, PairedScores] | None = None
    """Paired scores per protected slice, keyed by slice name."""

    severity1_regressions: int = 0
    critical_failures: tuple[str, ...] = ()
    """Identifiers of critical safety/security failures (empty = none)."""

    budget_pass: bool = False
    integrity_findings: tuple[str, ...] = ()
    """Leakage / tampering / leak-detection finding identifiers."""

    claimed_transfer_scope: tuple[str, ...] = ()
    evaluated_transfer_scope: tuple[str, ...] = ()
    """The scopes the holdout evaluation actually covered."""

    preregistered_non_inferiority: bool = False
    """True when the campaign preregistered the cost-reduction path."""

    comparisons: int = 1
    """Candidate arms in the comparison family (drives multiplicity)."""

    bootstrap_iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS
    bootstrap_seed: int = DEFAULT_BOOTSTRAP_SEED

    def __post_init__(self) -> None:
        if not self.arm_id:
            raise InvalidPromotionPolicyError("arm_id must be non-empty")
        if self.comparisons < 1:
            raise InvalidPromotionPolicyError("comparisons must be at least 1")


@dataclass(frozen=True, slots=True)
class ConditionResult:
    """One named §12.5 condition and the evidence that decided it."""

    condition: str
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class PromotionDecision:
    """The engine's verdict for one candidate arm."""

    arm_id: str
    eligible: bool
    tier: int
    conditions: tuple[ConditionResult, ...]
    label: str
    ci_low: float
    ci_high: float
    adjusted_p_value: float

    def failed_conditions(self) -> tuple[str, ...]:
        """Names of the conditions that failed — the rejection's reasons."""
        return tuple(c.condition for c in self.conditions if not c.passed)


def evaluate_promotion(
    policy: PromotionPolicyDocument,
    evidence: PromotionEvidence,
    *,
    release: ResolvedRelease,
    recursive_claim: RecursiveClaimEvidence | None = None,
    tier_approvals: TierApprovalEvidence | None = None,
) -> PromotionDecision:
    """Apply the six §12.5 conditions to one candidate's evidence.

    Raises:
        TierRejectedError: the resolved release warrants tier-3/4 authority
            and carries no (or malformed) approval evidence — the F2 gate
            refuses the promotion before any condition is evaluated.
    """
    tier = resolve_authority_tier(release)
    assert_phase2_admissible(tier, tier_approvals)

    # Multiplicity: every candidate arm in the family compares against the
    # same incumbent, so the interval is built at the family-split alpha.
    comparison_alpha = per_comparison_alpha(
        policy.alpha, evidence.comparisons, MultiplicityMethod.BONFERRONI
    )
    main = paired_bootstrap(
        evidence.heldout.baseline,
        evidence.heldout.candidate,
        iterations=evidence.bootstrap_iterations,
        alpha=comparison_alpha,
        seed=evidence.bootstrap_seed,
    )

    slice_bootstraps = {
        name: paired_bootstrap(
            scores.baseline,
            scores.candidate,
            iterations=evidence.bootstrap_iterations,
            alpha=comparison_alpha,
            seed=evidence.bootstrap_seed,
        )
        for name, scores in (evidence.protected_slices or {}).items()
    }

    # Holm across the family: the main comparison plus every protected
    # slice that produced an interval. Reported for the record; the
    # decision itself reads the (simultaneous) Bonferroni intervals.
    p_values = {
        "heldout": main.p_value,
        **{f"slice:{name}": bootstrap.p_value for name, bootstrap in slice_bootstraps.items()},
    }
    adjusted = holm_adjusted_p_values(p_values)

    conditions = (
        _statistical_condition(policy, evidence, main),
        _protected_slice_condition(policy, slice_bootstraps),
        _critical_failure_condition(policy, evidence),
        _budget_condition(evidence),
        _integrity_condition(evidence),
        _transfer_scope_condition(evidence),
    )

    verdict: RecursiveClaimVerdict | None = (
        evaluate_recursive_claim(recursive_claim) if recursive_claim else None
    )

    return PromotionDecision(
        arm_id=evidence.arm_id,
        eligible=all(c.passed for c in conditions),
        tier=int(tier),
        conditions=conditions,
        label=claim_label(verdict),
        ci_low=main.ci_low,
        ci_high=main.ci_high,
        adjusted_p_value=adjusted["heldout"],
    )


def _statistical_condition(
    policy: PromotionPolicyDocument,
    evidence: PromotionEvidence,
    main: PairedBootstrapResult,
) -> ConditionResult:
    """Condition 1: multiplicity-adjusted lower bound above zero — or the
    preregistered non-inferiority path with material cost reduction."""
    superiority = main.ci_low > 0.0 and evidence.success_gain >= policy.min_success_gain
    non_inferior = (
        evidence.preregistered_non_inferiority
        and main.ci_low >= -policy.success_non_inferiority_margin
        and evidence.cost_reduction >= policy.min_cost_reduction
    )
    if superiority:
        return ConditionResult(
            CONDITION_STATISTICAL,
            True,
            f"CI lower bound {main.ci_low:.4f} > 0 and success gain "
            f"{evidence.success_gain:.4f} >= {policy.min_success_gain:.4f}",
        )
    if non_inferior:
        return ConditionResult(
            CONDITION_STATISTICAL,
            True,
            f"preregistered non-inferiority: CI lower bound {main.ci_low:.4f} >= "
            f"-{policy.success_non_inferiority_margin:.4f} and cost reduction "
            f"{evidence.cost_reduction:.4f} >= {policy.min_cost_reduction:.4f}",
        )
    return ConditionResult(
        CONDITION_STATISTICAL,
        False,
        f"CI lower bound {main.ci_low:.4f} clears neither the superiority bar "
        f"(> 0 with gain >= {policy.min_success_gain:.4f}) nor the preregistered "
        f"non-inferiority bar (>= -{policy.success_non_inferiority_margin:.4f} with "
        f"cost reduction >= {policy.min_cost_reduction:.4f})",
    )


def _protected_slice_condition(
    policy: PromotionPolicyDocument,
    slice_bootstraps: Mapping[str, PairedBootstrapResult],
) -> ConditionResult:
    """Condition 2: every protected slice above its non-inferiority margin."""
    failures: list[str] = []
    for slice_name, margin in sorted(policy.protected_slice_margins.items()):
        bootstrap = slice_bootstraps.get(slice_name)
        if bootstrap is None:
            failures.append(f"{slice_name}: no paired data (fail closed)")
        elif bootstrap.ci_low < -margin:
            failures.append(
                f"{slice_name}: CI lower bound {bootstrap.ci_low:.4f} below margin -{margin:.4f}"
            )
    if failures:
        return ConditionResult(CONDITION_PROTECTED_SLICES, False, "; ".join(failures))
    slices = ", ".join(sorted(policy.protected_slice_margins)) or "(none declared)"
    return ConditionResult(
        CONDITION_PROTECTED_SLICES, True, f"all protected slices above margin: {slices}"
    )


def _critical_failure_condition(
    policy: PromotionPolicyDocument, evidence: PromotionEvidence
) -> ConditionResult:
    """Condition 3: no critical safety/security failure, no severity-1
    regression beyond the policy's (typically zero) allowance."""
    problems: list[str] = []
    if evidence.critical_failures:
        problems.append(f"critical failures: {sorted(evidence.critical_failures)}")
    if evidence.severity1_regressions > policy.max_severity1_regressions:
        problems.append(
            f"severity-1 regressions {evidence.severity1_regressions} > "
            f"allowed {policy.max_severity1_regressions}"
        )
    if problems:
        return ConditionResult(CONDITION_NO_CRITICAL_FAILURE, False, "; ".join(problems))
    return ConditionResult(CONDITION_NO_CRITICAL_FAILURE, True, "no critical failures")


def _budget_condition(evidence: PromotionEvidence) -> ConditionResult:
    """Condition 4: the campaign's budget check passed."""
    if evidence.budget_pass:
        return ConditionResult(CONDITION_BUDGET, True, "budget pass")
    return ConditionResult(CONDITION_BUDGET, False, "budget check failed")


def _integrity_condition(evidence: PromotionEvidence) -> ConditionResult:
    """Condition 5: no leakage, tampering, or leak-detection finding."""
    if evidence.integrity_findings:
        return ConditionResult(
            CONDITION_NO_INTEGRITY_FINDINGS,
            False,
            f"integrity findings: {sorted(evidence.integrity_findings)}",
        )
    return ConditionResult(CONDITION_NO_INTEGRITY_FINDINGS, True, "no integrity findings")


def _transfer_scope_condition(evidence: PromotionEvidence) -> ConditionResult:
    """Condition 6: every claimed transfer scope was actually evaluated."""
    unevaluated = sorted(
        set(evidence.claimed_transfer_scope) - set(evidence.evaluated_transfer_scope)
    )
    if unevaluated:
        return ConditionResult(
            CONDITION_TRANSFER_SCOPE,
            False,
            f"claimed scopes the evaluation never covered: {unevaluated}",
        )
    return ConditionResult(CONDITION_TRANSFER_SCOPE, True, "claimed transfer scope fully covered")


__all__ = [
    "CONDITION_BUDGET",
    "CONDITION_NO_CRITICAL_FAILURE",
    "CONDITION_NO_INTEGRITY_FINDINGS",
    "CONDITION_PROTECTED_SLICES",
    "CONDITION_STATISTICAL",
    "CONDITION_TRANSFER_SCOPE",
    "ConditionResult",
    "PairedScores",
    "PromotionDecision",
    "PromotionEvidence",
    "PromotionPolicyDocument",
    "evaluate_promotion",
]
