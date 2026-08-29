"""Assembling §12.6 recursive-claim evidence from real paired results (H11).

Everything the §12.6 gate is judged on used to be typed by hand in tests —
a satisfied :class:`RecursiveClaimEvidence` was a fixture, not a finding.
This module is the adapter that closes that gap: it takes the *real*
:class:`ExperimentResult` objects the harness produced for the two
generations and derives each evidence field from them, so the evidence a
claim cites is the evidence the experiments measured.

What each field is derived from, and why that derivation is honest:

- ``successive_promoted_generations`` — both generations' promoted release
  digests are present and distinct. Re-promoting the same release is not a
  second generation.
- ``shared_error_budget`` — both experiments' recorded runs agree they ran
  under one matched budget, and the two experiments pinned the same budget
  profile. ``ExperimentResult.budgets_are_matched`` re-derives the match
  from the runs themselves, so a campaign that quietly widened one arm's
  envelope fails here, not at review time.
- ``causal_inheritance`` — the generation-2 campaign's incumbent binding
  resolves to the generation-1 promoted release (the inheritance link is
  real) *and* the generation-2 strategy arm's interval against its own
  incumbent is an improvement (there is a gain to attribute).
- ``matched_compute_one_shot_advantage`` — the strategy arm beats the
  one-shot control in a paired comparison built at the experiment's own
  multiplicity-adjusted alpha, under matched budgets.
- ``no_inheritance_control_arm`` — the one-shot control ran and did *not*
  show the same advantage: its observed delta against the incumbent is
  strictly below the strategy arm's.
- ``fixed_editor_*`` — the RI-3/RI-4 facts: the control arm ran, its
  numeric advantage is the observed mean paired delta of the strategy arm
  over the fixed-editor arm on the shared holdout tasks, and its p-value
  survived the Holm step-down across the experiment's whole comparison
  family (every candidate-vs-incumbent delta plus the fixed-editor
  comparison itself).

The adapter is pure and fails closed: an arm it needs but cannot
unambiguously identify (two strategy arms, two fixed-editor arms) is an
:class:`EvidenceAssemblyError`, never a guessed field. It decides
*nothing* — the gate in :mod:`evoruntime.selection.recursive_gate` still
owns every condition; this module only makes sure the gate is judged on
measured numbers.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from evoruntime.eval.experiment import Arm, ArmKind
from evoruntime.eval.results import ArmSummary, ExperimentResult, aligned_scores
from evoruntime.eval.statistics import (
    PairedBootstrapResult,
    Verdict,
    holm_adjusted_p_values,
    paired_bootstrap,
    per_comparison_alpha,
)
from evoruntime.selection.errors import EvidenceAssemblyError
from evoruntime.selection.recursive_gate import RecursiveClaimEvidence

_EVIDENCE_FIELDS = (
    "successive_promoted_generations",
    "shared_error_budget",
    "causal_inheritance",
    "matched_compute_one_shot_advantage",
    "no_inheritance_control_arm",
    "fixed_editor_control_arm",
    "fixed_editor_advantage",
    "fixed_editor_minimum_effect",
    "fixed_editor_holm_significant",
)


@dataclass(frozen=True, slots=True)
class ArmPairComparison:
    """One paired comparison between two arms of a real experiment."""

    candidate_arm_id: str
    baseline_arm_id: str
    bootstrap: PairedBootstrapResult
    adjusted_p_value: float
    """Holm-adjusted inside the comparison family this adapter built."""

    @property
    def observed_delta(self) -> float:
        """The observed mean paired delta (candidate minus baseline)."""
        return self.bootstrap.observed_delta

    @property
    def is_improvement(self) -> bool:
        """True when the whole interval sits above parity."""
        return self.bootstrap.verdict is Verdict.IMPROVEMENT


@dataclass(frozen=True, slots=True)
class RecursiveClaimEvidenceAssembly:
    """The assembled evidence plus the comparisons it was derived from.

    The comparisons ride along so a reviewer can audit the numbers behind
    each boolean without re-running the bootstrap: the evidence object is
    the claim's input, the comparisons are its provenance.
    """

    evidence: RecursiveClaimEvidence
    strategy_gain: ArmPairComparison
    """The generation-2 strategy arm against its own incumbent."""
    fixed_editor_comparison: ArmPairComparison | None = None
    """The strategy arm against the fixed-editor arm (RI-3/RI-4)."""
    one_shot_comparison: ArmPairComparison | None = None
    """The strategy arm against the one-shot control (RI-2)."""

    def to_request_payload(self) -> dict[str, Any]:
        """The flat evidence fields, ready for the claim-issuance API."""
        return {
            "evidence": canonical_evidence_dict(self.evidence),
            "provenance": {
                "strategy_gain": _comparison_dict(self.strategy_gain),
                "fixed_editor_comparison": (
                    _comparison_dict(self.fixed_editor_comparison)
                    if self.fixed_editor_comparison is not None
                    else None
                ),
                "one_shot_comparison": (
                    _comparison_dict(self.one_shot_comparison)
                    if self.one_shot_comparison is not None
                    else None
                ),
            },
        }


def canonical_evidence_dict(evidence: RecursiveClaimEvidence) -> dict[str, Any]:
    """The evidence's fields as a canonical (sorted-key) JSON-safe dict."""
    return {name: getattr(evidence, name) for name in _EVIDENCE_FIELDS}


def evidence_digest(evidence: RecursiveClaimEvidence) -> str:
    """SHA-256 over the evidence's canonical JSON — the digest the
    append-only decision record pins, so what was decided is what was
    submitted."""
    canonical = json.dumps(canonical_evidence_dict(evidence), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def assemble_recursive_claim_evidence(
    generation1: ExperimentResult,
    generation2: ExperimentResult,
    *,
    generation1_promoted_digest: str | None,
    generation2_promoted_digest: str | None,
    generation2_incumbent_digest: str,
    fixed_editor_minimum_effect: float | None,
) -> RecursiveClaimEvidenceAssembly:
    """Derive the §12.6 evidence from two generations' real paired results.

    Args:
        generation1: the generation-1 campaign's experiment result.
        generation2: the generation-2 campaign's experiment result — the
            one that must carry the strategy, one-shot, and fixed-editor
            arms the claim is judged on.
        generation1_promoted_digest: the release generation 1 promoted,
            or ``None`` while generation 1 has not promoted.
        generation2_promoted_digest: the release generation 2 promoted,
            or ``None`` while generation 2 has not promoted.
        generation2_incumbent_digest: the release digest the generation-2
            campaign's incumbent binding pinned.
        fixed_editor_minimum_effect: the preregistered RI-3 minimum
            effect, or ``None`` when nothing was pinned (the gate then
            fails the condition — an unpinned floor defaults to failing).

    Raises:
        EvidenceAssemblyError: the generation-2 experiment does not name
            exactly one strategy arm, or names more than one fixed-editor
            or one-shot arm — an ambiguous claim input fails closed.
    """
    strategy = _single_arm(generation2, ArmKind.STRATEGY)
    fixed_editor = _optional_arm(generation2, ArmKind.FIXED_EDITOR, "fixed-editor")
    one_shot = _optional_arm(generation2, ArmKind.ONE_SHOT_CONTROL, "one-shot control")

    alpha = generation2.experiment.alpha
    strategy_gain = _comparison_from_delta(generation2, strategy)

    fixed_editor_comparison = (
        _paired_comparison(generation2, baseline=fixed_editor, candidate=strategy, alpha=alpha)
        if fixed_editor is not None
        else None
    )
    one_shot_comparison = (
        _paired_comparison(generation2, baseline=one_shot, candidate=strategy, alpha=alpha)
        if one_shot is not None
        else None
    )

    evidence = RecursiveClaimEvidence(
        successive_promoted_generations=(
            generation1_promoted_digest is not None
            and generation2_promoted_digest is not None
            and generation2_promoted_digest != generation1_promoted_digest
        ),
        shared_error_budget=_shared_error_budget(generation1, generation2),
        causal_inheritance=(
            generation1_promoted_digest is not None
            and generation2_incumbent_digest == generation1_promoted_digest
            and strategy_gain.is_improvement
        ),
        matched_compute_one_shot_advantage=(
            one_shot_comparison is not None
            and generation2.budgets_are_matched
            and one_shot_comparison.is_improvement
        ),
        no_inheritance_control_arm=(
            one_shot is not None
            and strategy_gain.observed_delta > _delta_vs_incumbent(generation2, one_shot)
        ),
        fixed_editor_control_arm=fixed_editor is not None,
        fixed_editor_advantage=(
            fixed_editor_comparison.observed_delta if fixed_editor_comparison else None
        ),
        fixed_editor_minimum_effect=fixed_editor_minimum_effect,
        fixed_editor_holm_significant=(
            fixed_editor_comparison.adjusted_p_value < alpha
            if fixed_editor_comparison is not None
            else False
        ),
    )
    return RecursiveClaimEvidenceAssembly(
        evidence=evidence,
        strategy_gain=strategy_gain,
        fixed_editor_comparison=fixed_editor_comparison,
        one_shot_comparison=one_shot_comparison,
    )


def _single_arm_summary(result: ExperimentResult, arm: Arm) -> ArmSummary:
    """One arm's summary, refusing an arm the result never scored."""
    summary = result.primary.get(arm.id)
    if summary is None:
        raise EvidenceAssemblyError(
            f"experiment {result.experiment.name!r} has no recorded summary for "
            f"arm {arm.id!r} — the evidence cannot cite an arm that did not run"
        )
    return summary


def _comparison_from_delta(result: ExperimentResult, arm: Arm) -> ArmPairComparison:
    """The experiment's own candidate-vs-incumbent comparison for one arm."""
    comparison = result.delta.get(arm.id)
    if comparison is None:
        raise EvidenceAssemblyError(
            f"experiment {result.experiment.name!r} has no paired comparison for "
            f"arm {arm.id!r} against the incumbent"
        )
    return ArmPairComparison(
        candidate_arm_id=arm.id,
        baseline_arm_id=result.experiment.incumbent.id,
        bootstrap=comparison.bootstrap,
        adjusted_p_value=comparison.adjusted_p_value,
    )


def _delta_vs_incumbent(result: ExperimentResult, arm: Arm) -> float:
    """One candidate arm's observed delta against the incumbent."""
    return _comparison_from_delta(result, arm).observed_delta


def _paired_comparison(
    result: ExperimentResult, *, baseline: Arm, candidate: Arm, alpha: float
) -> ArmPairComparison:
    """A paired comparison between two arms the experiment's own delta map
    does not carry (strategy vs fixed-editor, strategy vs one-shot).

    Built at the same multiplicity-adjusted alpha the experiment's other
    intervals use, so the fixed-editor comparison is comparable to the
    family it will be Holm-adjusted inside.
    """
    baseline_summary = _single_arm_summary(result, baseline)
    candidate_summary = _single_arm_summary(result, candidate)
    comparison_alpha = per_comparison_alpha(
        alpha, len(result.experiment.candidate_arms), result.experiment.multiplicity
    )
    bootstrap = paired_bootstrap(
        aligned_scores(baseline_summary, result.task_ids),
        aligned_scores(candidate_summary, result.task_ids),
        iterations=result.experiment.bootstrap_iterations,
        alpha=comparison_alpha,
        seed=result.experiment.bootstrap_seed,
    )
    return ArmPairComparison(
        candidate_arm_id=candidate.id,
        baseline_arm_id=baseline.id,
        bootstrap=bootstrap,
        adjusted_p_value=_holm_significance(result, candidate, bootstrap),
    )


def _holm_significance(
    result: ExperimentResult, candidate: Arm, bootstrap: PairedBootstrapResult
) -> float:
    """The comparison's p-value after Holm across the whole family.

    RI-4: the fixed-editor comparison is one member of the same
    multiplicity family as the campaign's other comparisons. The family is
    every candidate-vs-incumbent p-value the experiment produced plus this
    comparison's own — adjusted together, read together.
    """
    family = {arm_id: comparison.bootstrap.p_value for arm_id, comparison in result.delta.items()}
    family[candidate.id] = bootstrap.p_value
    return holm_adjusted_p_values(family)[candidate.id]


def _shared_error_budget(generation1: ExperimentResult, generation2: ExperimentResult) -> bool:
    """Both generations ran under one preregistered, internally matched budget."""
    return (
        generation1.budgets_are_matched
        and generation2.budgets_are_matched
        and generation1.experiment.task_budget_profile == generation2.experiment.task_budget_profile
        and generation1.experiment.budget == generation2.experiment.budget
    )


def _single_arm(result: ExperimentResult, kind: ArmKind) -> Arm:
    """The experiment's exactly-one arm of a kind, or a fail-closed error."""
    arms = [arm for arm in result.experiment.arms if arm.kind is kind]
    if len(arms) != 1:
        raise EvidenceAssemblyError(
            f"experiment {result.experiment.name!r} must name exactly one "
            f"{kind.value} arm for evidence assembly, found {len(arms)}"
        )
    return arms[0]


def _optional_arm(result: ExperimentResult, kind: ArmKind, what: str) -> Arm | None:
    """The experiment's at-most-one arm of a control kind."""
    arms = [arm for arm in result.experiment.arms if arm.kind is kind]
    if len(arms) > 1:
        raise EvidenceAssemblyError(
            f"experiment {result.experiment.name!r} names {len(arms)} {what} arms — "
            "an ambiguous control fails closed, it does not get averaged"
        )
    return arms[0] if arms else None


def _comparison_dict(comparison: ArmPairComparison) -> dict[str, Any]:
    """JSON-safe provenance for one comparison."""
    return {
        "candidate_arm_id": comparison.candidate_arm_id,
        "baseline_arm_id": comparison.baseline_arm_id,
        "observed_delta": comparison.observed_delta,
        "ci_low": comparison.bootstrap.ci_low,
        "ci_high": comparison.bootstrap.ci_high,
        "p_value": comparison.bootstrap.p_value,
        "adjusted_p_value": comparison.adjusted_p_value,
        "n_pairs": comparison.bootstrap.n_pairs,
        "seed": comparison.bootstrap.seed,
    }


__all__ = [
    "ArmPairComparison",
    "RecursiveClaimEvidenceAssembly",
    "assemble_recursive_claim_evidence",
    "canonical_evidence_dict",
    "evidence_digest",
]
