"""Cascaded evaluation (Phase 2 F6): cheap stages gate expensive ones.

A campaign's evaluators differ in cost by orders of magnitude — a lint-grade
checker, a test-suite runner, a full holdout scoring pass. Running all of
them for every candidate spends the expensive end on candidates the cheap
end already rejected. The cascade fixes the *order*, not the evaluators:
stages run in ascending `stage` order, and a failing stage whose
`short_circuit` is set stops the cascade right there — later, more
expensive stages never run at all.

The statistics discipline is the part that is easy to get wrong. A cascade
that stops early has not "not yet measured" the candidate — it has
*measured a failure*: the candidate could not clear a cheaper stage, so it
has no passing result to compare. The paired comparison therefore treats
an early exit as a failure outcome for the candidate arm (see
`CascadeResult.candidate_scores`), which preserves the pairing with the
incumbent arm instead of silently shrinking the task set. Dropping the
unrun tasks would break the pairing; imputing success would fabricate it.

Alpha accounting stays with the D5 holdout query ledger. Each stage that
resolves the sealed holdout does so under its own ledger `purpose`
(`holdout_purpose`), so the ledger attributes alpha spend per stage and an
early exit's unspent stages are visible as absent rows rather than as an
unexplained budget remainder.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from evoruntime.eval.errors import CascadeDefinitionError

if TYPE_CHECKING:
    # Type-only: campaign.spec imports the cost-class enum from this module,
    # so a runtime import here would be a circular import.
    from evoruntime.campaign.spec import EvaluatorBinding


class EvaluatorCostClass(StrEnum):
    """How expensive one evaluator stage is to run.

    The class is descriptive metadata for attribution and reporting; the
    cascade's control flow is driven by `stage` order and `short_circuit`,
    never by the class itself. Keeping it descriptive means a campaign can
    add a cost class without changing the runner.
    """

    CHEAP = "cheap"
    STANDARD = "standard"
    EXPENSIVE = "expensive"


HOLDOUT_PURPOSE_PREFIX = "cascade.stage"
"""Ledger `purpose` prefix for stage-attributed holdout resolutions.

The D5 ledger keys alpha accounting on the purpose string; everything
under this prefix is a cascade stage's holdout resolution, parseable back
to its stage number and name by `parse_holdout_purpose`.
"""


def holdout_purpose(stage: int, stage_name: str) -> str:
    """The ledger purpose under which one stage's holdout resolution is recorded.

    Pure and stable: the ledger's per-stage alpha attribution depends on
    this exact string, so it lives here as the single definition rather
    than being re-formed at each call site.
    """
    return f"{HOLDOUT_PURPOSE_PREFIX}.{stage}:{stage_name}"


def parse_holdout_purpose(purpose: str) -> tuple[int, str] | None:
    """Split a cascade ledger purpose back into (stage, stage_name).

    Returns None for purposes outside the cascade namespace — the ledger
    holds resolutions from many callers, and most are not cascade stages.
    """
    if not purpose.startswith(HOLDOUT_PURPOSE_PREFIX + "."):
        return None
    remainder = purpose.removeprefix(HOLDOUT_PURPOSE_PREFIX + ".")
    stage_text, separator, stage_name = remainder.partition(":")
    if not separator or not stage_name or not stage_text.isdigit():
        raise CascadeDefinitionError(f"malformed cascade ledger purpose: {purpose!r}")
    return int(stage_text), stage_name


@dataclass(frozen=True, slots=True)
class StageOutcome:
    """What one stage's evaluation concluded, plus its raw metrics."""

    passed: bool
    metrics: Mapping[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metrics", dict(self.metrics))


@dataclass(frozen=True, slots=True)
class CascadeStage:
    """One position in the cascade, in the spec's own vocabulary."""

    name: str
    stage: int
    cost_class: EvaluatorCostClass
    short_circuit: bool = True

    def __post_init__(self) -> None:
        if not self.name:
            raise CascadeDefinitionError("cascade stage name must be non-empty")
        if self.stage < 0:
            raise CascadeDefinitionError(
                f"cascade stage {self.name!r} must be >= 0, got {self.stage}"
            )


def stage_from_binding(binding: EvaluatorBinding) -> CascadeStage:
    """Project a spec's `EvaluatorBinding` into a runnable cascade stage."""
    return CascadeStage(
        name=binding.name,
        stage=binding.stage,
        cost_class=binding.cost_class,
        short_circuit=binding.short_circuit,
    )


StageEvaluator = Callable[[CascadeStage], StageOutcome]
"""Runs one stage's evaluation and returns its outcome.

Receives the stage so an implementation can dispatch on it (different
evaluator images per stage); returns the stage's verdict and metrics.
"""


def stage_tagged_metrics(stage: CascadeStage, outcome: StageOutcome) -> dict[str, float]:
    """Flatten one stage's outcome into stage-tagged attestation metrics.

    Every key is prefixed with the stage number (`stage_<n>.<metric>`), so
    a result aggregated across stages stays attributable per stage — a
    consumer reading an attestation can tell the cheap stage's pass rate
    from the expensive stage's without positional guesswork. The stage
    number itself is included as a metric so the tag survives flattening
    into a numeric store.
    """
    tagged: dict[str, float] = {
        f"stage_{stage.stage}.stage_index": float(stage.stage),
        f"stage_{stage.stage}.passed": 1.0 if outcome.passed else 0.0,
    }
    for key, value in outcome.metrics.items():
        tagged[f"stage_{stage.stage}.{key}"] = float(value)
    return tagged


@dataclass(frozen=True, slots=True)
class StageRun:
    """One stage that actually ran, with its tagged metrics."""

    stage: CascadeStage
    outcome: StageOutcome
    metrics: Mapping[str, float] = field(default_factory=dict)

    @classmethod
    def record(cls, stage: CascadeStage, outcome: StageOutcome) -> StageRun:
        """Build a run with its stage-tagged metrics derived once."""
        return cls(stage=stage, outcome=outcome, metrics=stage_tagged_metrics(stage, outcome))


@dataclass(frozen=True, slots=True)
class CascadeResult:
    """The cascade's full record: what ran, what was skipped, and why.

    `skipped_stages` is part of the result, not an absence: an early exit
    is a finding about the candidate ("failed at stage N"), and the stages
    that never ran are the proof that the short-circuit held.
    """

    stage_runs: tuple[StageRun, ...]
    skipped_stages: tuple[CascadeStage, ...]
    short_circuited_at: str | None = None
    """Name of the stage whose failure stopped the cascade; None when it completed."""

    @property
    def completed(self) -> bool:
        """True when every stage ran — no stage short-circuited the cascade."""
        return self.short_circuited_at is None

    def candidate_scores(self, tasks: int) -> tuple[float, ...]:
        """The candidate arm's per-task scores for the paired comparison.

        Semantics on early exit (the defensibility contract): a cascade
        that stopped before its final stage is scored as a *failure* for
        the candidate arm on every task — one 0.0 per task — never as a
        shorter sample. The incumbent arm always runs the full cascade, so
        returning one score per task here keeps the pairing intact: the
        paired differences stay aligned per task, and the candidate's
        early exit counts against it exactly as much as it should. A
        completed cascade scores 1.0 per task when its final stage passed,
        0.0 when it did not.

        Raises:
            CascadeDefinitionError: `tasks` is not positive.
        """
        if tasks < 1:
            raise CascadeDefinitionError(f"candidate scores need at least one task, got {tasks}")
        if not self.completed:
            return (0.0,) * tasks
        passed = self.stage_runs[-1].outcome.passed
        return (1.0 if passed else 0.0,) * tasks


def run_cascade(stages: Sequence[CascadeStage], evaluate: StageEvaluator) -> CascadeResult:
    """Run evaluation stages in ascending order, short-circuiting on failure.

    A stage whose evaluation fails and whose `short_circuit` is set stops
    the cascade: later — more expensive — stages are recorded as skipped
    and their evaluators are never called. A stage with `short_circuit`
    cleared lets the cascade continue past its own failure (an informational
    stage whose verdict must not gate the expensive tiers).

    Raises:
        CascadeDefinitionError: the stage set is empty, or two stages
            share a stage number — an ordering the cascade cannot defend.
    """
    if not stages:
        raise CascadeDefinitionError("a cascade needs at least one stage")
    ordered = sorted(stages, key=lambda stage: stage.stage)
    stage_numbers = [stage.stage for stage in ordered]
    duplicates = sorted({n for n in stage_numbers if stage_numbers.count(n) > 1})
    if duplicates:
        raise CascadeDefinitionError(
            f"duplicate cascade stage number(s): {', '.join(map(str, duplicates))} — "
            "stage order must be a total order"
        )

    stage_runs: list[StageRun] = []
    skipped: list[CascadeStage] = []
    short_circuited_at: str | None = None

    for stage in ordered:
        if short_circuited_at is not None:
            skipped.append(stage)
            continue
        outcome = evaluate(stage)
        stage_runs.append(StageRun.record(stage, outcome))
        if not outcome.passed and stage.short_circuit:
            short_circuited_at = stage.name

    return CascadeResult(
        stage_runs=tuple(stage_runs),
        skipped_stages=tuple(skipped),
        short_circuited_at=short_circuited_at,
    )


__all__ = [
    "HOLDOUT_PURPOSE_PREFIX",
    "CascadeDefinitionError",
    "CascadeResult",
    "CascadeStage",
    "EvaluatorCostClass",
    "StageEvaluator",
    "StageOutcome",
    "StageRun",
    "holdout_purpose",
    "parse_holdout_purpose",
    "run_cascade",
    "stage_from_binding",
    "stage_tagged_metrics",
]
