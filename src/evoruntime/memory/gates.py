"""Suggestion-first promotion gates (deliverable E6, FR-016).

Memory never auto-promotes. An entry leaves suggestion mode only when
every gate below passes, and the gates are evaluated by
`MemoryService.promote_entry` — there is deliberately no code path that
flips a suggestion to active without producing a `GateReport` first.

Two statistical gates, both built on the D6 paired bootstrap so the
promotion decision and the evaluation harness share one definition of
"the interval":

- **persistence non-inferiority** — paired persistence-on vs
  persistence-off scores on the entry's scope. Memory that does not pay
  for its retrieval cost is not promoted, even if it is harmless: the
  burden of proof is on the memory, and the gate is one-sided (the lower
  bound of the improvement interval must clear -margin). A two-sided
  interval at 2*alpha gives exactly the 1-alpha one-sided lower bound.
- **negative transfer** — paired scores on probe tasks *outside* the
  entry's declared scope. Memory that helps where it applies but hurts
  where it leaks is a net loss; the gate passes only when the upper bound
  of the probe interval shows no regression beyond `max_regression`.

The third gate is hygiene itself: the entry must still be a clean
suggestion with no unresolved conflicts at promotion time. An entry that
was quarantined, expired, or revoked after the scores were collected does
not get promoted on stale evidence.

Gate inputs are invalid (empty, length-mismatched) → the gate *fails*
rather than raising: a promotion decision must be renderable from any
input, and an exception would let a caller skip the gate by feeding it
garbage.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from evoruntime.eval.errors import StatisticsError
from evoruntime.eval.statistics import (
    DEFAULT_BOOTSTRAP_ITERATIONS,
    paired_bootstrap,
)
from evoruntime.memory.schemas import MemoryStatus

DEFAULT_GATE_ALPHA = 0.05
"""Family-wise alpha for the promotion decision."""

DEFAULT_NON_INFERIORITY_MARGIN = 0.0
"""How much worse persistence-on may be than persistence-off and still
count as non-inferior. Zero by default: memory must at least break even."""

DEFAULT_MAX_NEGATIVE_TRANSFER = 0.0
"""Largest regression on out-of-scope probe tasks the upper bound may show."""

PERSISTENCE_GATE = "persistence_non_inferiority"
NEGATIVE_TRANSFER_GATE = "negative_transfer"
HYGIENE_GATE = "hygiene_clear"


@dataclass(frozen=True, slots=True)
class GateResult:
    """One gate's outcome, with the numbers it was decided from."""

    gate: str
    passed: bool
    detail: str


@dataclass(frozen=True, slots=True)
class GateReport:
    """The full gate evaluation behind one promotion decision."""

    results: tuple[GateResult, ...]

    @property
    def passed(self) -> bool:
        return all(result.passed for result in self.results)

    @property
    def failures(self) -> tuple[str, ...]:
        return tuple(result.gate for result in self.results if not result.passed)


def persistence_non_inferiority_gate(
    persistence_on: Sequence[float],
    persistence_off: Sequence[float],
    *,
    margin: float = DEFAULT_NON_INFERIORITY_MARGIN,
    alpha: float = DEFAULT_GATE_ALPHA,
    iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    seed: int = 0,
) -> GateResult:
    """Pass when persistence-on is statistically non-inferior to off.

    Args:
        persistence_on: per-task scores with the memory active.
        persistence_off: per-task scores with memory disabled, same tasks,
            same order — the pairing is the whole point.
        margin: tolerated deficit of persistence-on vs persistence-off.
        alpha: one-sided significance level for the lower bound.
    """
    try:
        result = paired_bootstrap(
            persistence_off,
            persistence_on,
            iterations=iterations,
            alpha=2.0 * alpha,
            seed=seed,
        )
    except StatisticsError as exc:
        return GateResult(
            gate=PERSISTENCE_GATE,
            passed=False,
            detail=f"gate input invalid: {exc}",
        )
    passed = result.ci_low >= -margin
    detail = (
        f"persistence-on minus persistence-off delta {result.observed_delta:+.4f}; "
        f"one-sided {(1.0 - alpha):.0%} lower bound {result.ci_low:+.4f} vs "
        f"margin -{margin:.4f}"
    )
    return GateResult(gate=PERSISTENCE_GATE, passed=passed, detail=detail)


def negative_transfer_gate(
    probe_baseline: Sequence[float],
    probe_with_memory: Sequence[float],
    *,
    max_regression: float = DEFAULT_MAX_NEGATIVE_TRANSFER,
    alpha: float = DEFAULT_GATE_ALPHA,
    iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    seed: int = 0,
) -> GateResult:
    """Pass when out-of-scope probe tasks show no significant regression.

    Args:
        probe_baseline: per-probe-task scores without the memory.
        probe_with_memory: same probe tasks with the memory active.
        max_regression: the regression the interval's upper bound must not
            exceed (0.0 = no statistically detectable harm tolerated).
        alpha: one-sided significance level for the upper bound.
    """
    try:
        result = paired_bootstrap(
            probe_baseline,
            probe_with_memory,
            iterations=iterations,
            alpha=2.0 * alpha,
            seed=seed,
        )
    except StatisticsError as exc:
        return GateResult(
            gate=NEGATIVE_TRANSFER_GATE,
            passed=False,
            detail=f"gate input invalid: {exc}",
        )
    passed = result.ci_high >= -max_regression
    detail = (
        f"probe delta (with memory minus baseline) {result.observed_delta:+.4f}; "
        f"one-sided {(1.0 - alpha):.0%} upper bound {result.ci_high:+.4f} vs "
        f"max regression -{max_regression:.4f}"
    )
    return GateResult(gate=NEGATIVE_TRANSFER_GATE, passed=passed, detail=detail)


def hygiene_gate(*, status: MemoryStatus, unresolved_conflicts: int) -> GateResult:
    """Pass when the entry is still a clean, conflict-free suggestion."""
    if status is not MemoryStatus.SUGGESTION:
        detail = (
            f"entry status is {status.value}, not suggestion — an entry that "
            "left suggestion mode (quarantined, expired, revoked, or already "
            "active) is not promotable on stale evidence"
        )
    elif unresolved_conflicts > 0:
        detail = f"{unresolved_conflicts} unresolved conflicting claim(s) in scope"
    else:
        detail = "entry is a clean suggestion with no unresolved conflicts"
    return GateResult(
        gate=HYGIENE_GATE,
        passed=status is MemoryStatus.SUGGESTION and unresolved_conflicts == 0,
        detail=detail,
    )
