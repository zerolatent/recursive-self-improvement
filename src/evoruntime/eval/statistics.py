"""Paired bootstrap, multiplicity control, and the parity verdict.

Two arms measured on the same tasks are paired data, and treating them as
two independent samples throws away the pairing that makes small task
sets informative at all. So the interval here is built from per-task
*differences*: resample the tasks, average their differences, read the
percentiles.

Three choices worth defending, because each one changes what the interval
means:

*The resampling unit is the task, not the (task, seed) cell.* Seeds are
repeated measurements of the same task, and their outcomes are correlated
through the task's difficulty. Resampling cells as if they were
independent would shrink the interval by a factor of roughly sqrt(seeds)
and manufacture confidence nobody earned. Each task contributes its mean
across seeds; the bootstrap resamples tasks.

*Multiplicity is corrected on the interval, not just the p-value.* The
spec's decision rule is "the CI excludes parity", so the correction has
to live where the decision is read. Comparing three candidate arms
against one incumbent at a nominal 95% each gives a family-wise error
rate near 14%; Bonferroni widens each interval to alpha/m so the family
keeps its coverage. Holm-adjusted p-values are reported alongside for
readers who want the (more powerful, but non-interval) ordered view.

*A bootstrap p-value never reports zero.* With B resamples the smallest
observable tail proportion is 1/B, so the p-value floors there. Printing
`p = 0.0` from 2,000 resamples claims a precision the procedure does not
have.
"""

from __future__ import annotations

import math
import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from evoruntime.eval.errors import StatisticsError

DEFAULT_BOOTSTRAP_ITERATIONS = 2_000
"""Enough resamples for a stable 95% percentile interval on Phase 0 task counts."""

MIN_BOOTSTRAP_ITERATIONS = 200
"""Below this the tails are too coarse for an interval anyone should act on."""

DEFAULT_ALPHA = 0.05
"""Family-wise error rate for the whole experiment, not per comparison."""


class Verdict(StrEnum):
    """What a candidate arm's interval says about parity with the incumbent."""

    IMPROVEMENT = "improvement"
    """The whole interval sits above zero."""

    REGRESSION = "regression"
    """The whole interval sits below zero — the arm is worse, not merely unproven."""

    INCONCLUSIVE = "inconclusive"
    """The interval contains parity. Not evidence of equivalence, only of not knowing."""


class MultiplicityMethod(StrEnum):
    """How the family-wise error rate is spread across comparisons."""

    BONFERRONI = "bonferroni"
    """Split alpha evenly. Conservative, assumption-free, and easy to defend."""

    NONE = "none"
    """No correction. Only honest for a single preregistered comparison."""


@dataclass(frozen=True, slots=True)
class PairedBootstrapResult:
    """A candidate-vs-incumbent interval and the inputs that produced it."""

    observed_delta: float
    ci_low: float
    ci_high: float
    alpha: float
    iterations: int
    n_pairs: int
    p_value: float
    seed: int

    @property
    def excludes_parity(self) -> bool:
        """True when the interval lies entirely on one side of zero."""
        return self.ci_low > 0.0 or self.ci_high < 0.0

    @property
    def verdict(self) -> Verdict:
        """Classify the interval against parity."""
        if self.ci_low > 0.0:
            return Verdict.IMPROVEMENT
        if self.ci_high < 0.0:
            return Verdict.REGRESSION
        return Verdict.INCONCLUSIVE


def per_comparison_alpha(
    family_alpha: float, comparisons: int, method: MultiplicityMethod
) -> float:
    """Split a family-wise alpha across simultaneous comparisons.

    Args:
        family_alpha: the error rate the whole experiment is allowed.
        comparisons: how many candidate arms are compared to the incumbent.
        method: correction to apply.

    Returns:
        The alpha each individual interval should be built at.
    """
    if not 0.0 < family_alpha < 1.0:
        raise StatisticsError(f"alpha must be in (0, 1), got {family_alpha!r}")
    if comparisons < 1:
        raise StatisticsError(f"comparisons must be at least 1, got {comparisons!r}")
    if method is MultiplicityMethod.NONE:
        return family_alpha
    return family_alpha / comparisons


def mean(values: Sequence[float]) -> float:
    """Arithmetic mean of a non-empty sequence."""
    if not values:
        raise StatisticsError("cannot take the mean of an empty sequence")
    return sum(values) / len(values)


def sample_stdev(values: Sequence[float]) -> float:
    """Bessel-corrected sample standard deviation; 0.0 for a single value.

    Implemented here rather than imported from the standard library's
    `statistics` so every statistical primitive the harness reports has
    one home — and so this module's name never has to be reasoned about.
    """
    if not values:
        raise StatisticsError("cannot take the standard deviation of an empty sequence")
    if len(values) == 1:
        return 0.0
    centre = mean(values)
    variance = sum((value - centre) ** 2 for value in values) / (len(values) - 1)
    return math.sqrt(variance)


def quantile(sorted_values: Sequence[float], q: float) -> float:
    """Linear-interpolated quantile of an already-sorted sequence.

    Interpolating rather than nearest-rank matters at the tails: with
    2,000 resamples and a Bonferroni-narrowed alpha, the interval's
    endpoint can fall between two order statistics, and snapping to the
    nearer one biases the interval by a visible amount on small samples.
    """
    if not sorted_values:
        raise StatisticsError("cannot take a quantile of an empty sequence")
    if not 0.0 <= q <= 1.0:
        raise StatisticsError(f"quantile must be in [0, 1], got {q!r}")
    if len(sorted_values) == 1:
        return sorted_values[0]

    position = q * (len(sorted_values) - 1)
    lower_index = int(position)
    upper_index = min(lower_index + 1, len(sorted_values) - 1)
    weight = position - lower_index
    return sorted_values[lower_index] * (1.0 - weight) + sorted_values[upper_index] * weight


def paired_differences(baseline: Sequence[float], candidate: Sequence[float]) -> tuple[float, ...]:
    """Element-wise candidate minus baseline, validated as a paired design.

    Raises:
        StatisticsError: the samples are empty or not the same length,
            which means the caller lost the pairing somewhere upstream.
    """
    if len(baseline) != len(candidate):
        raise StatisticsError(
            f"paired samples must be the same length: {len(baseline)} vs {len(candidate)}"
        )
    if not baseline:
        raise StatisticsError("paired samples must be non-empty")
    return tuple(c - b for b, c in zip(baseline, candidate, strict=True))


def paired_bootstrap(
    baseline: Sequence[float],
    candidate: Sequence[float],
    *,
    iterations: int = DEFAULT_BOOTSTRAP_ITERATIONS,
    alpha: float = DEFAULT_ALPHA,
    seed: int = 0,
) -> PairedBootstrapResult:
    """Percentile bootstrap interval for the mean paired difference.

    Args:
        baseline: incumbent scores, one per pairing unit (task).
        candidate: candidate scores, same units in the same order.
        iterations: bootstrap resamples.
        alpha: the alpha *this interval* is built at — already multiplicity
            -adjusted by the caller if more than one comparison is in play.
        seed: RNG seed, recorded in the result so the interval reproduces.

    Returns:
        The observed difference, its interval, and a two-sided bootstrap
        p-value.
    """
    if iterations < MIN_BOOTSTRAP_ITERATIONS:
        raise StatisticsError(
            f"iterations must be at least {MIN_BOOTSTRAP_ITERATIONS}, got {iterations}"
        )
    if not 0.0 < alpha < 1.0:
        raise StatisticsError(f"alpha must be in (0, 1), got {alpha!r}")

    deltas = paired_differences(baseline, candidate)
    observed = mean(deltas)

    rng = random.Random(seed)
    n = len(deltas)
    resampled_means: list[float] = []
    for _ in range(iterations):
        total = 0.0
        for _ in range(n):
            total += deltas[rng.randrange(n)]
        resampled_means.append(total / n)
    resampled_means.sort()

    ci_low = quantile(resampled_means, alpha / 2.0)
    ci_high = quantile(resampled_means, 1.0 - alpha / 2.0)

    at_or_below = sum(1 for value in resampled_means if value <= 0.0)
    at_or_above = sum(1 for value in resampled_means if value >= 0.0)
    tail = min(at_or_below, at_or_above) / iterations
    p_value = min(1.0, max(2.0 * tail, 1.0 / iterations))

    return PairedBootstrapResult(
        observed_delta=observed,
        ci_low=ci_low,
        ci_high=ci_high,
        alpha=alpha,
        iterations=iterations,
        n_pairs=n,
        p_value=p_value,
        seed=seed,
    )


def holm_adjusted_p_values(p_values: Mapping[str, float]) -> dict[str, float]:
    """Holm step-down adjustment, preserving the input keys.

    Holm is uniformly more powerful than Bonferroni at the same family-wise
    error rate, which is why the p-values get it even though the intervals
    (which have to be simultaneous, not sequential) get Bonferroni.
    """
    if not p_values:
        return {}

    ordered = sorted(p_values.items(), key=lambda item: item[1])
    total = len(ordered)
    adjusted: dict[str, float] = {}
    running_max = 0.0
    for index, (key, raw_p) in enumerate(ordered):
        # Step-down: each p is scaled by the number of hypotheses still
        # untested, then forced to be non-decreasing so a later (larger)
        # raw p can never end up with a smaller adjusted value.
        scaled = min(1.0, (total - index) * raw_p)
        running_max = max(running_max, scaled)
        adjusted[key] = running_max
    return adjusted


__all__ = [
    "DEFAULT_ALPHA",
    "DEFAULT_BOOTSTRAP_ITERATIONS",
    "MIN_BOOTSTRAP_ITERATIONS",
    "MultiplicityMethod",
    "PairedBootstrapResult",
    "Verdict",
    "holm_adjusted_p_values",
    "mean",
    "paired_bootstrap",
    "paired_differences",
    "per_comparison_alpha",
    "quantile",
    "sample_stdev",
]
