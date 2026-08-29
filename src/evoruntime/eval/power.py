"""Power analysis: how many paired tasks a comparison needs (H10).

A campaign that discovers it is underpowered after the runs are spent has
not saved budget — it has spent it on a number nobody can act on. This
module moves that discovery to plan time: given the experiment's alpha,
the power the campaign wants, and the minimum detectable effect worth
detecting, it computes the paired-proportion sample size and the caller
pins it into the preregistered `StatisticsPlan` before any search begins.

The math is the standard two-proportion z-test sizing, applied to the
harness's paired design: the incumbent's success rate is `p1`, the
smallest improvement worth running is `mde`, so the candidate rate is
`p2 = p1 + mde`, and the required tasks per arm is

    n = ceil( (z_{1-a/2} * sqrt(2 * p_bar * (1 - p_bar))
               + z_{1-b} * sqrt(p1*(1-p1) + p2*(1-p2)))^2 / mde^2 )

with `p_bar = (p1 + p2) / 2`. Pairing by task makes the observed
difference less variable than two independent samples, so this is the
conservative (larger) answer — a powered campaign budgeted from it can
only be over-provisioned, never silently under.

Everything here is pure, deterministic math: no I/O, no RNG, no tuning
knobs. The same inputs always produce the same plan, which is what makes
the pinned number auditable after the fact.
"""

from __future__ import annotations

from dataclasses import dataclass
from statistics import NormalDist

from evoruntime.eval.errors import StatisticsError

DEFAULT_BASELINE_SUCCESS_RATE = 0.5
"""The variance-maximizing baseline.

A caller that does not know the incumbent's success rate gets the most
conservative plan: binary-outcome variance peaks at p = 0.5, so sizing
against it never under-counts the required tasks.
"""

DEFAULT_POWER = 0.8
"""The conventional minimum probability of detecting a real effect."""

_NORMAL = NormalDist()


@dataclass(frozen=True, slots=True)
class PowerAnalysis:
    """The inputs and the answer of one sample-size computation.

    Every input is carried on the result so the pinned number is
    auditable: a reviewer can recompute `required_tasks` from the plan
    without trusting that the caller's inputs were what the docstring
    said they were.
    """

    alpha: float
    power: float
    minimum_detectable_effect: float
    baseline_success_rate: float
    candidate_success_rate: float
    required_tasks: int
    """Tasks per arm. The harness pairs by task, so the sample size is a
    task count, not a run count — seeds buy variance reporting, not n."""


def required_sample_size(
    *,
    alpha: float,
    power: float,
    minimum_detectable_effect: float,
    baseline_success_rate: float = DEFAULT_BASELINE_SUCCESS_RATE,
) -> PowerAnalysis:
    """Tasks per arm needed to detect `minimum_detectable_effect` at
    family-wise `alpha` with `power`, given the incumbent's success rate.

    Args:
        alpha: the two-sided family-wise error rate, in (0, 1).
        power: the probability of detecting a real effect of at least the
            MDE, in (0, 1).
        minimum_detectable_effect: the smallest success-rate improvement
            worth running the campaign for, in (0, 1].
        baseline_success_rate: the incumbent arm's expected success rate,
            in [0, 1). Defaults to the variance-maximizing 0.5.

    Returns:
        The :class:`PowerAnalysis` carrying the required task count.

    Raises:
        StatisticsError: any argument is out of range, or the baseline
            plus the MDE would exceed a certain success rate.
    """
    _validate_fraction(alpha, "alpha")
    _validate_fraction(power, "power")
    if not 0.0 < minimum_detectable_effect <= 1.0:
        raise StatisticsError(
            f"minimum_detectable_effect must be in (0, 1], got {minimum_detectable_effect!r}"
        )
    if not 0.0 <= baseline_success_rate < 1.0:
        raise StatisticsError(
            f"baseline_success_rate must be in [0, 1), got {baseline_success_rate!r}"
        )

    baseline = baseline_success_rate
    candidate = baseline + minimum_detectable_effect
    if candidate > 1.0:
        raise StatisticsError(
            f"baseline_success_rate {baseline!r} plus minimum_detectable_effect "
            f"{minimum_detectable_effect!r} exceeds a certain success rate — the "
            "effect is not detectable above this baseline"
        )

    pooled = (baseline + candidate) / 2.0
    z_alpha = _NORMAL.inv_cdf(1.0 - alpha / 2.0)
    z_power = _NORMAL.inv_cdf(power)
    numerator = (
        z_alpha * (2.0 * pooled * (1.0 - pooled)) ** 0.5
        + z_power * (baseline * (1.0 - baseline) + candidate * (1.0 - candidate)) ** 0.5
    ) ** 2
    required = max(1, -(-numerator // minimum_detectable_effect**2))  # ceil, never below 1

    return PowerAnalysis(
        alpha=alpha,
        power=power,
        minimum_detectable_effect=minimum_detectable_effect,
        baseline_success_rate=baseline,
        candidate_success_rate=candidate,
        required_tasks=int(required),
    )


def _validate_fraction(value: float, what: str) -> None:
    """Reject anything outside the open interval (0, 1)."""
    if not 0.0 < value < 1.0:
        raise StatisticsError(f"{what} must be in (0, 1), got {value!r}")


__all__ = [
    "DEFAULT_BASELINE_SUCCESS_RATE",
    "DEFAULT_POWER",
    "PowerAnalysis",
    "required_sample_size",
]
