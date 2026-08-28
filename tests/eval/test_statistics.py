"""The statistical claim, checked against data whose answer we already know.

The spec's D6 row asks for one thing above all: a paired-bootstrap
interval that reproduces a known effect within tolerance on a seeded
synthetic dataset. Everything else in this file exists to stop that
headline test from passing for the wrong reason — a null case that must
not claim an effect, a regression case that must be flagged, and a
coverage check that the nominal 95% interval really covers about 95% of
the time rather than being an arbitrary pair of numbers.

Synthetic data is generated with common random numbers: one uniform draw
per task decides both arms' outcomes, which is exactly the coupling the
runner produces by seeding each (task, seed) cell identically across
arms. The true effect is therefore `candidate_p - baseline_p` by
construction, and no test here has to guess it.
"""

from __future__ import annotations

import random

import pytest

from evoruntime.eval import (
    MIN_BOOTSTRAP_ITERATIONS,
    MultiplicityMethod,
    StatisticsError,
    Verdict,
    holm_adjusted_p_values,
    paired_bootstrap,
    per_comparison_alpha,
)
from evoruntime.eval.statistics import (
    DEFAULT_ALPHA,
    mean,
    paired_differences,
    quantile,
    sample_stdev,
)

TOLERANCE = 0.07
"""How far the estimate may sit from the true effect at n=200.

The paired difference is Bernoulli with p≈0.25, so its standard error at
200 tasks is about 0.031; 0.07 is a shade over two standard errors —
tight enough that a biased estimator fails, loose enough that honest
sampling noise does not.
"""


def synthetic_paired_scores(
    n: int, *, baseline_p: float, candidate_p: float, seed: int
) -> tuple[list[float], list[float]]:
    """Generate coupled per-task scores with a known effect size.

    One uniform draw per task feeds both arms, mirroring the harness's
    common-random-number seeding. The expected paired difference is then
    exactly `candidate_p - baseline_p`, with no independent-sampling
    noise added on top.
    """
    rng = random.Random(seed)
    baseline: list[float] = []
    candidate: list[float] = []
    for _ in range(n):
        draw = rng.random()
        baseline.append(1.0 if draw < baseline_p else 0.0)
        candidate.append(1.0 if draw < candidate_p else 0.0)
    return baseline, candidate


def independent_paired_scores(
    n: int, *, baseline_p: float, candidate_p: float, seed: int
) -> tuple[list[float], list[float]]:
    """Uncoupled scores — the harder, noisier null the interval must survive."""
    rng = random.Random(seed)
    baseline = [1.0 if rng.random() < baseline_p else 0.0 for _ in range(n)]
    candidate = [1.0 if rng.random() < candidate_p else 0.0 for _ in range(n)]
    return baseline, candidate


class TestKnownEffectReproduction:
    """The D6 acceptance row: a known effect, recovered within tolerance."""

    def test_bootstrap_recovers_a_known_positive_effect(self) -> None:
        """A planted +0.25 effect is estimated within tolerance and bracketed."""
        true_effect = 0.25
        baseline, candidate = synthetic_paired_scores(
            200, baseline_p=0.45, candidate_p=0.70, seed=20260827
        )

        result = paired_bootstrap(baseline, candidate, seed=11)

        assert result.observed_delta == pytest.approx(true_effect, abs=TOLERANCE)
        assert result.ci_low <= true_effect <= result.ci_high
        assert result.ci_low > 0.0
        assert result.verdict is Verdict.IMPROVEMENT
        assert result.p_value < 0.05
        assert result.n_pairs == 200

    def test_regression_arm_is_flagged(self) -> None:
        """A planted -0.25 effect must come back as a regression, not a shrug.

        This is the failure mode the harness exists to catch: an arm that
        looks fine on aggregate success but is reliably worse task-for-task.
        """
        true_effect = -0.25
        baseline, candidate = synthetic_paired_scores(
            200, baseline_p=0.60, candidate_p=0.35, seed=4242
        )

        result = paired_bootstrap(baseline, candidate, seed=11)

        assert result.observed_delta == pytest.approx(true_effect, abs=TOLERANCE)
        assert result.ci_low <= true_effect <= result.ci_high
        assert result.ci_high < 0.0
        assert result.verdict is Verdict.REGRESSION

    def test_identical_arms_produce_an_exactly_zero_interval(self) -> None:
        """Perfect coupling is the sharpest null available: no difference at all.

        Under common random numbers two identical arms differ on zero
        tasks, so every resample averages zero. An interval that wandered
        off zero here would mean the resampling had a bug.
        """
        baseline, candidate = synthetic_paired_scores(120, baseline_p=0.5, candidate_p=0.5, seed=99)

        result = paired_bootstrap(baseline, candidate, seed=3)

        assert baseline == candidate
        assert result.observed_delta == 0.0
        assert (result.ci_low, result.ci_high) == (0.0, 0.0)
        assert result.verdict is Verdict.INCONCLUSIVE

    def test_no_effect_with_independent_noise_stays_inconclusive(self) -> None:
        """Two equally good arms must not be reported as different."""
        baseline, candidate = independent_paired_scores(
            200, baseline_p=0.5, candidate_p=0.5, seed=8675309
        )

        result = paired_bootstrap(baseline, candidate, seed=5)

        assert result.ci_low < 0.0 < result.ci_high
        assert result.verdict is Verdict.INCONCLUSIVE
        assert result.p_value > 0.05

    def test_interval_covers_the_truth_about_as_often_as_advertised(self) -> None:
        """Calibration, not a single lucky dataset.

        A 95% interval that covered the truth 60% of the time would still
        pass every single-dataset test above while making every promotion
        decision built on it wrong. Forty independent synthetic datasets
        with a planted +0.20 effect; the nominal-95% interval must cover
        it at least 34 times (85%), which is a wide-enough band to absorb
        Monte-Carlo noise at n=60 but far below what a broken interval
        would produce.
        """
        true_effect = 0.20
        covered = 0
        datasets = 40
        for index in range(datasets):
            baseline, candidate = synthetic_paired_scores(
                60, baseline_p=0.40, candidate_p=0.60, seed=1000 + index
            )
            result = paired_bootstrap(
                baseline, candidate, iterations=MIN_BOOTSTRAP_ITERATIONS, seed=index
            )
            if result.ci_low <= true_effect <= result.ci_high:
                covered += 1

        assert covered >= 34, f"interval covered the truth {covered}/{datasets} times"


class TestMultiplicity:
    """Three arms means three chances to be fooled; the alpha has to pay for them."""

    def test_bonferroni_splits_the_family_alpha(self) -> None:
        """Two candidate arms against one incumbent: each interval gets alpha/2."""
        assert per_comparison_alpha(0.05, 2, MultiplicityMethod.BONFERRONI) == pytest.approx(0.025)

    def test_none_leaves_the_alpha_alone(self) -> None:
        """Opting out is explicit and named, never the default."""
        assert per_comparison_alpha(0.05, 3, MultiplicityMethod.NONE) == pytest.approx(0.05)

    def test_a_narrower_alpha_widens_the_interval(self) -> None:
        """The correction has to cost something, or it is decoration."""
        baseline, candidate = synthetic_paired_scores(
            150, baseline_p=0.40, candidate_p=0.60, seed=17
        )

        uncorrected = paired_bootstrap(baseline, candidate, alpha=0.05, seed=2)
        corrected = paired_bootstrap(baseline, candidate, alpha=0.025, seed=2)

        assert corrected.ci_low <= uncorrected.ci_low
        assert corrected.ci_high >= uncorrected.ci_high

    @pytest.mark.parametrize("alpha", [0.0, 1.0, -0.5])
    def test_family_alpha_must_be_a_probability(self, alpha: float) -> None:
        """An alpha of 0 or 1 is a category error, not an edge case."""
        with pytest.raises(StatisticsError, match="alpha"):
            per_comparison_alpha(alpha, 2, MultiplicityMethod.BONFERRONI)

    def test_at_least_one_comparison_is_required(self) -> None:
        """Dividing an alpha by zero comparisons is not a correction."""
        with pytest.raises(StatisticsError, match="comparisons"):
            per_comparison_alpha(0.05, 0, MultiplicityMethod.BONFERRONI)


class TestHolmAdjustment:
    """Step-down p-values: more power than Bonferroni at the same error rate."""

    def test_smallest_p_is_scaled_by_the_full_family_size(self) -> None:
        """Holm's first step is Bonferroni; the later steps are where it wins."""
        adjusted = holm_adjusted_p_values({"a": 0.01, "b": 0.04, "c": 0.30})

        assert adjusted["a"] == pytest.approx(0.03)
        assert adjusted["b"] == pytest.approx(0.08)
        assert adjusted["c"] == pytest.approx(0.30)

    def test_adjusted_values_never_decrease_with_raw_rank(self) -> None:
        """Monotonicity is the property that makes the adjustment interpretable."""
        raw = {"a": 0.001, "b": 0.049, "c": 0.05, "d": 0.9}
        adjusted = holm_adjusted_p_values(raw)

        ordered = [adjusted[key] for key in sorted(raw, key=lambda k: raw[k])]
        assert ordered == sorted(ordered)

    def test_adjusted_values_are_capped_at_one(self) -> None:
        """A probability greater than one would be reported to a human."""
        adjusted = holm_adjusted_p_values({"a": 0.6, "b": 0.7, "c": 0.8})

        assert max(adjusted.values()) <= 1.0

    def test_empty_family_is_empty_not_an_error(self) -> None:
        """An experiment with no candidate arms is legal — it just says nothing."""
        assert holm_adjusted_p_values({}) == {}

    def test_keys_are_preserved(self) -> None:
        """Arm ids must survive the adjustment or the report mislabels arms."""
        assert set(holm_adjusted_p_values({"retry": 0.2, "one-shot": 0.4})) == {
            "retry",
            "one-shot",
        }


class TestBootstrapContract:
    """Validation and reproducibility of the interval itself."""

    def test_result_is_reproducible_from_its_recorded_seed(self) -> None:
        """A published interval a reviewer cannot recompute is an assertion, not evidence."""
        baseline, candidate = synthetic_paired_scores(80, baseline_p=0.3, candidate_p=0.5, seed=1)

        first = paired_bootstrap(baseline, candidate, seed=77)
        second = paired_bootstrap(baseline, candidate, seed=first.seed)

        assert (first.ci_low, first.ci_high) == (second.ci_low, second.ci_high)
        assert first.p_value == second.p_value

    def test_observed_delta_does_not_depend_on_the_resampling_seed(self) -> None:
        """The point estimate is data; only the interval is resampled."""
        baseline, candidate = synthetic_paired_scores(80, baseline_p=0.3, candidate_p=0.5, seed=1)

        assert paired_bootstrap(baseline, candidate, seed=1).observed_delta == pytest.approx(
            paired_bootstrap(baseline, candidate, seed=2).observed_delta
        )

    def test_mismatched_lengths_are_refused(self) -> None:
        """Unequal vectors mean the pairing was lost upstream — never zip and hope."""
        with pytest.raises(StatisticsError, match="same length"):
            paired_bootstrap([1.0, 0.0], [1.0])

    def test_empty_samples_are_refused(self) -> None:
        """A comparison over zero tasks has no defensible interval."""
        with pytest.raises(StatisticsError, match="non-empty"):
            paired_bootstrap([], [])

    def test_iterations_below_the_floor_are_refused(self) -> None:
        """Too few resamples put noise in the interval's endpoints."""
        with pytest.raises(StatisticsError, match="at least"):
            paired_bootstrap([1.0], [0.0], iterations=MIN_BOOTSTRAP_ITERATIONS - 1)

    def test_p_value_is_never_reported_as_exactly_zero(self) -> None:
        """A bootstrap cannot resolve below 1/iterations; claiming zero overstates it."""
        baseline = [0.0] * 40
        candidate = [1.0] * 40

        result = paired_bootstrap(baseline, candidate, iterations=MIN_BOOTSTRAP_ITERATIONS, seed=0)

        assert result.p_value == pytest.approx(1.0 / MIN_BOOTSTRAP_ITERATIONS)

    def test_alpha_is_recorded_on_the_result(self) -> None:
        """The interval carries the alpha it was built at, for the report to cite."""
        baseline, candidate = synthetic_paired_scores(40, baseline_p=0.4, candidate_p=0.5, seed=3)

        result = paired_bootstrap(baseline, candidate, alpha=0.025, seed=0)

        assert result.alpha == pytest.approx(0.025)
        assert result.iterations >= MIN_BOOTSTRAP_ITERATIONS

    def test_default_alpha_is_the_conventional_five_percent(self) -> None:
        """Pins the default so a silent change becomes a failing test."""
        assert pytest.approx(0.05) == DEFAULT_ALPHA


class TestPrimitives:
    """Small pure helpers; each one is a place a wrong number could hide."""

    def test_paired_differences_is_candidate_minus_baseline(self) -> None:
        """Sign convention: positive means the candidate did better."""
        assert paired_differences([1.0, 0.0], [0.0, 1.0]) == (-1.0, 1.0)

    def test_mean_of_empty_is_an_error_not_a_zero(self) -> None:
        """Zero is a legitimate mean; returning it for "no data" hides the gap."""
        with pytest.raises(StatisticsError, match="empty"):
            mean([])

    def test_sample_stdev_is_bessel_corrected(self) -> None:
        """Population stdev would understate seed-to-seed spread at n=3."""
        assert sample_stdev([2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]) == pytest.approx(
            2.13809, abs=1e-5
        )

    def test_sample_stdev_of_one_value_is_zero(self) -> None:
        """One replicate has no spread; it must not raise mid-report."""
        assert sample_stdev([0.7]) == 0.0

    def test_quantile_interpolates_between_order_statistics(self) -> None:
        """Nearest-rank would bias interval endpoints on small resample counts."""
        assert quantile([0.0, 1.0, 2.0, 3.0], 0.5) == pytest.approx(1.5)

    @pytest.mark.parametrize("q", [-0.01, 1.01])
    def test_quantile_outside_the_unit_interval_is_refused(self, q: float) -> None:
        """A quantile outside [0, 1] is a caller bug worth surfacing loudly."""
        with pytest.raises(StatisticsError, match="quantile"):
            quantile([0.0, 1.0], q)
