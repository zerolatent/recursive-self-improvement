"""Power-analysis sample-size math (H10) and its pin into the plan.

The known-answer case is hand-computed: alpha=0.05, power=0.80, MDE=0.10,
baseline 0.5 gives z_{1-a/2}=1.959964, z_{1-b}=0.841621, p_bar=0.55, so

    n = ceil((1.959964*sqrt(0.495) + 0.841621*sqrt(0.49))^2 / 0.01)
      = ceil(3.873387 / 0.01)
      = 388

The property checks walk deterministic parameter grids — no RNG — because
the module's contract is that the same inputs always produce the same
plan, and that the plan only ever gets *more* expensive as the demand
tightens (smaller alpha, higher power, smaller effect).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from evoruntime.campaign.spec import CampaignSpec, StatisticsPlan, pin_powered_sample_size
from evoruntime.eval.errors import StatisticsError
from evoruntime.eval.power import required_sample_size
from evoruntime.eval.statistics import MultiplicityMethod
from tests.campaign.conftest import make_spec_mapping


class TestRequiredSampleSize:
    """The paired-proportion sizing and its known answer."""

    def test_known_answer_case(self) -> None:
        """alpha=0.05, power=0.80, MDE=0.10, baseline 0.5 -> 388 tasks per arm."""
        analysis = required_sample_size(alpha=0.05, power=0.80, minimum_detectable_effect=0.10)

        assert analysis.required_tasks == 388
        assert analysis.candidate_success_rate == pytest.approx(0.60)

    def test_result_is_deterministic(self) -> None:
        """Same inputs, same plan — the pinned number must be auditable."""
        first = required_sample_size(alpha=0.05, power=0.8, minimum_detectable_effect=0.05)
        second = required_sample_size(alpha=0.05, power=0.8, minimum_detectable_effect=0.05)

        assert first == second

    def test_smaller_effect_never_needs_fewer_tasks(self) -> None:
        """Halving the MDE can only raise the bar, never lower it."""
        coarse = required_sample_size(alpha=0.05, power=0.8, minimum_detectable_effect=0.10)
        fine = required_sample_size(alpha=0.05, power=0.8, minimum_detectable_effect=0.05)

        assert fine.required_tasks > coarse.required_tasks

    def test_tighter_alpha_never_needs_fewer_tasks(self) -> None:
        """A stricter family-wise error rate costs tasks, never saves them."""
        loose = required_sample_size(alpha=0.10, power=0.8, minimum_detectable_effect=0.10)
        tight = required_sample_size(alpha=0.01, power=0.8, minimum_detectable_effect=0.10)

        assert tight.required_tasks > loose.required_tasks

    def test_higher_power_never_needs_fewer_tasks(self) -> None:
        """Demanding a better chance of detecting the effect costs tasks."""
        weaker = required_sample_size(alpha=0.05, power=0.7, minimum_detectable_effect=0.10)
        stronger = required_sample_size(alpha=0.05, power=0.9, minimum_detectable_effect=0.10)

        assert stronger.required_tasks > weaker.required_tasks

    def test_known_baseline_lowers_the_requirement(self) -> None:
        """A baseline away from the variance peak needs fewer tasks than 0.5."""
        conservative = required_sample_size(alpha=0.05, power=0.8, minimum_detectable_effect=0.10)
        informed = required_sample_size(
            alpha=0.05, power=0.8, minimum_detectable_effect=0.10, baseline_success_rate=0.3
        )

        assert informed.required_tasks < conservative.required_tasks

    def test_required_tasks_is_always_at_least_one(self) -> None:
        """Even a near-certain effect budgets a real (nonzero) task count."""
        analysis = required_sample_size(
            alpha=0.2, power=0.5, minimum_detectable_effect=0.9, baseline_success_rate=0.05
        )

        assert analysis.required_tasks >= 1

    @pytest.mark.parametrize(
        ("kwargs", "match"),
        [
            ({"alpha": 0.0}, "alpha"),
            ({"alpha": 1.0}, "alpha"),
            ({"power": 0.0}, "power"),
            ({"power": 1.0}, "power"),
            ({"minimum_detectable_effect": 0.0}, "minimum_detectable_effect"),
            ({"minimum_detectable_effect": -0.1}, "minimum_detectable_effect"),
            ({"baseline_success_rate": 1.0}, "baseline_success_rate"),
            ({"baseline_success_rate": -0.1}, "baseline_success_rate"),
        ],
    )
    def test_out_of_range_arguments_are_refused(self, kwargs: dict[str, Any], match: str) -> None:
        """Every out-of-range input is a typed refusal, not a silent plan."""
        with pytest.raises(StatisticsError, match=match):
            required_sample_size(
                alpha=kwargs.get("alpha", 0.05),
                power=kwargs.get("power", 0.8),
                minimum_detectable_effect=kwargs.get("minimum_detectable_effect", 0.1),
                baseline_success_rate=kwargs.get("baseline_success_rate", 0.5),
            )

    def test_baseline_plus_effect_above_certainty_is_refused(self) -> None:
        """An effect that would push success past 100% cannot be detected."""
        with pytest.raises(StatisticsError, match="exceeds a certain success rate"):
            required_sample_size(
                alpha=0.05,
                power=0.8,
                minimum_detectable_effect=0.5,
                baseline_success_rate=0.9,
            )


def _plan(alpha: float = 0.05) -> StatisticsPlan:
    return StatisticsPlan(
        alpha=alpha,
        multiplicity=MultiplicityMethod.BONFERRONI,
        bootstrap_iterations=2_000,
        bootstrap_seed=7,
    )


class TestPinPoweredSampleSize:
    """The plan-time pin (H10): budgeted powered, not discovered underpowered."""

    def test_pin_computes_against_the_plan_alpha(self) -> None:
        """The pinned count matches a direct computation at the same alpha."""
        pinned = pin_powered_sample_size(
            _plan(alpha=0.05), power=0.8, minimum_detectable_effect=0.10
        )
        direct = required_sample_size(alpha=0.05, power=0.8, minimum_detectable_effect=0.10)

        assert pinned.required_sample_size == direct.required_tasks

    def test_pin_is_pure(self) -> None:
        """The input plan is untouched; a new plan carries the pin."""
        original = _plan()
        pinned = pin_powered_sample_size(original, power=0.8, minimum_detectable_effect=0.10)

        assert original.required_sample_size is None
        assert pinned.required_sample_size == 388
        assert pinned.alpha == original.alpha

    def test_unpinned_plan_omits_the_key_from_canonical_form(self) -> None:
        """Pre-H10 plans keep their canonical bytes (and digest) unchanged."""
        assert "required_sample_size" not in _plan().to_canonical_dict()

    def test_pinned_plan_serializes_the_pin(self) -> None:
        """A pinned plan binds the number into its canonical form."""
        pinned = pin_powered_sample_size(_plan(), power=0.8, minimum_detectable_effect=0.10)

        assert pinned.to_canonical_dict()["required_sample_size"] == 388

    def test_pin_parses_from_a_spec_mapping(self) -> None:
        """A spec document carrying the pin loads it into the plan."""
        raw = make_spec_mapping()
        raw["schema_version"] = 3
        raw["mutable_artifacts"] = [
            {"artifact_type": "prompt_bundle", "paths": ["prompts/system.md"]}
        ]
        raw.pop("mutable_artifact")
        raw["statistics"]["required_sample_size"] = 388

        spec = CampaignSpec.from_mapping(raw)

        assert spec.statistics.required_sample_size == 388

    def test_spec_without_the_pin_parses_as_absent(self) -> None:
        """Pre-H10 documents still load, with the pin absent."""
        raw = make_spec_mapping()
        raw["schema_version"] = 3
        raw["mutable_artifacts"] = [
            {"artifact_type": "prompt_bundle", "paths": ["prompts/system.md"]}
        ]
        raw.pop("mutable_artifact")

        spec = CampaignSpec.from_mapping(raw)

        assert spec.statistics.required_sample_size is None

    def test_invalid_pin_is_refused_at_construction(self) -> None:
        """A zero or negative sample size is a spec bug, refused loudly."""
        with pytest.raises(Exception, match="required_sample_size"):
            StatisticsPlan(
                alpha=0.05,
                multiplicity=MultiplicityMethod.BONFERRONI,
                bootstrap_iterations=2_000,
                bootstrap_seed=7,
                required_sample_size=0,
            )


def _assert_monotone(fn: Callable[[float], int], values: list[float]) -> None:
    """Across the grid, the requirement never decreases as demand tightens."""
    counts = [fn(value) for value in values]
    pairs = list(zip(counts, counts[1:], strict=False))
    assert all(later >= earlier for earlier, later in pairs)


class TestPowerProperties:
    """Deterministic grid walks over the sizing's monotonicity structure."""

    def test_monotone_in_effect_size(self) -> None:
        """Smaller effects to detect never shrink the required count."""
        _assert_monotone(
            lambda mde: (
                required_sample_size(
                    alpha=0.05, power=0.8, minimum_detectable_effect=mde
                ).required_tasks
            ),
            [0.5, 0.3, 0.2, 0.1, 0.05],
        )

    def test_monotone_in_alpha(self) -> None:
        """Tighter alpha never shrinks the required count."""
        _assert_monotone(
            lambda alpha: (
                required_sample_size(
                    alpha=alpha, power=0.8, minimum_detectable_effect=0.1
                ).required_tasks
            ),
            [0.2, 0.1, 0.05, 0.01],
        )

    def test_monotone_in_power(self) -> None:
        """Higher power never shrinks the required count."""
        _assert_monotone(
            lambda power: (
                required_sample_size(
                    alpha=0.05, power=power, minimum_detectable_effect=0.1
                ).required_tasks
            ),
            [0.5, 0.7, 0.8, 0.9, 0.95],
        )
