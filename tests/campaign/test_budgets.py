"""Budget-enforcement tests (FR-005's enforcement half).

The meter is external: the orchestrator holds it, the strategy never
sees it. These tests pin the three behaviors that make that claim true —
pre-flight transactional charges, wall clock under an injected clock, and
the plugin-visible `RemainingBudget` view that carries no ceilings.
"""

from __future__ import annotations

from typing import Any

import pytest

from evoruntime.campaign.budgets import CampaignBudget, CampaignBudgetMeter
from evoruntime.campaign.errors import CampaignBudgetExceededError
from evoruntime.campaign.spec import CampaignBudgets
from evoruntime.eval.budgets import FrozenClock


def make_budget(**overrides: Any) -> CampaignBudget:
    """A small budget with every dimension overridable per test."""
    values: dict[str, Any] = {
        "max_proposals": 3,
        "max_model_tokens": 1000,
        "max_wall_clock_minutes": 1.0,
    }
    values.update(overrides)
    return CampaignBudget(**values)


class TestTransactionalCharges:
    def test_charge_within_budget_records(self) -> None:
        meter = CampaignBudgetMeter(make_budget(), clock=FrozenClock())
        meter.charge_proposals(2, input_tokens=300, output_tokens=200)
        assert meter.proposals_charged == 2
        assert meter.model_tokens_charged == 500

    def test_charge_crossing_a_ceiling_raises_and_records_nothing(self) -> None:
        meter = CampaignBudgetMeter(make_budget(), clock=FrozenClock())
        meter.charge_proposals(2, input_tokens=400, output_tokens=100)
        with pytest.raises(CampaignBudgetExceededError) as excinfo:
            meter.charge_proposals(2, input_tokens=100, output_tokens=0)
        assert excinfo.value.dimension == "proposals"
        # Transactional: the refused charge left no trace.
        assert meter.proposals_charged == 2
        assert meter.model_tokens_charged == 500

    def test_token_ceiling_is_enforced_independently(self) -> None:
        meter = CampaignBudgetMeter(make_budget(), clock=FrozenClock())
        with pytest.raises(CampaignBudgetExceededError) as excinfo:
            meter.charge_proposals(1, input_tokens=900, output_tokens=200)
        assert excinfo.value.dimension == "model_tokens"
        assert meter.proposals_charged == 0

    def test_negative_charges_are_refused(self) -> None:
        meter = CampaignBudgetMeter(make_budget(), clock=FrozenClock())
        with pytest.raises(ValueError, match="non-negative"):
            meter.charge_proposals(-1)
        with pytest.raises(ValueError, match="non-negative"):
            meter.charge_wall_clock_s(-5.0)

    def test_exact_ceiling_is_allowed_but_nothing_more(self) -> None:
        meter = CampaignBudgetMeter(make_budget(), clock=FrozenClock())
        meter.charge_proposals(3)
        assert meter.proposals_charged == 3
        with pytest.raises(CampaignBudgetExceededError):
            meter.charge_proposals(1)


class TestWallClock:
    def test_declared_durations_count_against_the_ceiling(self) -> None:
        meter = CampaignBudgetMeter(make_budget(), clock=FrozenClock())
        meter.charge_wall_clock_s(30.0)  # half a minute
        assert meter.elapsed_minutes == pytest.approx(0.5)
        with pytest.raises(CampaignBudgetExceededError) as excinfo:
            meter.charge_wall_clock_s(45.0)  # would total 75s > 60s ceiling
        assert excinfo.value.dimension == "wall_clock_minutes"

    def test_real_elapsed_time_counts_via_the_injected_clock(self) -> None:
        clock = FrozenClock()
        meter = CampaignBudgetMeter(make_budget(), clock=clock)
        clock.advance(120.0)  # two minutes of real time
        assert meter.elapsed_minutes == pytest.approx(2.0)
        assert meter.exhausted()


class TestPluginVisibility:
    def test_remaining_view_floors_at_zero_and_hides_ceilings(self) -> None:
        meter = CampaignBudgetMeter(make_budget(), clock=FrozenClock())
        meter.charge_proposals(3, input_tokens=1000, output_tokens=0)
        remaining = meter.remaining()
        assert remaining.proposals_remaining == 0
        assert remaining.model_tokens_remaining == 0
        # The view carries headroom only — never the ceilings themselves.
        assert not hasattr(remaining, "max_proposals")

    def test_exhausted_flags_when_any_dimension_runs_dry(self) -> None:
        meter = CampaignBudgetMeter(make_budget(), clock=FrozenClock())
        assert not meter.exhausted()
        meter.charge_proposals(3)
        assert meter.exhausted()


class TestSpecResolution:
    def test_budget_resolves_from_the_spec(self) -> None:
        budgets = CampaignBudgets(
            task_budget_profile="task-budget-v1",
            max_proposals=7,
            max_model_tokens=50_000,
            max_wall_clock_minutes=12.5,
        )
        budget = CampaignBudget.from_spec(budgets)
        assert budget.max_proposals == 7
        assert budget.max_model_tokens == 50_000
        assert budget.max_wall_clock_minutes == 12.5
