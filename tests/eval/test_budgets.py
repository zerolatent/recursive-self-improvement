"""The resource envelope: named profiles and a transactional meter.

The budget is the harness's whole claim to fairness, so these tests are
about the ways a ceiling could leak: a refused charge that still counted,
a dimension that reported a different violation depending on evaluation
order, wall clock that ignored real time, a refund that went negative.
"""

from __future__ import annotations

import pytest

from evoruntime.eval import (
    BUDGET_PROFILES,
    TASK_BUDGET_V1,
    BudgetDimension,
    BudgetExceededError,
    BudgetMeter,
    BudgetUsage,
    FrozenClock,
    TaskBudget,
    UnknownBudgetProfileError,
    resolve_budget_profile,
)

SMALL_BUDGET = TaskBudget(
    max_input_tokens=1_000,
    max_output_tokens=500,
    max_tool_calls=4,
    max_wall_clock_s=60.0,
)


def test_the_spec_profile_name_resolves_to_the_versioned_envelope() -> None:
    """`task-budget-v1` is the name the spec's Experiment sample passes."""
    assert resolve_budget_profile("task-budget-v1") is TASK_BUDGET_V1
    assert set(BUDGET_PROFILES) == {"task-budget-v1"}


def test_unknown_profile_names_the_profiles_that_exist() -> None:
    """A typo in a preregistered profile must not be a silent default."""
    with pytest.raises(UnknownBudgetProfileError) as excinfo:
        resolve_budget_profile("task-budget-v2")

    assert "task-budget-v1" in str(excinfo.value)


@pytest.mark.parametrize(
    "field",
    ["max_input_tokens", "max_output_tokens", "max_tool_calls", "max_wall_clock_s"],
)
def test_non_positive_ceilings_are_rejected(field: str) -> None:
    """A zero ceiling is an arm that cannot act; that is a config bug, not a budget."""
    kwargs: dict[str, float] = {
        "max_input_tokens": 10,
        "max_output_tokens": 10,
        "max_tool_calls": 1,
        "max_wall_clock_s": 1.0,
    }
    kwargs[field] = 0

    with pytest.raises(ValueError, match=field):
        TaskBudget(**kwargs)  # type: ignore[arg-type]


def test_charges_accumulate_and_remaining_reports_headroom() -> None:
    """Usage and headroom are two views of the same ledger."""
    meter = BudgetMeter(SMALL_BUDGET, clock=FrozenClock())

    meter.charge(input_tokens=300, output_tokens=100, tool_calls=1, wall_clock_s=5.0)
    meter.charge(input_tokens=200, output_tokens=50, tool_calls=2, wall_clock_s=2.5)

    assert meter.usage == BudgetUsage(
        input_tokens=500, output_tokens=150, tool_calls=3, wall_clock_s=7.5
    )
    assert meter.remaining() == BudgetUsage(
        input_tokens=500, output_tokens=350, tool_calls=1, wall_clock_s=52.5
    )


def test_a_refused_charge_records_nothing() -> None:
    """The charge is transactional: the caller must not do work it cannot pay for.

    A meter that recorded a partial charge before raising would leave the
    arm billed for an attempt it never made, and every later comparison
    would be against a budget nobody actually spent.
    """
    meter = BudgetMeter(SMALL_BUDGET, clock=FrozenClock())
    meter.charge(input_tokens=900, tool_calls=1)
    before = meter.usage

    with pytest.raises(BudgetExceededError) as excinfo:
        meter.charge(input_tokens=200, tool_calls=1)

    assert meter.usage == before
    assert excinfo.value.dimension == BudgetDimension.INPUT_TOKENS.value


def test_violation_dimension_is_stable_when_two_ceilings_would_break() -> None:
    """A stop reason that varied with evaluation order could not be aggregated."""
    meter = BudgetMeter(SMALL_BUDGET, clock=FrozenClock())

    with pytest.raises(BudgetExceededError) as excinfo:
        meter.charge(input_tokens=5_000, output_tokens=5_000, tool_calls=99)

    assert excinfo.value.dimension == BudgetDimension.INPUT_TOKENS.value


def test_can_afford_answers_without_charging() -> None:
    """The non-raising probe leaves the ledger untouched either way."""
    meter = BudgetMeter(SMALL_BUDGET, clock=FrozenClock())

    assert meter.can_afford(input_tokens=1_000) is True
    assert meter.can_afford(input_tokens=1_001) is False
    assert meter.usage == BudgetUsage()


def test_output_refund_returns_reserved_tokens_and_floors_at_zero() -> None:
    """Reserve-then-reconcile has to give back what the model did not generate."""
    meter = BudgetMeter(SMALL_BUDGET, clock=FrozenClock())
    meter.charge(output_tokens=400)

    meter.refund_output_tokens(350)
    assert meter.usage.output_tokens == 50

    meter.refund_output_tokens(999)
    assert meter.usage.output_tokens == 0

    with pytest.raises(ValueError, match="non-negative"):
        meter.refund_output_tokens(-1)


def test_wall_clock_counts_real_time_and_declared_durations() -> None:
    """Both halves count: a backend that sleeps and one that declares 5s spend the same."""
    clock = FrozenClock()
    meter = BudgetMeter(SMALL_BUDGET, clock=clock)

    meter.charge(wall_clock_s=10.0)
    clock.advance(4.0)

    assert meter.elapsed_s == pytest.approx(14.0)
    assert meter.remaining().wall_clock_s == pytest.approx(46.0)


def test_checkpoint_detects_an_exhausted_clock_without_charging() -> None:
    """A retry arm finds out between attempts, not halfway through the next call."""
    clock = FrozenClock()
    meter = BudgetMeter(SMALL_BUDGET, clock=clock)

    meter.checkpoint()  # plenty of room
    clock.advance(SMALL_BUDGET.max_wall_clock_s + 1.0)

    with pytest.raises(BudgetExceededError) as excinfo:
        meter.checkpoint()

    assert excinfo.value.dimension == BudgetDimension.WALL_CLOCK.value
    assert meter.usage.input_tokens == 0


def test_negative_charges_are_rejected() -> None:
    """A negative charge is a refund with the wrong name, and refunds are explicit."""
    meter = BudgetMeter(SMALL_BUDGET, clock=FrozenClock())

    with pytest.raises(ValueError, match="non-negative"):
        meter.charge(input_tokens=-1)


def test_usage_within_reports_containment() -> None:
    """`within` is what the runner's matched-budget assertions read."""
    assert BudgetUsage(input_tokens=1_000, output_tokens=500).within(SMALL_BUDGET) is True
    assert BudgetUsage(input_tokens=1_001).within(SMALL_BUDGET) is False
    assert BudgetUsage(input_tokens=10, output_tokens=20).total_tokens == 30


def test_budget_is_frozen_so_no_arm_can_widen_its_own_ceiling() -> None:
    """The design asserts a shared envelope; the type system enforces it."""
    with pytest.raises(AttributeError):
        TASK_BUDGET_V1.max_input_tokens = 10**9  # type: ignore[misc]


def test_limit_covers_every_dimension() -> None:
    """Every dimension the meter enforces has a ceiling to read."""
    assert {
        dimension: SMALL_BUDGET.limit(dimension) for dimension in BudgetDimension
    } == {
        BudgetDimension.INPUT_TOKENS: 1_000.0,
        BudgetDimension.OUTPUT_TOKENS: 500.0,
        BudgetDimension.TOOL_CALLS: 4.0,
        BudgetDimension.WALL_CLOCK: 60.0,
    }
