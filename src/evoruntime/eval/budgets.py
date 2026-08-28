"""Matched-resource budgets: the ceiling every arm runs under.

A comparison between an incumbent and a candidate is only informative if
both spent the same resources getting there. The PRD's kill condition —
"equal-compute retry/search matches the optimizer" — is unfalsifiable if
the arms were never actually held to equal compute, so this module is
where equal compute stops being a promise and becomes a mechanism: one
`TaskBudget`, resolved once from a named profile, handed unchanged to
every arm, and enforced per task by a `BudgetMeter`.

Charges are pre-flight and transactional. A caller declares what a step
will cost *before* doing the work, and a charge that would cross any
ceiling raises without recording anything. A meter therefore never
reports usage above its budget: an arm is stopped at the line rather than
audited after crossing it, which is the difference between a budget and a
post-hoc complaint.

Wall clock has two sources and one ceiling. Real elapsed time comes from
an injected `Clock`; declared time comes from `charge(wall_clock_s=...)`,
which is how a deterministic backend accounts for work it simulates
rather than performs. Tests inject `FrozenClock` so the declared
component is the only one, because a ceiling measured against real time
turns every budget assertion into a race with the CI runner.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Protocol

from evoruntime.eval.errors import BudgetExceededError, UnknownBudgetProfileError


class BudgetDimension(StrEnum):
    """The resources an arm may exhaust.

    Four dimensions, because an arm can be starved four ways and the
    finding differs each time: a retry arm that runs out of tool calls is
    a different result from one that runs out of context.
    """

    INPUT_TOKENS = "input_tokens"
    OUTPUT_TOKENS = "output_tokens"
    TOOL_CALLS = "tool_calls"
    WALL_CLOCK = "wall_clock_s"


@dataclass(frozen=True, slots=True)
class TaskBudget:
    """The per-task resource envelope shared by every arm in an experiment.

    Frozen on purpose: an arm strategy holds a reference to the same
    object every other arm holds, so there is no way for one arm to widen
    its own ceiling — the type system enforces what the experiment design
    asserts.
    """

    max_input_tokens: int
    max_output_tokens: int
    max_tool_calls: int
    max_wall_clock_s: float

    def __post_init__(self) -> None:
        for name, value in (
            ("max_input_tokens", self.max_input_tokens),
            ("max_output_tokens", self.max_output_tokens),
            ("max_tool_calls", self.max_tool_calls),
            ("max_wall_clock_s", self.max_wall_clock_s),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be positive, got {value!r}")

    def limit(self, dimension: BudgetDimension) -> float:
        """Return the ceiling for one dimension."""
        match dimension:
            case BudgetDimension.INPUT_TOKENS:
                return float(self.max_input_tokens)
            case BudgetDimension.OUTPUT_TOKENS:
                return float(self.max_output_tokens)
            case BudgetDimension.TOOL_CALLS:
                return float(self.max_tool_calls)
            case BudgetDimension.WALL_CLOCK:
                return self.max_wall_clock_s


@dataclass(frozen=True, slots=True)
class BudgetUsage:
    """Resources consumed (or, from `BudgetMeter.remaining`, still available)."""

    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: int = 0
    wall_clock_s: float = 0.0

    @property
    def total_tokens(self) -> int:
        """Input plus output tokens — the headline cost number."""
        return self.input_tokens + self.output_tokens

    def within(self, budget: TaskBudget) -> bool:
        """True when every dimension sits at or below the budget's ceiling."""
        return (
            self.input_tokens <= budget.max_input_tokens
            and self.output_tokens <= budget.max_output_tokens
            and self.tool_calls <= budget.max_tool_calls
            and self.wall_clock_s <= budget.max_wall_clock_s
        )


TASK_BUDGET_V1 = TaskBudget(
    max_input_tokens=120_000,
    max_output_tokens=16_000,
    max_tool_calls=40,
    max_wall_clock_s=600.0,
)
"""The Phase 0 baseline envelope named by the spec's `task-budget-v1`.

Sized for one repo-repair task on the D8 coding fixtures: enough context
for an issue plus a small module and its tests, enough tool calls for a
read/patch/test loop, and a ten-minute ceiling. The numbers matter far
less than the fact that all three arms are held to the same ones — but
they are versioned rather than tunable per run so a result from August is
comparable to a result from November.
"""

BUDGET_PROFILES: MappingProxyType[str, TaskBudget] = MappingProxyType(
    {"task-budget-v1": TASK_BUDGET_V1}
)
"""Named, versioned budget profiles. A new envelope gets a new name."""


def resolve_budget_profile(name: str) -> TaskBudget:
    """Look up a named budget profile.

    Raises:
        UnknownBudgetProfileError: the name is not registered.
    """
    try:
        return BUDGET_PROFILES[name]
    except KeyError as exc:
        raise UnknownBudgetProfileError(name, tuple(BUDGET_PROFILES)) from exc


class Clock(Protocol):
    """Source of monotonic seconds for wall-clock accounting."""

    def now(self) -> float:
        """Return the current time in seconds; only differences are meaningful."""
        ...


class MonotonicClock:
    """Real elapsed time, for live runs against a real backend."""

    def now(self) -> float:
        """Return `time.monotonic()`."""
        return time.monotonic()


class FrozenClock:
    """A clock that only moves when told to.

    Deterministic backends declare their own durations, so a run under
    this clock consumes exactly the wall clock the script says it does —
    which is what makes a wall-clock budget assertion a statement about
    the harness rather than about the machine it ran on.
    """

    def __init__(self, start: float = 0.0) -> None:
        self._now = start

    def now(self) -> float:
        """Return the current simulated time."""
        return self._now

    def advance(self, seconds: float) -> None:
        """Move simulated time forward."""
        if seconds < 0:
            raise ValueError(f"cannot advance a clock backwards: {seconds!r}")
        self._now += seconds


class BudgetMeter:
    """Enforces one `TaskBudget` over one arm's attempt(s) at one task.

    The meter is per (arm, task, seed) and is shared across a retry arm's
    attempts on purpose: three attempts under one envelope is what "equal
    compute" means for a retry baseline. An arm that gets a fresh meter
    per attempt is not a control, it is three times the budget wearing a
    control's name.
    """

    def __init__(self, budget: TaskBudget, *, clock: Clock | None = None) -> None:
        self._budget = budget
        self._clock = clock if clock is not None else MonotonicClock()
        self._started_at = self._clock.now()
        self._input_tokens = 0
        self._output_tokens = 0
        self._tool_calls = 0
        self._declared_wall_clock_s = 0.0

    @property
    def budget(self) -> TaskBudget:
        """The ceiling this meter enforces."""
        return self._budget

    @property
    def usage(self) -> BudgetUsage:
        """Everything charged so far, including elapsed wall clock."""
        return BudgetUsage(
            input_tokens=self._input_tokens,
            output_tokens=self._output_tokens,
            tool_calls=self._tool_calls,
            wall_clock_s=self.elapsed_s,
        )

    @property
    def elapsed_s(self) -> float:
        """Real time since construction plus every declared duration."""
        return (self._clock.now() - self._started_at) + self._declared_wall_clock_s

    def remaining(self) -> BudgetUsage:
        """Headroom per dimension, floored at zero.

        Returned as a `BudgetUsage` so a backend can size its next request
        against the same shape it reports costs in.
        """
        return BudgetUsage(
            input_tokens=max(0, self._budget.max_input_tokens - self._input_tokens),
            output_tokens=max(0, self._budget.max_output_tokens - self._output_tokens),
            tool_calls=max(0, self._budget.max_tool_calls - self._tool_calls),
            wall_clock_s=max(0.0, self._budget.max_wall_clock_s - self.elapsed_s),
        )

    def can_afford(
        self,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        tool_calls: int = 0,
        wall_clock_s: float = 0.0,
    ) -> bool:
        """Non-raising check: would this charge fit inside the envelope?"""
        return (
            self._first_violation(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                tool_calls=tool_calls,
                wall_clock_s=wall_clock_s,
            )
            is None
        )

    def charge(
        self,
        *,
        input_tokens: int = 0,
        output_tokens: int = 0,
        tool_calls: int = 0,
        wall_clock_s: float = 0.0,
    ) -> None:
        """Record a charge, or refuse it and leave the meter untouched.

        Raises:
            BudgetExceededError: the charge would cross a ceiling. Nothing
                is recorded — the caller must not perform the work.
        """
        if input_tokens < 0 or output_tokens < 0 or tool_calls < 0 or wall_clock_s < 0:
            raise ValueError("budget charges must be non-negative")

        violation = self._first_violation(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            tool_calls=tool_calls,
            wall_clock_s=wall_clock_s,
        )
        if violation is not None:
            dimension, attempted = violation
            raise BudgetExceededError(dimension.value, self._budget.limit(dimension), attempted)

        self._input_tokens += input_tokens
        self._output_tokens += output_tokens
        self._tool_calls += tool_calls
        self._declared_wall_clock_s += wall_clock_s

    def refund_output_tokens(self, tokens: int) -> None:
        """Return unused output tokens reserved by a pre-flight charge.

        A live provider is charged its worst case (`max_tokens`) before
        the request goes out, because the ceiling has to hold even when
        the model runs long. Once the response arrives with real usage,
        the difference comes back — otherwise every request would bill the
        arm for tokens nobody generated.
        """
        if tokens < 0:
            raise ValueError(f"refund must be non-negative, got {tokens!r}")
        self._output_tokens = max(0, self._output_tokens - tokens)

    def checkpoint(self) -> None:
        """Assert the envelope still has room, charging nothing.

        Real time passes between attempts without any charge; a retry arm
        calls this before starting another attempt so a wall-clock
        exhaustion is detected at the boundary instead of halfway through
        the next model call.

        Raises:
            BudgetExceededError: the budget is already spent.
        """
        self.charge()

    def _first_violation(
        self,
        *,
        input_tokens: int,
        output_tokens: int,
        tool_calls: int,
        wall_clock_s: float,
    ) -> tuple[BudgetDimension, float] | None:
        """Return the first breached dimension and the total that breached it.

        Checked in a fixed order so a charge that would blow two ceilings
        reports the same one every time — a stop reason that varies with
        evaluation order is a stop reason nobody can aggregate.
        """
        prospective: tuple[tuple[BudgetDimension, float], ...] = (
            (BudgetDimension.INPUT_TOKENS, float(self._input_tokens + input_tokens)),
            (BudgetDimension.OUTPUT_TOKENS, float(self._output_tokens + output_tokens)),
            (BudgetDimension.TOOL_CALLS, float(self._tool_calls + tool_calls)),
            (BudgetDimension.WALL_CLOCK, self.elapsed_s + wall_clock_s),
        )
        for dimension, total in prospective:
            if total > self._budget.limit(dimension):
                return dimension, total
        return None


__all__ = [
    "BUDGET_PROFILES",
    "TASK_BUDGET_V1",
    "BudgetDimension",
    "BudgetMeter",
    "BudgetUsage",
    "Clock",
    "FrozenClock",
    "MonotonicClock",
    "TaskBudget",
    "resolve_budget_profile",
]
