"""Externally enforced campaign budgets (FR-005's enforcement half).

The pattern is `eval/budgets.py`'s `BudgetMeter`, lifted from per-task to
per-campaign scale: charges are pre-flight and transactional, a charge
that would cross a ceiling raises without recording anything, and the
meter never reports usage above its budget. The difference is *who* holds
the meter: the orchestrator does, outside the strategy process. A plugin
never sees the meter — it sees only a `RemainingBudget` view — so a
strategy that ignores its budget doesn't overspend, it simply stops being
called. That is what "externally enforced" means: the ceiling is a
property of the runtime, not a promise the plugin could break.
"""

from __future__ import annotations

from dataclasses import dataclass

from evoruntime.campaign.errors import CampaignBudgetExceededError
from evoruntime.campaign.spec import CampaignBudgets
from evoruntime.eval.budgets import Clock, MonotonicClock
from evoruntime.plugins.protocol import RemainingBudget

_SECONDS_PER_MINUTE = 60.0


@dataclass(frozen=True, slots=True)
class CampaignBudget:
    """The campaign-level resource envelope, resolved from the spec.

    Frozen for the same reason `TaskBudget` is: the orchestrator holds the
    only reference, and there is no code path that widens it mid-search.
    """

    max_proposals: int
    max_model_tokens: int
    max_wall_clock_minutes: float

    @classmethod
    def from_spec(cls, budgets: CampaignBudgets) -> CampaignBudget:
        """Resolve the spec's declared budgets into the enforced envelope."""
        return cls(
            max_proposals=budgets.max_proposals,
            max_model_tokens=budgets.max_model_tokens,
            max_wall_clock_minutes=budgets.max_wall_clock_minutes,
        )

    def limit(self, dimension: str) -> float:
        """Return the ceiling for one dimension name."""
        match dimension:
            case "proposals":
                return float(self.max_proposals)
            case "model_tokens":
                return float(self.max_model_tokens)
            case "wall_clock_minutes":
                return self.max_wall_clock_minutes
        raise CampaignBudgetExceededError(dimension, 0.0, 0.0)


class CampaignBudgetMeter:
    """Enforces one `CampaignBudget` over one campaign's search.

    Charges are pre-flight: the orchestrator declares what a step *will*
    cost before doing the work, and a charge that would cross any ceiling
    raises without recording anything. Wall clock combines real elapsed
    time (injected `Clock`, `FrozenClock` in tests) with declared
    durations, exactly like the per-task meter.
    """

    def __init__(self, budget: CampaignBudget, *, clock: Clock | None = None) -> None:
        self._budget = budget
        self._clock = clock if clock is not None else MonotonicClock()
        self._started_at = self._clock.now()
        self._proposals = 0
        self._model_tokens = 0
        self._declared_wall_clock_s = 0.0

    @property
    def budget(self) -> CampaignBudget:
        """The ceiling this meter enforces."""
        return self._budget

    @property
    def proposals_charged(self) -> int:
        """Proposals recorded so far."""
        return self._proposals

    @property
    def model_tokens_charged(self) -> int:
        """Model tokens (input + output) recorded so far."""
        return self._model_tokens

    @property
    def elapsed_minutes(self) -> float:
        """Real elapsed time plus every declared duration, in minutes."""
        elapsed_s = self._clock.now() - self._started_at + self._declared_wall_clock_s
        return elapsed_s / _SECONDS_PER_MINUTE

    def can_charge_proposals(
        self, count: int, *, input_tokens: int = 0, output_tokens: int = 0
    ) -> bool:
        """Non-raising check: would charging `count` proposals fit?"""
        return (
            self._first_violation(proposals=count, model_tokens=input_tokens + output_tokens)
            is None
        )

    def charge_proposals(
        self, count: int, *, input_tokens: int = 0, output_tokens: int = 0
    ) -> None:
        """Record a proposal batch and its token cost, or refuse it entirely.

        Raises:
            CampaignBudgetExceededError: the charge would cross a ceiling.
                Nothing is recorded — the caller must not perform the work.
            ValueError: a negative charge.
        """
        if count < 0 or input_tokens < 0 or output_tokens < 0:
            raise ValueError("budget charges must be non-negative")
        violation = self._first_violation(
            proposals=count, model_tokens=input_tokens + output_tokens
        )
        if violation is not None:
            dimension, attempted = violation
            raise CampaignBudgetExceededError(dimension, self._budget.limit(dimension), attempted)
        self._proposals += count
        self._model_tokens += input_tokens + output_tokens

    def charge_wall_clock_s(self, seconds: float) -> None:
        """Record declared wall-clock time (deterministic backends).

        Raises:
            CampaignBudgetExceededError: the declared duration would cross
                the wall-clock ceiling.
            ValueError: a negative duration.
        """
        if seconds < 0:
            raise ValueError("wall-clock charges must be non-negative")
        violation = self._first_violation(wall_clock_s=seconds)
        if violation is not None:
            dimension, attempted = violation
            raise CampaignBudgetExceededError(dimension, self._budget.limit(dimension), attempted)
        self._declared_wall_clock_s += seconds

    def remaining(self) -> RemainingBudget:
        """The plugin-visible view: headroom per dimension, floored at zero.

        This is the *only* budget representation a strategy ever receives
        (§10.2 `RemainingBudget`) — the plugin can see what it has left
        but can neither read nor widen the ceilings themselves.
        """
        return RemainingBudget(
            proposals_remaining=max(0, self._budget.max_proposals - self._proposals),
            model_tokens_remaining=max(0, self._budget.max_model_tokens - self._model_tokens),
            wall_clock_minutes_remaining=max(
                0.0, self._budget.max_wall_clock_minutes - self.elapsed_minutes
            ),
        )

    def exhausted(self) -> bool:
        """True when any dimension has no headroom left."""
        remaining = self.remaining()
        return (
            remaining.proposals_remaining == 0
            or remaining.model_tokens_remaining == 0
            or remaining.wall_clock_minutes_remaining <= 0.0
        )

    def _first_violation(
        self,
        *,
        proposals: int = 0,
        model_tokens: int = 0,
        wall_clock_s: float = 0.0,
    ) -> tuple[str, float] | None:
        """First breached dimension and the total that breached it, in a
        fixed order so stop reasons aggregate consistently."""
        prospective: tuple[tuple[str, float], ...] = (
            ("proposals", float(self._proposals + proposals)),
            ("model_tokens", float(self._model_tokens + model_tokens)),
            ("wall_clock_minutes", self.elapsed_minutes + wall_clock_s / _SECONDS_PER_MINUTE),
        )
        for dimension, total in prospective:
            if total > self._budget.limit(dimension):
                return dimension, total
        return None


__all__ = [
    "CampaignBudget",
    "CampaignBudgetMeter",
]
