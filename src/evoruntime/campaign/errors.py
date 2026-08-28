"""Typed campaign-orchestrator errors.

Collected in one module, like `evoruntime.eval.errors`, so the set of
failures a campaign caller must handle is auditable in one place. The
split that matters: `InvalidCampaignSpecError` and `SpecTamperedError`
are construction-time refusals (a campaign that cannot be trusted should
never start), while `InvalidTransitionError`, `MutationMaskViolationError`,
and `CampaignBudgetExceededError` are runtime enforcement — the state
machine, the mutation mask, and the budget meter refusing to be crossed.
"""

from __future__ import annotations


class CampaignError(Exception):
    """Base class for campaign-orchestrator failures."""


class InvalidCampaignSpecError(CampaignError):
    """A campaign spec was declared in a way the orchestrator cannot run.

    Raised at construction time, not run time: every field a campaign pins
    is pinned *before* search begins, so a spec that fails validation never
    burns a single token.
    """


class SpecTamperedError(CampaignError):
    """A pinned campaign spec failed digest or signature verification.

    The spec is signed before search begins; an orchestrator handed bytes
    that no longer match their digest or signature is looking at a spec
    someone edited after the fact, and refuses to run it.
    """


class InvalidTransitionError(CampaignError):
    """A lifecycle transition the state machine does not allow.

    Carries the phase the campaign is in and the phase that was requested,
    so a caller that drives the machine programmatically learns which edge
    is missing rather than that "something" was refused.
    """

    def __init__(self, from_phase: str, to_phase: str, allowed: tuple[str, ...]) -> None:
        self.from_phase = from_phase
        self.to_phase = to_phase
        self.allowed = allowed
        super().__init__(
            f"illegal campaign transition {from_phase!r} -> {to_phase!r} "
            f"(allowed from here: {', '.join(allowed) or 'nothing — terminal phase'})"
        )


class MutationMaskViolationError(CampaignError):
    """A candidate or patch edits paths outside the campaign's mutation mask.

    FR-006: the violation is a *validation* failure, raised before any
    execution — never discovered mid-run by an artifact that was already
    rendered.
    """

    def __init__(self, violations: tuple[str, ...]) -> None:
        self.violations = violations
        super().__init__(f"mutation mask violations: {'; '.join(violations)}")


class CampaignBudgetExceededError(CampaignError):
    """A charge would push the campaign past one of its ceilings.

    Carries the dimension that was hit so the orchestrator can record *why*
    a campaign stopped — a campaign that ran out of proposals and one that
    ran out of wall clock are different findings about the same spec.
    """

    def __init__(self, dimension: str, limit: float, attempted: float) -> None:
        self.dimension = dimension
        self.limit = limit
        self.attempted = attempted
        super().__init__(
            f"campaign budget exhausted on {dimension}: attempted {attempted:g}, ceiling {limit:g}"
        )


class CampaignCheckpointError(CampaignError):
    """A checkpoint could not be loaded, parsed, or verified.

    A checkpoint that does not hash to its own content address is not a
    resume point, it is a forgery (or corruption) — either way the
    orchestrator refuses to reconstruct from it rather than resuming a
    campaign whose history it cannot trust.
    """


__all__ = [
    "CampaignBudgetExceededError",
    "CampaignCheckpointError",
    "CampaignError",
    "InvalidCampaignSpecError",
    "InvalidTransitionError",
    "MutationMaskViolationError",
    "SpecTamperedError",
]
