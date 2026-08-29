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


class ScaffoldEnvironmentRefusedError(InvalidCampaignSpecError):
    """A scaffold-mutable spec declared an environment other than research.

    Phase 3 (G6): scaffold mutation exists only in the research tenant —
    a spec whose mutable set contains a scaffold-class artifact must pin
    `environment: research` at construction, before anything can be
    pinned, signed, or run. A distinct type (not just a message) lets the
    control plane audit the refusal at the spec-construction boundary.
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


class UnexecutedCompensationError(CampaignError):
    """A declared requires-execution compensation has no execution record.

    F5: promotion is refused while a non-CAS compensating action is
    declared and not executed — a rollback that leaves external state
    mutated is not a rollback, it is a release with extra steps. Carries
    the plan, the action's position, and its kind so the operator knows
    exactly which compensation is still owed.
    """

    def __init__(self, plan_id: str, action_index: int, action: str, artifact_digest: str) -> None:
        self.plan_id = plan_id
        self.action_index = action_index
        self.action = action
        self.artifact_digest = artifact_digest
        super().__init__(
            f"compensation plan {plan_id!r} action #{action_index} ({action!r}, "
            f"artifact {artifact_digest!r}) is declared requires-execution but has "
            "no execution record — promotion is refused"
        )


class CompensationPlanTamperedError(CampaignError):
    """A compensation plan failed digest or signature verification.

    The plan is signed and content-addressed like a pinned spec; bytes
    that no longer hash to their address or verify against their
    signature are a forgery (or corruption), and are refused rather than
    trusted to gate promotion.
    """


class CompensationPlanBuildError(CampaignError):
    """A compensation plan could not be built or its actions are malformed.

    Raised at plan-construction time: an action without an artifact
    digest, with an unknown execution mode, or targeting an artifact type
    with no resolved candidate digest is not a plan, it is a refusal.
    """


class ScaffoldRestoreError(CampaignError):
    """A scaffold-source restore (G8) could not be completed honestly.

    The restore is a digest-verified registry read: the scaffold's file
    map must re-hash to the scaffold digest, every member module's bytes
    must re-hash to its pinned module digest, and the bytes written to
    the working tree must match what the registry returned. Any mismatch
    is corruption or tampering — the rollback is not discharged on a
    restore that cannot prove what it wrote.
    """


class ConformanceRerunFailedError(CampaignError):
    """A rerun_conformance_suite compensation (G8) did not prove zero
    regressions.

    The rollback's discharge check: the restored scaffold source must
    pass its own pinned conformance suite before the plan counts as
    executed. A suite that fails, times out, or produces unparseable
    output leaves the compensation unexecuted — the promotion check
    keeps refusing until the plan is discharged honestly.
    """


__all__ = [
    "CampaignBudgetExceededError",
    "CampaignCheckpointError",
    "CampaignError",
    "CompensationPlanBuildError",
    "CompensationPlanTamperedError",
    "ConformanceRerunFailedError",
    "InvalidCampaignSpecError",
    "InvalidTransitionError",
    "MutationMaskViolationError",
    "ScaffoldRestoreError",
    "SpecTamperedError",
    "UnexecutedCompensationError",
]
