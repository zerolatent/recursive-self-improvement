"""Campaign orchestrator (deliverable E3, PRD §11).

The §11 lifecycle state machine with persisted transitions and
content-addressed checkpoints (FR-005), the declarative §11.2 campaign
spec (validated, versioned, pinned + signed before search), externally
enforced campaign budgets, and mutation masks enforced by the artifact
adapter before any execution (FR-006).

- `evoruntime.campaign.spec` — the §11.2 document and its pinning
- `evoruntime.campaign.machine` — lifecycle phases, transitions, orchestrator
- `evoruntime.campaign.budgets` — externally enforced token/time/proposal ceilings
- `evoruntime.campaign.masks` — mutation-mask enforcement ahead of execution
- `evoruntime.campaign.errors` — the typed failure surface
"""

from __future__ import annotations

from evoruntime.campaign.budgets import CampaignBudget, CampaignBudgetMeter
from evoruntime.campaign.compensation import (
    CheckpointedCompensationGate,
    CompensationActionKind,
    CompensationExecutionRecord,
    CompensationPlanStore,
    ExecutionSink,
    InMemoryExecutionSink,
    SignedCompensationPlan,
    assert_promotion_allowed,
    classification_for_action,
    compensation_plan_body,
    execute_rollback_compensations,
    plan_actions_from_spec,
    sign_compensation_plan,
    validate_compensation_actions,
)
from evoruntime.campaign.errors import (
    CampaignBudgetExceededError,
    CampaignCheckpointError,
    CampaignError,
    CompensationPlanBuildError,
    CompensationPlanTamperedError,
    InvalidCampaignSpecError,
    InvalidTransitionError,
    MutationMaskViolationError,
    SpecTamperedError,
    UnexecutedCompensationError,
)
from evoruntime.campaign.machine import (
    CampaignOrchestrator,
    CampaignPhase,
    CampaignTransition,
    CheckpointStore,
    CompensationGate,
    InMemoryTransitionSink,
    TransitionSink,
    allowed_transitions,
    can_cancel,
    can_pause,
    is_terminal,
)
from evoruntime.campaign.masks import (
    MaskEnforcingAdapter,
    MutationMask,
    mask_violations,
    masks_from_spec,
    member_mask_violations,
)
from evoruntime.campaign.spec import (
    SUPPORTED_SPEC_VERSION,
    V1_MIGRATION_WINDOW_END,
    CampaignBudgets,
    CampaignSpec,
    CompensationActionSpec,
    CompensationPlanSection,
    DatasetBindings,
    EvaluatorBinding,
    IncumbentBinding,
    MutableArtifact,
    MutableArtifactSet,
    PinnedCampaignSpec,
    PromotionPolicyRef,
    StatisticsPlan,
    StoppingRules,
    StrategyBinding,
    pin_and_sign,
)

__all__ = [
    "SUPPORTED_SPEC_VERSION",
    "V1_MIGRATION_WINDOW_END",
    "CampaignBudget",
    "CampaignBudgetExceededError",
    "CampaignBudgetMeter",
    "CampaignBudgets",
    "CampaignCheckpointError",
    "CampaignError",
    "CampaignOrchestrator",
    "CampaignPhase",
    "CampaignSpec",
    "CampaignTransition",
    "CheckpointStore",
    "CheckpointedCompensationGate",
    "CompensationActionKind",
    "CompensationActionSpec",
    "CompensationExecutionRecord",
    "CompensationPlanBuildError",
    "CompensationPlanSection",
    "CompensationPlanStore",
    "CompensationPlanTamperedError",
    "CompensationGate",
    "DatasetBindings",
    "EvaluatorBinding",
    "ExecutionSink",
    "InMemoryExecutionSink",
    "InMemoryTransitionSink",
    "IncumbentBinding",
    "InvalidCampaignSpecError",
    "InvalidTransitionError",
    "MaskEnforcingAdapter",
    "MutableArtifact",
    "MutableArtifactSet",
    "MutationMask",
    "MutationMaskViolationError",
    "PinnedCampaignSpec",
    "PromotionPolicyRef",
    "SignedCompensationPlan",
    "SpecTamperedError",
    "StatisticsPlan",
    "StoppingRules",
    "StrategyBinding",
    "TransitionSink",
    "UnexecutedCompensationError",
    "allowed_transitions",
    "assert_promotion_allowed",
    "can_cancel",
    "can_pause",
    "classification_for_action",
    "compensation_plan_body",
    "execute_rollback_compensations",
    "is_terminal",
    "mask_violations",
    "masks_from_spec",
    "member_mask_violations",
    "pin_and_sign",
    "plan_actions_from_spec",
    "sign_compensation_plan",
    "validate_compensation_actions",
]
