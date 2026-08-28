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
from evoruntime.campaign.errors import (
    CampaignBudgetExceededError,
    CampaignCheckpointError,
    CampaignError,
    InvalidCampaignSpecError,
    InvalidTransitionError,
    MutationMaskViolationError,
    SpecTamperedError,
)
from evoruntime.campaign.machine import (
    CampaignOrchestrator,
    CampaignPhase,
    CampaignTransition,
    CheckpointStore,
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
    "DatasetBindings",
    "EvaluatorBinding",
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
    "SpecTamperedError",
    "StatisticsPlan",
    "StoppingRules",
    "StrategyBinding",
    "TransitionSink",
    "allowed_transitions",
    "can_cancel",
    "can_pause",
    "is_terminal",
    "mask_violations",
    "masks_from_spec",
    "member_mask_violations",
    "pin_and_sign",
]
