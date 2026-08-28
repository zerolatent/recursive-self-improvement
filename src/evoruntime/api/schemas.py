"""Response schemas for the FR-014 control-plane API.

These are the wire shapes the API, dashboard, and `evo` CLI all share.
They are deliberately flat views over the E1/E3 records — the API serves
*resources* (what a reviewer inspects), not optimizer internals.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from evoruntime.core.schemas import EvoRuntimeBaseModel


class TransitionView(EvoRuntimeBaseModel):
    """One persisted campaign lifecycle transition."""

    sequence: int
    from_phase: str
    to_phase: str
    reason: str
    occurred_at: datetime


class CampaignSummary(EvoRuntimeBaseModel):
    """A campaign as the list endpoint and dashboard index show it."""

    campaign_id: str
    name: str
    phase: str
    spec_digest: str
    created_at: datetime
    updated_at: datetime


class CampaignDetail(CampaignSummary):
    """Full campaign record: lifecycle history plus candidate count."""

    resume_target: str | None = None
    transitions: tuple[TransitionView, ...] = ()
    candidate_count: int = 0


class AgentView(EvoRuntimeBaseModel):
    """A registered agent plugin."""

    agent_id: str
    plugin_id: str
    kind: str
    pinned_image: str
    artifact_types: list[str]
    registered_by: str
    created_at: datetime


class CandidateView(EvoRuntimeBaseModel):
    """One candidate proposal, with its lifecycle status projection."""

    proposal_id: str
    campaign_id: str | None
    artifact_digest: str
    parent_digest: str | None
    strategy_id: str
    status: str | None = None
    created_at: datetime


class DiffView(EvoRuntimeBaseModel):
    """A semantic diff between a candidate and its parent, computed by
    the E2 artifact adapter."""

    proposal_id: str
    base_digest: str
    candidate_digest: str
    unified: str


class EvidenceView(EvoRuntimeBaseModel):
    """A redacted evidence bundle attached to a campaign/candidate."""

    bundle_id: str
    campaign_id: str | None
    artifact_digest: str | None
    redacted_items: list[dict[str, Any]]
    created_at: datetime


class EvaluationView(EvoRuntimeBaseModel):
    """A signed evaluation outcome (an E1 evaluation attestation)."""

    attestation_id: str
    artifact_digest: str
    outcome: str
    result_metrics: dict[str, Any]
    evaluation_payload_digest: str
    evaluator_subject: str
    created_at: datetime


class ParetoEntry(EvoRuntimeBaseModel):
    """One candidate's comparison against its parent.

    `gains` and `regressions` split the per-metric deltas by sign; `costs`
    pulls the candidate's cost-shaped metrics forward so a reviewer can
    see what the gains were bought with.
    """

    proposal_id: str
    artifact_digest: str
    parent_digest: str | None
    outcome: str | None = None
    metrics: dict[str, float] = {}
    gains: dict[str, float] = {}
    regressions: dict[str, float] = {}
    costs: dict[str, float] = {}


class ParetoReport(EvoRuntimeBaseModel):
    """The campaign's Pareto view: every candidate against its parent."""

    campaign_id: str
    baseline_release_digest: str
    entries: tuple[ParetoEntry, ...] = ()


class ApprovalView(EvoRuntimeBaseModel):
    """One approval decision, recorded as an E1 artifact status event."""

    event_id: str
    proposal_id: str
    artifact_digest: str
    kind: str
    actor_identity: str
    reason: str | None
    created_at: datetime


class ReleaseView(EvoRuntimeBaseModel):
    """A signed release manifest plus its current activation state."""

    manifest_id: str
    manifest_digest: str
    artifact_digests: list[str]
    prior_release_digest: str | None
    status: str | None = None
    created_at: datetime


class RollbackStatusView(EvoRuntimeBaseModel):
    """Where a release stands with respect to rollback."""

    manifest_digest: str
    status: str | None
    prior_release_digest: str | None
    rolled_back_to: str | None = None
