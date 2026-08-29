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


class CampaignSpecValidation(EvoRuntimeBaseModel):
    """The result of a validate dry-run — what the spec pins, once valid.

    Deliberately a summary, not the spec: the dry-run's contract is "your
    document parses and passes the plan step's checks", and echoing the
    whole spec back would invite treating the response as a registration.
    """

    valid: bool
    schema_version: int
    name: str
    environment: str | None
    mutable_artifact_types: tuple[str, ...]
    arm_ids: tuple[str, ...]


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


class SliceSummaryView(EvoRuntimeBaseModel):
    """One slice value's aggregated outcomes and attested costs.

    Success is the pass rate over the slice's attestation outcomes; every
    cost number (including latency, `wall_clock_s`) comes from the signed
    attestation's metrics restricted to COST_METRIC_KEYS — claimed values
    never enter the archive.
    """

    dimension: str
    value: str
    attestation_count: int
    pass_count: int
    success_rate: float | None = None
    mean_costs: dict[str, float] = {}


class ArchiveEntryView(EvoRuntimeBaseModel):
    """One artifact's aggregated archive record with its frontier role.

    `on_frontier` is computed on read (dominated by nothing); membership
    is never stored, so the dominance rule stays reviewable in code.
    """

    artifact_digest: str
    proposal_ids: list[str] = []
    attestation_count: int
    pass_count: int
    success_rate: float | None = None
    mean_costs: dict[str, float] = {}
    dominates: list[str] = []
    dominated_by: list[str] = []
    on_frontier: bool = True


class ParetoArchiveReport(EvoRuntimeBaseModel):
    """The campaign's Pareto archive across slices (H5).

    `reconciled` reports whether the stored projection still equals what
    the pure builder produces from the raw append-only records; `drift`
    carries one human-readable description per discrepancy.
    """

    campaign_id: str
    slice_dimensions: list[str] = []
    frontier: list[ArchiveEntryView] = []
    slices: list[SliceSummaryView] = []
    reconciled: bool = True
    drift: list[str] = []


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


class CanaryRunView(EvoRuntimeBaseModel):
    """One canary run's measurements, read from the append-only ledger
    (H6). The FR-012 numbers ride along with the outcome."""

    run_id: str
    manifest_digest: str
    outcome: str
    paired_tasks: int
    total_sessions: int
    candidate_sessions: int
    candidate_allocation: float
    stopped_reason: str | None = None
    rolled_back_to: str | None = None
    digest_report_coverage: float
    p99_convergence_seconds: float | None = None
    observation_elapsed_seconds: float
    guardrail_events: list[dict[str, Any]] = []
    release_status: str | None = None
    created_at: datetime


class CanaryStatusView(EvoRuntimeBaseModel):
    """Where a release stands with respect to its canary runs (H6)."""

    manifest_digest: str
    release_status: str | None = None
    latest_run: CanaryRunView | None = None


class ApprovalRequestView(EvoRuntimeBaseModel):
    """A review-board request for a tier-3/4 promotion or privileged
    plugin admission (F10).

    G7: ``human_signoff`` and ``manually_initiated`` are the tier-4
    evidence legs, recorded when the request was opened and immutable
    thereafter (the migration's evidence guard). They are always false
    for tier-3 and privileged-admission requests.
    """

    request_id: str
    kind: str
    campaign_id: str | None = None
    proposal_id: str | None = None
    plugin_id: str | None = None
    content_digest: str | None = None
    privileged_role: str | None = None
    tier: int
    justification: str
    requested_by: str
    human_signoff: bool = False
    manually_initiated: bool = False
    status: str
    created_at: datetime


class ApprovalDecisionView(EvoRuntimeBaseModel):
    """One verified approver's decision on a review-board request."""

    decision_id: str
    request_id: str
    decision: str
    approver: str
    approver_role: str
    note: str
    created_at: datetime


class ApprovalRequestDetail(ApprovalRequestView):
    """A review-board request with its full decision history."""

    decisions: tuple[ApprovalDecisionView, ...] = ()


class AdmissionRecordView(EvoRuntimeBaseModel):
    """A signed admission record, surfaced read-only (F10).

    ``signature_b64``/``signer_public_key_b64`` carry the Ed25519
    detached signature over the record body — for privileged admissions
    these are the FR-022 record's own signature fields.
    """

    record_id: str
    request_id: str
    kind: str
    decision: str
    plugin_id: str | None = None
    content_digest: str | None = None
    privileged_role: str | None = None
    proposal_digest: str | None = None
    tier: int | None = None
    requested_by: str
    request_digest: str | None = None
    approvals: list[dict[str, Any]] = []
    signature_b64: str
    signer_public_key_b64: str
    created_at: datetime


class StaticAnalysisReportView(EvoRuntimeBaseModel):
    """A signed static-analysis verdict (F3 record type, read surface).

    ``signature_b64``/``signer_public_key_b64`` carry the Ed25519
    detached signature over the verdict's canonical bytes, so a caller
    can verify what the gate saw without trusting the JSON.
    """

    report_id: str
    campaign_id: str | None = None
    candidate_digest: str
    artifact_type: str
    outcome: str
    violations: list[dict[str, Any]] = []
    verdict_digest: str
    signature_b64: str
    signer_public_key_b64: str
    created_at: datetime


class DiscoveryClusterView(EvoRuntimeBaseModel):
    """One failure cluster in a discovery report (H3 read surface).

    ``category`` is a D8 taxonomy name, or None for the unclassified
    bucket — failures that matched no taxonomy entry and no signal rule
    are reported, never dropped.
    """

    category: str | None
    failure_signature: str
    trace_ids: list[str]
    representative_trace_ids: list[str]
    count: int


class DiscoveryReportView(EvoRuntimeBaseModel):
    """A signed discovery report (H3 record type, read surface).

    ``signature_b64``/``signer_public_key_b64`` carry the Ed25519 detached
    signature over the report's canonical bytes, so a caller can verify
    what discovery clustered without trusting the JSON.
    """

    report_id: str
    campaign_id: str | None = None
    agent_id: str | None = None
    release_id: str | None = None
    traces_scanned: int
    unresolved_events: int
    failure_count: int
    unclassified_count: int
    categories_hit: list[str]
    clusters: list[DiscoveryClusterView]
    report_digest: str
    signature_b64: str
    signer_public_key_b64: str
    created_at: datetime


class CompensationPlanView(EvoRuntimeBaseModel):
    """A signed compensation plan (F5 record type, read surface)."""

    plan_id: str
    campaign_id: str | None = None
    manifest_digest: str | None = None
    actions: list[dict[str, Any]] = []
    plan_digest: str
    signature_b64: str
    signer_public_key_b64: str
    created_at: datetime


class AnalysisReportView(EvoRuntimeBaseModel):
    """A signed static-analysis verdict over one candidate (F3 record
    type, read surface)."""

    report_id: str
    campaign_id: str | None = None
    candidate_digest: str
    artifact_type: str
    outcome: str
    violations: list[dict[str, Any]] = []
    verdict_digest: str
    signature_b64: str
    signer_public_key_b64: str
    created_at: datetime
