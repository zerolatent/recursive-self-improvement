"""The FR-014 control-plane service — campaigns, candidates, approvals.

This is the application layer between the HTTP routers and the existing
E1/E2/E3 machinery. It adds as little policy of its own as possible:

- Campaign lifecycle transitions are validated by the E3 state machine
  itself — the orchestrator is rebuilt from the stored, signature-verified
  spec and transition log on every request, so the API can never take an
  edge the machine forbids and can never run a spec whose pin no longer
  verifies.
- Candidates, evaluations, approvals, and releases are recorded through
  the E1 registry service, so every write lands in the same append-only,
  signed tables the rest of the runtime trusts.
- Semantic diffs are computed by the E2 artifact adapter process contract;
  the adapter command is a deployment setting, never caller input (an API
  that spawned subprocesses from request bodies would be a remote
  execution primitive, not a diff endpoint).

Tenant scoping is absolute: every query filters on the caller's tenant
first, and a missing row in another tenant is indistinguishable from a
missing row at all.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
from datetime import UTC, datetime
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from evoruntime.api.approvals import dict_rows
from evoruntime.api.errors import (
    AdapterNotConfiguredError,
    AnalysisReportNotFoundError,
    CampaignApiError,
    CampaignNotFoundError,
    DiffUnavailableError,
    EvidenceNotFoundError,
    InvalidCampaignTransitionError,
    InvalidSpecError,
    ProposalNotFoundError,
    RegistrationRefusedError,
    ReleaseNotFoundError,
    ReleaseStateError,
)
from evoruntime.api.schemas import (
    AgentView,
    ApprovalView,
    CampaignDetail,
    CampaignSummary,
    CandidateView,
    DiffView,
    EvaluationView,
    EvidenceView,
    ParetoEntry,
    ParetoReport,
    ReleaseView,
    RollbackStatusView,
    StaticAnalysisReportView,
    TransitionView,
)
from evoruntime.campaign.errors import InvalidTransitionError, SpecTamperedError
from evoruntime.campaign.machine import CampaignOrchestrator, CampaignPhase, CampaignTransition
from evoruntime.campaign.masks import MutationMask
from evoruntime.campaign.spec import CampaignSpec, PinnedCampaignSpec, pin_and_sign
from evoruntime.core.ids import new_id
from evoruntime.core.metrics import COST_METRIC_KEYS as _COST_METRIC_KEYS
from evoruntime.core.principal import Principal
from evoruntime.db.base import session_scope
from evoruntime.db.models.analysis import AnalysisReport
from evoruntime.db.models.campaign import (
    AgentRegistration,
    CampaignRecord,
    CampaignTransitionRecord,
    EvidenceBundleRecord,
    ReleaseActivation,
)
from evoruntime.db.models.registry import (
    ArtifactStatusEvent,
    EvaluationAttestation,
    ProposalRecord,
    ReleaseManifest,
)
from evoruntime.plugins import StaticAnalysisReport, admit_output, analyze_files
from evoruntime.plugins.admission import OutputEntry
from evoruntime.plugins.manifest import EXECUTABLE_ARTIFACT_TYPES
from evoruntime.plugins.protocol import (
    AdapterPluginClient,
    CanonicalBytes,
    InMemoryCheckpointStore,
    StdioJsonRpcTransport,
    clean_plugin_env,
)
from evoruntime.registry import canonical
from evoruntime.registry.service import RegistryService
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.signing import DetachedSignature, sign

#: Metric keys the Pareto view reports as *costs* rather than gains or
#: regressions. Re-exported from `evoruntime.core.metrics` — FR-102's
#: productivity selection shares the same closed vocabulary, and a
#: vocabulary two planes agree on has one definition.
COST_METRIC_KEYS = _COST_METRIC_KEYS

#: Approval decisions the control plane records, mapped onto the E1
#: status-event kinds. "approve" is spelled "nominate" — the E1 event
#: vocabulary is the single source of lifecycle truth.
APPROVAL_DECISIONS = ("nominate", "reject", "quarantine", "revoke")

#: Activation states a release may be created in. Promotion from canary
#: is the only route to `active` through the API.
CREATE_RELEASE_STATUSES = ("canary", "active")

#: Default file path each executable artifact class's canonical bytes are
#: analyzed under when the artifact does not declare its own file bundle.
_EXECUTABLE_DEFAULT_PATHS = {
    "workflow_graph": "candidate/workflow.json",
    "tool_spec": "candidate/tool.json",
    "skill_script": "candidate/main.py",
    "algorithm": "candidate/main.py",
    "harness_patch": "candidate/patch.json",
}


def candidate_file_entries(artifact_type: str, canonical_bytes: bytes) -> list[dict[str, Any]]:
    """The file entries an executable candidate's canonical bytes declare.

    Executable artifacts may declare their payload as a JSON bundle
    ``{"files": [{"path": ..., "content": ...}]}``; anything else is
    analyzed as a single file under the class's default path. Pure.
    """
    text = canonical_bytes.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict) and isinstance(parsed.get("files"), list):
        return [entry for entry in parsed["files"] if isinstance(entry, dict)]
    return [
        {
            "path": _EXECUTABLE_DEFAULT_PATHS.get(artifact_type, "candidate/artifact.bin"),
            "content": text,
        }
    ]


def gate_executable_candidate(
    artifact_type: str, canonical_bytes: bytes, *, candidate_digest: str
) -> StaticAnalysisReport:
    """Run the pre-registration gates over an executable candidate (F10).

    Two gates, in order, both BEFORE anything is registered:

    - **FR-018 output admission** over the bundle's entries — path shape,
      size caps, confusable paths. The metadata plane; no content parsing.
    - **F3 static analysis** over the file payloads — the source-safety
      plane (network imports, subprocess spawns, dynamic exec,
      unparseable source). The mutation-mask plane is the campaign's
      concern (FR-006); at registration the artifact's own declared
      paths are allowed, so a self-contained candidate is judged on what
      its code does, not on where it sits.

    Raises:
        RegistrationRefusedError: with the refusing gate's violation
            payloads — a refusal without its violations would force the
            caller to guess which check failed.

    Returns:
        The static-analysis report, for the caller to persist as the
        audit record of the verdict the registration passed.
    """
    entries = candidate_file_entries(artifact_type, canonical_bytes)
    output_entries = [
        OutputEntry(
            path=str(entry.get("path", "")),
            size_bytes=len(str(entry.get("content", "")).encode("utf-8")),
        )
        for entry in entries
    ]
    decision = admit_output(output_entries)
    if not decision.admitted:
        raise RegistrationRefusedError(
            "fr018_output_admission",
            [violation.model_dump() for violation in decision.violations],
        )
    declared_paths = tuple(str(entry.get("path", "")) for entry in entries)
    report = analyze_files(
        entries,
        masks=(MutationMask(artifact_type=artifact_type, allowed_paths=declared_paths),),
        artifact_type=artifact_type,
        candidate_digest=candidate_digest,
    )
    if report.blocked:
        raise RegistrationRefusedError(
            "static_analysis", [violation.model_dump() for violation in report.violations]
        )
    return report


_DIGEST_PREFIX = "sha256:"


def compare_with_parent(
    candidate_metrics: dict[str, float], parent_metrics: dict[str, float]
) -> tuple[dict[str, float], dict[str, float]]:
    """Split per-metric deltas against the parent into gains and regressions.

    Pure function so the split the API reports is testable without a
    database: a metric present in both attestation sets with a positive
    delta is a gain, negative a regression, zero or absent neither —
    except for cost-shaped metrics (COST_METRIC_KEYS), where the sign
    inverts: spending more tokens or wall clock than the parent is a
    regression, spending less is a gain.
    """
    deltas = {
        key: candidate_metrics[key] - parent_metrics[key]
        for key in candidate_metrics
        if key in parent_metrics
    }
    gains: dict[str, float] = {}
    regressions: dict[str, float] = {}
    for key, delta in deltas.items():
        if delta == 0:
            continue
        good = delta < 0 if key in COST_METRIC_KEYS else delta > 0
        (gains if good else regressions)[key] = delta
    return gains, regressions


def metrics_payload_digest(metrics: dict[str, Any]) -> str:
    """Content digest over the canonical JSON of an evaluation's metrics.

    The E1 attestation record requires a payload digest; the metrics
    mapping *is* the evaluation payload the API records, so its canonical
    bytes are what the digest vouches for.
    """
    canonical = json.dumps(metrics, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _DIGEST_PREFIX + hashlib.sha256(canonical).hexdigest()


def _numeric_metrics(raw: dict[str, Any]) -> dict[str, float]:
    """Keep only numeric metric entries, coerced to float."""
    return {
        str(key): float(value)
        for key, value in raw.items()
        if isinstance(value, (int, float)) and not isinstance(value, bool)
    }


class CampaignApiService:
    """The FR-014 control-plane service bound to one deployment's signing
    key and (optionally) one artifact adapter command."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        signing_key: Ed25519PrivateKey,
        evaluator_subject: str,
        adapter_command: tuple[str, ...] = (),
    ) -> None:
        self._session_factory = session_factory
        self._signing_key = signing_key
        self._evaluator_subject = evaluator_subject
        self._adapter_command = adapter_command

    # ------------------------------------------------------------------
    # Campaigns (plan / run / inspect)
    # ------------------------------------------------------------------

    def create_campaign(self, principal: Principal, spec_mapping: dict[str, Any]) -> CampaignDetail:
        """Validate, pin, sign, and persist a campaign spec (the `plan` step).

        The spec never runs unless its canonical bytes verify against the
        stored digest AND the stored signature — the E3 machine's rule,
        enforced here at creation and at every later reconstruction.
        """
        try:
            spec = CampaignSpec.from_mapping(spec_mapping)
        except Exception as exc:  # InvalidCampaignSpecError and shape errors
            raise InvalidSpecError(f"campaign spec is invalid: {exc}") from exc
        pinned = pin_and_sign(spec, self._signing_key)
        campaign_id = new_id("camp")
        with session_scope(self._session_factory) as session:
            session.add(
                CampaignRecord(
                    tenant_id=principal.tenant_id,
                    campaign_id=campaign_id,
                    name=spec.name,
                    spec_digest=pinned.digest,
                    spec_canonical=spec.to_canonical_dict(),
                    spec_signature=pinned.signature.signature,
                    signer_public_key=pinned.signature.public_key,
                    phase=CampaignPhase.DISCOVER.value,
                )
            )
        return self.get_campaign(principal, campaign_id)

    def list_campaigns(self, principal: Principal) -> list[CampaignSummary]:
        """The caller's tenant's campaigns, oldest first."""
        with session_scope(self._session_factory) as session:
            rows = session.scalars(
                select(CampaignRecord)
                .where(CampaignRecord.tenant_id == principal.tenant_id)
                .order_by(CampaignRecord.created_at)
            ).all()
            return [self._campaign_summary(row) for row in rows]

    def get_campaign(self, principal: Principal, campaign_id: str) -> CampaignDetail:
        """One campaign with its full transition history."""
        with session_scope(self._session_factory) as session:
            record = self._require_campaign(session, principal.tenant_id, campaign_id)
            transitions = session.scalars(
                select(CampaignTransitionRecord)
                .where(
                    CampaignTransitionRecord.tenant_id == principal.tenant_id,
                    CampaignTransitionRecord.campaign_id == campaign_id,
                )
                .order_by(CampaignTransitionRecord.sequence)
            ).all()
            candidate_count = session.scalar(
                select(func.count())
                .select_from(ProposalRecord)
                .where(
                    ProposalRecord.tenant_id == principal.tenant_id,
                    ProposalRecord.campaign_id == campaign_id,
                )
            )
            detail = self._campaign_summary(record).model_dump()
            detail.update(
                resume_target=record.resume_target,
                transitions=tuple(
                    TransitionView(
                        sequence=row.sequence,
                        from_phase=row.from_phase,
                        to_phase=row.to_phase,
                        reason=row.reason,
                        occurred_at=row.occurred_at,
                    )
                    for row in transitions
                ),
                candidate_count=int(candidate_count or 0),
            )
            return CampaignDetail.model_validate(detail)

    def transition_campaign(
        self, principal: Principal, campaign_id: str, to_phase: str, *, reason: str = ""
    ) -> CampaignDetail:
        """Move the campaign one lifecycle step (the `run` step).

        Pause, cancel, and resume are the same endpoint: the E3 machine
        owns the edge table, and an illegal edge is a 409, never a silent
        no-op.
        """
        target = _parse_phase(to_phase)
        with session_scope(self._session_factory) as session:
            record = self._require_campaign(session, principal.tenant_id, campaign_id)
            orchestrator = self._rebuild_orchestrator(record)
            try:
                if target is CampaignPhase.PAUSED:
                    transition = orchestrator.pause(reason=reason)
                elif target is CampaignPhase.CANCELLED:
                    transition = orchestrator.cancel(reason=reason)
                elif orchestrator.phase is CampaignPhase.PAUSED:
                    transition = orchestrator.resume(reason=reason)
                    if transition.to_phase is not target:
                        raise InvalidCampaignTransitionError(
                            f"campaign is paused and resumes to "
                            f"{transition.to_phase.value}, not {target.value}"
                        )
                else:
                    transition = orchestrator.transition(target, reason=reason)
            except InvalidTransitionError as exc:
                raise InvalidCampaignTransitionError(str(exc)) from exc
            session.add(
                CampaignTransitionRecord(
                    tenant_id=principal.tenant_id,
                    campaign_id=campaign_id,
                    sequence=transition.sequence,
                    from_phase=transition.from_phase.value,
                    to_phase=transition.to_phase.value,
                    reason=transition.reason,
                )
            )
            record.phase = transition.to_phase.value
            record.resume_target = (
                orchestrator.resume_target.value if orchestrator.resume_target else None
            )
            record.updated_at = datetime.now(UTC)
        return self.get_campaign(principal, campaign_id)

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------

    def register_agent(
        self,
        principal: Principal,
        *,
        plugin_id: str,
        kind: str,
        pinned_image: str,
        artifact_types: list[str],
        agent_id: str | None = None,
    ) -> AgentView:
        """Record an agent plugin registration (the `agent register` step)."""
        if kind not in ("strategy", "adapter"):
            raise InvalidSpecError(f"agent kind {kind!r} must be 'strategy' or 'adapter'")
        if not plugin_id.strip() or not pinned_image.strip():
            raise InvalidSpecError("plugin_id and pinned_image must be non-empty")
        resolved_id = agent_id or new_id("agt")
        with session_scope(self._session_factory) as session:
            session.add(
                AgentRegistration(
                    tenant_id=principal.tenant_id,
                    agent_id=resolved_id,
                    plugin_id=plugin_id,
                    kind=kind,
                    pinned_image=pinned_image,
                    artifact_types=list(artifact_types),
                    registered_by=principal.identity_id,
                )
            )
        return self.get_agent(principal, resolved_id)

    def get_agent(self, principal: Principal, agent_id: str) -> AgentView:
        with session_scope(self._session_factory) as session:
            row = self._require_agent(session, principal.tenant_id, agent_id)
            return self._agent_view(row)

    def list_agents(self, principal: Principal) -> list[AgentView]:
        with session_scope(self._session_factory) as session:
            rows = session.scalars(
                select(AgentRegistration)
                .where(AgentRegistration.tenant_id == principal.tenant_id)
                .order_by(AgentRegistration.created_at)
            ).all()
            return [self._agent_view(row) for row in rows]

    # ------------------------------------------------------------------
    # Candidates
    # ------------------------------------------------------------------

    def register_candidate(
        self,
        principal: Principal,
        *,
        artifact_type: str,
        canonical_bytes_b64: str,
        strategy_id: str,
        campaign_id: str | None = None,
        parent_digest: str | None = None,
        proposal_metadata: dict[str, Any] | None = None,
    ) -> CandidateView:
        """Register a candidate artifact and its proposal record."""
        try:
            canonical_bytes = base64.b64decode(canonical_bytes_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise InvalidSpecError("canonical_bytes_b64 is not valid base64") from exc
        with session_scope(self._session_factory) as session:
            if campaign_id is not None:
                self._require_campaign(session, principal.tenant_id, campaign_id)
            report = None
            if artifact_type in EXECUTABLE_ARTIFACT_TYPES:
                # F10: executable classes pass the FR-018 output-admission
                # and F3 static-analysis gates BEFORE anything is registered —
                # a candidate that would be refused leaves no artifact row.
                body_digest = canonical.payload_body_digest(canonical_bytes)
                candidate_digest = canonical.artifact_digest_for(
                    artifact_type=artifact_type,
                    canonical_body_digest=body_digest,
                    dependencies=[],
                    capability_requests={},
                )
                report = gate_executable_candidate(
                    artifact_type, canonical_bytes, candidate_digest=candidate_digest
                )
            registry = RegistryService(session)
            artifact = registry.register_artifact(
                tenant_id=principal.tenant_id,
                artifact_type=artifact_type,
                canonical_bytes=canonical_bytes,
            )
            if report is not None:
                self._persist_analysis_report(
                    session,
                    tenant_id=principal.tenant_id,
                    campaign_id=campaign_id,
                    report=report,
                    candidate_digest=artifact.digest,
                )
            proposal = registry.record_proposal(
                tenant_id=principal.tenant_id,
                proposed_digest=artifact.digest,
                strategy_id=strategy_id,
                parent_digest=parent_digest,
                campaign_id=campaign_id,
                proposal_metadata=proposal_metadata,
            )
            return self._candidate_view(session, principal.tenant_id, proposal)

    def list_candidates(
        self, principal: Principal, *, campaign_id: str | None = None
    ) -> list[CandidateView]:
        """The tenant's candidate proposals, optionally scoped to a campaign."""
        with session_scope(self._session_factory) as session:
            query = select(ProposalRecord).where(ProposalRecord.tenant_id == principal.tenant_id)
            if campaign_id is not None:
                query = query.where(ProposalRecord.campaign_id == campaign_id)
            proposals = session.scalars(query.order_by(ProposalRecord.created_at)).all()
            return [
                self._candidate_view(session, principal.tenant_id, proposal)
                for proposal in proposals
            ]

    def get_candidate(self, principal: Principal, proposal_id: str) -> CandidateView:
        with session_scope(self._session_factory) as session:
            proposal = self._require_proposal(session, principal.tenant_id, proposal_id)
            return self._candidate_view(session, principal.tenant_id, proposal)

    def semantic_diff(self, principal: Principal, proposal_id: str) -> DiffView:
        """Compute the candidate's semantic diff against its parent via the
        E2 artifact adapter.

        The adapter runs as an untrusted subprocess under the scrubbed
        plugin environment; its command comes from deployment settings.
        """
        if not self._adapter_command:
            raise AdapterNotConfiguredError(
                "no artifact adapter is configured for this deployment "
                "(set EVORUNTIME_ADAPTER_COMMAND to enable semantic diffs)"
            )
        with session_scope(self._session_factory) as session:
            proposal = self._require_proposal(session, principal.tenant_id, proposal_id)
            if proposal.parent_digest is None:
                raise DiffUnavailableError(
                    f"candidate {proposal_id} has no parent artifact to diff against"
                )
            registry = RegistryService(session)
            base_bytes = registry.read_artifact(
                tenant_id=principal.tenant_id, digest=proposal.parent_digest
            )
            candidate_bytes = registry.read_artifact(
                tenant_id=principal.tenant_id, digest=proposal.proposed_digest
            )
            base_digest, candidate_digest = proposal.parent_digest, proposal.proposed_digest
        diff = self._run_adapter_diff(base_digest, base_bytes, candidate_digest, candidate_bytes)
        return DiffView(
            proposal_id=proposal_id,
            base_digest=base_digest,
            candidate_digest=candidate_digest,
            unified=diff.unified,
        )

    def _run_adapter_diff(
        self, base_digest: str, base_bytes: bytes, candidate_digest: str, candidate_bytes: bytes
    ) -> Any:
        """Spawn the configured adapter and compute the semantic diff.

        The subprocess is untrusted code by contract: it gets the scrubbed
        plugin environment, a per-request deadline, and nothing else.
        """
        transport = StdioJsonRpcTransport(self._adapter_command, env=clean_plugin_env())
        client = AdapterPluginClient(transport)
        try:
            return client.semantic_diff(
                _canonical_bytes(base_digest, base_bytes),
                _canonical_bytes(candidate_digest, candidate_bytes),
            )
        finally:
            client.close()

    # ------------------------------------------------------------------
    # Analysis reports (F3 record type — F10 read surface)
    # ------------------------------------------------------------------

    def get_analysis_report(self, principal: Principal, report_id: str) -> StaticAnalysisReportView:
        """One F3 static-analysis verdict, signature bytes included."""
        with session_scope(self._session_factory) as session:
            row = session.execute(
                select(AnalysisReport).where(
                    AnalysisReport.tenant_id == principal.tenant_id,
                    AnalysisReport.report_id == report_id,
                )
            ).scalar_one_or_none()
            if row is None:
                raise AnalysisReportNotFoundError(
                    f"no analysis report {report_id!r} in this tenant"
                )
            return self._analysis_report_view(row)

    def list_analysis_reports(
        self,
        principal: Principal,
        *,
        candidate_digest: str | None = None,
        campaign_id: str | None = None,
    ) -> list[StaticAnalysisReportView]:
        """The tenant's static-analysis verdicts, optionally scoped."""
        with session_scope(self._session_factory) as session:
            query = select(AnalysisReport).where(AnalysisReport.tenant_id == principal.tenant_id)
            if candidate_digest is not None:
                query = query.where(AnalysisReport.candidate_digest == candidate_digest)
            if campaign_id is not None:
                query = query.where(AnalysisReport.campaign_id == campaign_id)
            rows = session.scalars(query.order_by(AnalysisReport.created_at)).all()
            return [self._analysis_report_view(row) for row in rows]

    def _persist_analysis_report(
        self,
        session: Session,
        *,
        tenant_id: str,
        campaign_id: str | None,
        report: StaticAnalysisReport,
        candidate_digest: str,
    ) -> None:
        """Append the F3 verdict row for a registration that passed the gate.

        The row is signed over the report's canonical bytes — the same
        tamper evidence every other verdict carries — so the audit record
        of what the gate saw is as trustworthy as the registration itself.
        """
        persisted = report.model_copy(update={"candidate_digest": candidate_digest})
        detached = sign(self._signing_key, persisted.canonical_bytes())
        session.add(
            AnalysisReport(
                tenant_id=tenant_id,
                report_id=new_id("arpt"),
                campaign_id=campaign_id,
                candidate_digest=candidate_digest,
                artifact_type=persisted.artifact_type,
                outcome=persisted.outcome,
                violations=[violation.model_dump() for violation in persisted.violations],
                verdict_digest=persisted.verdict_digest,
                signature=detached.signature,
                signer_public_key=detached.public_key,
            )
        )

    def _analysis_report_view(self, row: AnalysisReport) -> StaticAnalysisReportView:
        return StaticAnalysisReportView(
            report_id=row.report_id,
            campaign_id=row.campaign_id,
            candidate_digest=row.candidate_digest,
            artifact_type=row.artifact_type,
            outcome=row.outcome,
            violations=dict_rows(row.violations),
            verdict_digest=row.verdict_digest,
            signature_b64=base64.b64encode(row.signature).decode("ascii"),
            signer_public_key_b64=base64.b64encode(row.signer_public_key).decode("ascii"),
            created_at=row.created_at,
        )

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    def record_evidence(
        self,
        principal: Principal,
        *,
        redacted_items: list[dict[str, Any]],
        campaign_id: str | None = None,
        artifact_digest: str | None = None,
        bundle_id: str | None = None,
    ) -> EvidenceView:
        """Store an already-redacted evidence bundle (E8's bundle shape)."""
        if campaign_id is not None:
            with session_scope(self._session_factory) as session:
                self._require_campaign(session, principal.tenant_id, campaign_id)
        resolved_bundle_id = bundle_id or new_id("evb")
        with session_scope(self._session_factory) as session:
            if artifact_digest is not None:
                # Existence check keeps dangling evidence out; the FK would
                # also catch it, but a 404 beats an IntegrityError.
                RegistryService(session).get_artifact(
                    tenant_id=principal.tenant_id, digest=artifact_digest
                )
            session.add(
                EvidenceBundleRecord(
                    tenant_id=principal.tenant_id,
                    bundle_id=resolved_bundle_id,
                    campaign_id=campaign_id,
                    artifact_digest=artifact_digest,
                    redacted_items=list(redacted_items),
                )
            )
        return self.get_evidence(principal, resolved_bundle_id)

    def get_evidence(self, principal: Principal, bundle_id: str) -> EvidenceView:
        with session_scope(self._session_factory) as session:
            row = session.execute(
                select(EvidenceBundleRecord).where(
                    EvidenceBundleRecord.tenant_id == principal.tenant_id,
                    EvidenceBundleRecord.bundle_id == bundle_id,
                )
            ).scalar_one_or_none()
            if row is None:
                raise EvidenceNotFoundError(f"no evidence bundle {bundle_id!r} in this tenant")
            return _evidence_view(row)

    def list_evidence(
        self,
        principal: Principal,
        *,
        campaign_id: str | None = None,
        artifact_digest: str | None = None,
    ) -> list[EvidenceView]:
        with session_scope(self._session_factory) as session:
            query = select(EvidenceBundleRecord).where(
                EvidenceBundleRecord.tenant_id == principal.tenant_id
            )
            if campaign_id is not None:
                query = query.where(EvidenceBundleRecord.campaign_id == campaign_id)
            if artifact_digest is not None:
                query = query.where(EvidenceBundleRecord.artifact_digest == artifact_digest)
            rows = session.scalars(query.order_by(EvidenceBundleRecord.created_at)).all()
            return [_evidence_view(row) for row in rows]

    # ------------------------------------------------------------------
    # Evaluations (signed outcome attestations)
    # ------------------------------------------------------------------

    def record_evaluation(
        self,
        principal: Principal,
        *,
        artifact_digest: str,
        outcome: str,
        metrics: dict[str, Any],
    ) -> EvaluationView:
        """Sign and record an evaluation outcome for an artifact.

        The signature is the evaluation plane's (the server-held evaluator
        key), and the caller must hold the evaluator role — a candidate
        runner cannot mint outcomes for its own candidate.
        """
        if outcome not in ("pass", "fail"):
            raise CampaignApiError(f"outcome {outcome!r} must be 'pass' or 'fail'")
        _require_evaluator(principal)
        with session_scope(self._session_factory) as session:
            registry = RegistryService(session)
            attestation = registry.record_attestation(
                tenant_id=principal.tenant_id,
                evaluator=WorkloadIdentity(
                    role=WorkloadRole.EVALUATOR, subject=self._evaluator_subject
                ),
                artifact_digest=artifact_digest,
                outcome=outcome,
                result_metrics=dict(metrics),
                evaluation_payload_digest=metrics_payload_digest(dict(metrics)),
                private_key=self._signing_key,
            )
            return _evaluation_view(attestation)

    def list_evaluations(
        self, principal: Principal, *, artifact_digest: str | None = None
    ) -> list[EvaluationView]:
        with session_scope(self._session_factory) as session:
            query = select(EvaluationAttestation).where(
                EvaluationAttestation.tenant_id == principal.tenant_id
            )
            if artifact_digest is not None:
                query = query.where(EvaluationAttestation.artifact_digest == artifact_digest)
            rows = session.scalars(query.order_by(EvaluationAttestation.created_at)).all()
            return [_evaluation_view(row) for row in rows]

    # ------------------------------------------------------------------
    # Pareto results
    # ------------------------------------------------------------------

    def pareto(self, principal: Principal, campaign_id: str) -> ParetoReport:
        """Every candidate in the campaign compared against its parent.

        Deltas come from the latest signed attestation on each side; a
        candidate with no attestation yet appears with empty metrics so
        the dashboard shows it as unevaluated rather than missing.
        """
        with session_scope(self._session_factory) as session:
            record = self._require_campaign(session, principal.tenant_id, campaign_id)
            spec = _spec_from_record(record)
            proposals = session.scalars(
                select(ProposalRecord)
                .where(
                    ProposalRecord.tenant_id == principal.tenant_id,
                    ProposalRecord.campaign_id == campaign_id,
                )
                .order_by(ProposalRecord.created_at)
            ).all()
            entries = [
                _pareto_entry(
                    proposal,
                    self._latest_attestation(
                        session, principal.tenant_id, proposal.proposed_digest
                    ),
                    (
                        self._latest_attestation(
                            session, principal.tenant_id, str(proposal.parent_digest)
                        )
                        if proposal.parent_digest is not None
                        else None
                    ),
                )
                for proposal in proposals
            ]
            return ParetoReport(
                campaign_id=campaign_id,
                baseline_release_digest=spec.incumbent.release_manifest_digest,
                entries=tuple(entries),
            )

    def _latest_attestation(
        self, session: Session, tenant_id: str, artifact_digest: str
    ) -> EvaluationAttestation | None:
        return session.execute(
            select(EvaluationAttestation)
            .where(
                EvaluationAttestation.tenant_id == tenant_id,
                EvaluationAttestation.artifact_digest == artifact_digest,
            )
            .order_by(EvaluationAttestation.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()

    # ------------------------------------------------------------------
    # Approvals
    # ------------------------------------------------------------------

    def record_approval(
        self,
        principal: Principal,
        *,
        campaign_id: str,
        proposal_id: str,
        decision: str,
        reason: str | None = None,
    ) -> ApprovalView:
        """Record an approval decision as an E1 status event on the
        candidate's artifact."""
        if decision not in APPROVAL_DECISIONS:
            raise CampaignApiError(
                f"decision {decision!r} must be one of {', '.join(APPROVAL_DECISIONS)}"
            )
        with session_scope(self._session_factory) as session:
            proposal = self._require_proposal(session, principal.tenant_id, proposal_id)
            if proposal.campaign_id != campaign_id:
                raise CampaignApiError(
                    f"candidate {proposal_id} does not belong to campaign {campaign_id}"
                )
            event = RegistryService(session).append_status_event(
                tenant_id=principal.tenant_id,
                artifact_digest=proposal.proposed_digest,
                kind=decision,
                actor_identity=principal.identity_id,
                reason=reason,
            )
            return ApprovalView(
                event_id=event.event_id,
                proposal_id=proposal_id,
                artifact_digest=event.artifact_digest,
                kind=event.kind,
                actor_identity=event.actor_identity,
                reason=event.reason,
                created_at=event.created_at,
            )

    def list_approvals(self, principal: Principal, campaign_id: str) -> list[ApprovalView]:
        """Approval decisions for a campaign: status events joined to the
        campaign's proposals."""
        with session_scope(self._session_factory) as session:
            rows = session.execute(
                select(ArtifactStatusEvent, ProposalRecord)
                .join(
                    ProposalRecord,
                    (ProposalRecord.tenant_id == ArtifactStatusEvent.tenant_id)
                    & (ProposalRecord.proposed_digest == ArtifactStatusEvent.artifact_digest),
                )
                .where(
                    ArtifactStatusEvent.tenant_id == principal.tenant_id,
                    ProposalRecord.campaign_id == campaign_id,
                )
                .order_by(ArtifactStatusEvent.created_at)
            ).all()
            return [
                ApprovalView(
                    event_id=event.event_id,
                    proposal_id=proposal.proposal_id,
                    artifact_digest=event.artifact_digest,
                    kind=event.kind,
                    actor_identity=event.actor_identity,
                    reason=event.reason,
                    created_at=event.created_at,
                )
                for event, proposal in rows
            ]

    # ------------------------------------------------------------------
    # Releases: canary / promote / rollback status
    # ------------------------------------------------------------------

    def create_release(
        self,
        principal: Principal,
        *,
        artifact_digests: list[str],
        adapter_versions: dict[str, Any],
        model_routes: dict[str, Any],
        policies: dict[str, Any],
        prior_release_digest: str | None = None,
        status: str = "canary",
    ) -> ReleaseView:
        """Sign a release manifest, verify it through the FR-003 boundary,
        and record its activation state."""
        if status not in CREATE_RELEASE_STATUSES:
            raise CampaignApiError(
                f"release status {status!r} must be one of {', '.join(CREATE_RELEASE_STATUSES)}"
            )
        with session_scope(self._session_factory) as session:
            registry = RegistryService(session)
            manifest = registry.create_release_manifest(
                tenant_id=principal.tenant_id,
                artifact_digests=list(artifact_digests),
                adapter_versions=dict(adapter_versions),
                model_routes=dict(model_routes),
                policies=dict(policies),
                prior_release_digest=prior_release_digest,
                private_key=self._signing_key,
            )
            # Activation runs the FR-003 boundary (signature, membership,
            # acyclicity) before any activation state is recorded.
            registry.activate_release(
                tenant_id=principal.tenant_id,
                manifest_digest=manifest.manifest_digest,
                artifact_digests=[str(d) for d in manifest.artifact_digests],
            )
            session.add(
                ReleaseActivation(
                    tenant_id=principal.tenant_id,
                    manifest_digest=manifest.manifest_digest,
                    status=status,
                    prior_manifest_digest=prior_release_digest,
                    activated_by=principal.identity_id,
                )
            )
            return _release_view(manifest, status)

    def list_releases(self, principal: Principal) -> list[ReleaseView]:
        """The tenant's release manifests with their latest activation state."""
        with session_scope(self._session_factory) as session:
            manifests = session.scalars(
                select(ReleaseManifest)
                .where(ReleaseManifest.tenant_id == principal.tenant_id)
                .order_by(ReleaseManifest.created_at)
            ).all()
            views: list[ReleaseView] = []
            for manifest in manifests:
                latest = self._latest_activation(
                    session, principal.tenant_id, manifest.manifest_digest
                )
                views.append(_release_view(manifest, latest.status if latest else None))
            return views

    def promote_release(self, principal: Principal, manifest_digest: str) -> ReleaseView:
        """Move a canary release to active, superseding the prior active."""
        with session_scope(self._session_factory) as session:
            manifest = self._require_manifest(session, principal.tenant_id, manifest_digest)
            latest = self._latest_activation(session, principal.tenant_id, manifest_digest)
            if latest is None or latest.status != "canary":
                raise ReleaseStateError(
                    f"release {manifest_digest} is not in canary — promote runs after canary"
                )
            self._supersede_other_active(session, principal.tenant_id, manifest_digest)
            session.add(
                ReleaseActivation(
                    tenant_id=principal.tenant_id,
                    manifest_digest=manifest_digest,
                    status="active",
                    prior_manifest_digest=manifest.prior_release_digest,
                    activated_by=principal.identity_id,
                )
            )
            return _release_view(manifest, "active")

    def rollback_release(self, principal: Principal, manifest_digest: str) -> RollbackStatusView:
        """Roll a release back to its prior release, restoring that prior
        release to active."""
        with session_scope(self._session_factory) as session:
            manifest = self._require_manifest(session, principal.tenant_id, manifest_digest)
            latest = self._latest_activation(session, principal.tenant_id, manifest_digest)
            if latest is None or latest.status not in ("canary", "active"):
                raise ReleaseStateError(
                    f"release {manifest_digest} has no live activation to roll back"
                )
            session.add(
                ReleaseActivation(
                    tenant_id=principal.tenant_id,
                    manifest_digest=manifest_digest,
                    status="rolled_back",
                    prior_manifest_digest=manifest.prior_release_digest,
                    activated_by=principal.identity_id,
                )
            )
            rolled_back_to: str | None = None
            if manifest.prior_release_digest is not None:
                prior = self._require_manifest(
                    session, principal.tenant_id, manifest.prior_release_digest
                )
                self._supersede_other_active(session, principal.tenant_id, prior.manifest_digest)
                session.add(
                    ReleaseActivation(
                        tenant_id=principal.tenant_id,
                        manifest_digest=prior.manifest_digest,
                        status="active",
                        prior_manifest_digest=prior.prior_release_digest,
                        activated_by=principal.identity_id,
                    )
                )
                rolled_back_to = prior.manifest_digest
            return RollbackStatusView(
                manifest_digest=manifest_digest,
                status="rolled_back",
                prior_release_digest=manifest.prior_release_digest,
                rolled_back_to=rolled_back_to,
            )

    def rollback_status(self, principal: Principal, manifest_digest: str) -> RollbackStatusView:
        """Where a release stands with respect to rollback."""
        with session_scope(self._session_factory) as session:
            manifest = self._require_manifest(session, principal.tenant_id, manifest_digest)
            latest = self._latest_activation(session, principal.tenant_id, manifest_digest)
            status = latest.status if latest is not None else None
            return RollbackStatusView(
                manifest_digest=manifest_digest,
                status=status,
                prior_release_digest=manifest.prior_release_digest,
                rolled_back_to=manifest.prior_release_digest if status == "rolled_back" else None,
            )

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _require_campaign(
        self, session: Session, tenant_id: str, campaign_id: str
    ) -> CampaignRecord:
        record = session.execute(
            select(CampaignRecord).where(
                CampaignRecord.tenant_id == tenant_id,
                CampaignRecord.campaign_id == campaign_id,
            )
        ).scalar_one_or_none()
        if record is None:
            raise CampaignNotFoundError(f"no campaign {campaign_id!r} in this tenant")
        return record

    def _require_proposal(
        self, session: Session, tenant_id: str, proposal_id: str
    ) -> ProposalRecord:
        proposal = session.execute(
            select(ProposalRecord).where(
                ProposalRecord.tenant_id == tenant_id,
                ProposalRecord.proposal_id == proposal_id,
            )
        ).scalar_one_or_none()
        if proposal is None:
            raise ProposalNotFoundError(f"no candidate {proposal_id!r} in this tenant")
        return proposal

    def _require_agent(self, session: Session, tenant_id: str, agent_id: str) -> AgentRegistration:
        row = session.execute(
            select(AgentRegistration).where(
                AgentRegistration.tenant_id == tenant_id,
                AgentRegistration.agent_id == agent_id,
            )
        ).scalar_one_or_none()
        if row is None:
            raise CampaignApiError(f"no agent {agent_id!r} in this tenant")
        return row

    def _require_manifest(
        self, session: Session, tenant_id: str, manifest_digest: str
    ) -> ReleaseManifest:
        manifest = session.execute(
            select(ReleaseManifest).where(
                ReleaseManifest.tenant_id == tenant_id,
                ReleaseManifest.manifest_digest == manifest_digest,
            )
        ).scalar_one_or_none()
        if manifest is None:
            raise ReleaseNotFoundError(f"no release manifest {manifest_digest!r} in this tenant")
        return manifest

    def _latest_activation(
        self, session: Session, tenant_id: str, manifest_digest: str
    ) -> ReleaseActivation | None:
        return session.execute(
            select(ReleaseActivation)
            .where(
                ReleaseActivation.tenant_id == tenant_id,
                ReleaseActivation.manifest_digest == manifest_digest,
            )
            .order_by(ReleaseActivation.created_at.desc(), ReleaseActivation.id.desc())
            .limit(1)
        ).scalar_one_or_none()

    def _supersede_other_active(
        self, session: Session, tenant_id: str, manifest_digest: str
    ) -> None:
        """Mark every other manifest's active activation superseded, so
        exactly one release is active at a time."""
        actives = session.scalars(
            select(ReleaseActivation).where(
                ReleaseActivation.tenant_id == tenant_id,
                ReleaseActivation.status == "active",
                ReleaseActivation.manifest_digest != manifest_digest,
            )
        ).all()
        for row in actives:
            row.status = "superseded"

    def _rebuild_orchestrator(self, record: CampaignRecord) -> CampaignOrchestrator:
        """Rebuild the E3 orchestrator from the stored, signed spec.

        The stored signature is re-verified on every construction — a
        campaigns row edited after the fact fails verification here, not
        at some later, more expensive point.
        """
        spec = _spec_from_record(record)
        pinned = PinnedCampaignSpec(
            spec=spec,
            digest=record.spec_digest,
            signature=DetachedSignature(
                signature=record.spec_signature, public_key=record.signer_public_key
            ),
        )
        with session_scope(self._session_factory) as session:
            rows = session.scalars(
                select(CampaignTransitionRecord)
                .where(
                    CampaignTransitionRecord.tenant_id == record.tenant_id,
                    CampaignTransitionRecord.campaign_id == record.campaign_id,
                )
                .order_by(CampaignTransitionRecord.sequence)
            ).all()
            transitions = tuple(
                CampaignTransition(
                    sequence=row.sequence,
                    from_phase=CampaignPhase(row.from_phase),
                    to_phase=CampaignPhase(row.to_phase),
                    reason=row.reason,
                    at=row.occurred_at.timestamp(),
                )
                for row in rows
            )
        try:
            return CampaignOrchestrator(
                pinned,
                checkpoints=InMemoryCheckpointStore(),
                initial_phase=CampaignPhase(record.phase),
                resume_target=(
                    CampaignPhase(record.resume_target) if record.resume_target else None
                ),
                transitions=transitions,
            )
        except SpecTamperedError as exc:
            raise InvalidSpecError(f"campaign spec no longer verifies: {exc}") from exc

    def _candidate_view(
        self, session: Session, tenant_id: str, proposal: ProposalRecord
    ) -> CandidateView:
        status = RegistryService(session).current_status(
            tenant_id=tenant_id, artifact_digest=proposal.proposed_digest
        )
        return CandidateView(
            proposal_id=proposal.proposal_id,
            campaign_id=proposal.campaign_id,
            artifact_digest=proposal.proposed_digest,
            parent_digest=proposal.parent_digest,
            strategy_id=proposal.strategy_id,
            status=status,
            created_at=proposal.created_at,
        )

    def _campaign_summary(self, record: CampaignRecord) -> CampaignSummary:
        return CampaignSummary(
            campaign_id=record.campaign_id,
            name=record.name,
            phase=record.phase,
            spec_digest=record.spec_digest,
            created_at=record.created_at,
            updated_at=record.updated_at,
        )

    def _agent_view(self, row: AgentRegistration) -> AgentView:
        return AgentView(
            agent_id=row.agent_id,
            plugin_id=row.plugin_id,
            kind=row.kind,
            pinned_image=row.pinned_image,
            artifact_types=[str(t) for t in row.artifact_types],
            registered_by=row.registered_by,
            created_at=row.created_at,
        )


# ----------------------------------------------------------------------
# Module-level pure helpers (row -> view mappers)
# ----------------------------------------------------------------------


def _parse_phase(value: str) -> CampaignPhase:
    try:
        return CampaignPhase(value)
    except ValueError as exc:
        raise CampaignApiError(f"unknown campaign phase {value!r}") from exc


def _spec_from_record(record: CampaignRecord) -> CampaignSpec:
    try:
        return CampaignSpec.from_mapping(dict(record.spec_canonical))
    except Exception as exc:
        raise InvalidSpecError(f"stored campaign spec failed validation: {exc}") from exc


def _canonical_bytes(digest: str, data: bytes) -> CanonicalBytes:
    return CanonicalBytes(
        data_b64=base64.b64encode(data).decode("ascii"),
        digest=digest,
        media_type="application/octet-stream",
    )


def _evidence_view(row: EvidenceBundleRecord) -> EvidenceView:
    return EvidenceView(
        bundle_id=row.bundle_id,
        campaign_id=row.campaign_id,
        artifact_digest=row.artifact_digest,
        redacted_items=[dict(cast("dict[str, Any]", item)) for item in row.redacted_items],
        created_at=row.created_at,
    )


def _evaluation_view(row: EvaluationAttestation) -> EvaluationView:
    return EvaluationView(
        attestation_id=row.attestation_id,
        artifact_digest=row.artifact_digest,
        outcome=row.outcome,
        result_metrics=dict(row.result_metrics),
        evaluation_payload_digest=row.evaluation_payload_digest,
        evaluator_subject=row.evaluator_subject,
        created_at=row.created_at,
    )


def _release_view(manifest: ReleaseManifest, status: str | None) -> ReleaseView:
    return ReleaseView(
        manifest_id=manifest.manifest_id,
        manifest_digest=manifest.manifest_digest,
        artifact_digests=[str(d) for d in manifest.artifact_digests],
        prior_release_digest=manifest.prior_release_digest,
        status=status,
        created_at=manifest.created_at,
    )


def _pareto_entry(
    proposal: ProposalRecord,
    candidate_att: EvaluationAttestation | None,
    parent_att: EvaluationAttestation | None,
) -> ParetoEntry:
    candidate_metrics = _numeric_metrics(
        dict(candidate_att.result_metrics) if candidate_att else {}
    )
    parent_metrics = _numeric_metrics(dict(parent_att.result_metrics) if parent_att else {})
    gains, regressions = compare_with_parent(candidate_metrics, parent_metrics)
    return ParetoEntry(
        proposal_id=proposal.proposal_id,
        artifact_digest=proposal.proposed_digest,
        parent_digest=proposal.parent_digest,
        outcome=candidate_att.outcome if candidate_att else None,
        metrics=candidate_metrics,
        gains=gains,
        regressions=regressions,
        costs={key: value for key, value in candidate_metrics.items() if key in COST_METRIC_KEYS},
    )


def _require_evaluator(principal: Principal) -> None:
    """Only the evaluator role records evaluation outcomes."""
    if principal.role is not WorkloadRole.EVALUATOR:
        raise CampaignApiError("only the evaluator role may record evaluation outcomes")


__all__ = [
    "APPROVAL_DECISIONS",
    "CREATE_RELEASE_STATUSES",
    "COST_METRIC_KEYS",
    "CampaignApiService",
    "compare_with_parent",
    "metrics_payload_digest",
]
