"""The F10 review-board service — approval requests, decisions, admissions.

Two-person semantics and verified approver identities are the whole
point of this layer, so they are enforced structurally, not by
convention:

- **Verified approver identities.** A decision's approver is the
  caller's authenticated workload identity (the principal built from
  the identity headers the mesh strips from untrusted ingress) — never
  a field in the request body. An approver identity a caller types into
  a payload is not an approver identity; it is a claim.
- **Two-person semantics.** The gate is not rebuilt here: tier-3
  promotion evidence is judged by the Phase 2 tier engine
  (:func:`evoruntime.selection.authority.assert_phase2_admissible`) and
  privileged-plugin admissions by
  :func:`evoruntime.plugins.privileged.admit_privileged` (FR-022). Both
  refuse anything short of two *distinct* approvers, neither of them
  the requester, and neither refusal downgrades the request to a lower
  tier to compensate.
- **Signed, read-only outcomes.** A successful admission mints one
  append-only, signed admission record. The signature is produced by
  the evaluation plane's own key behind the Phase 0 policy check (the
  same key and loader every other signed record uses); the record is
  surfaced read-only, and a record whose signature no longer verifies
  is treated as if no admission happened.

Tenant scoping is absolute, as everywhere on the control plane: every
query filters on the caller's tenant first.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from evoruntime.api.errors import (
    AdmissionRecordNotFoundError,
    ApprovalDeniedError,
    ApprovalRequestNotFoundError,
    CompensationPlanNotFoundError,
    InvalidSpecError,
    ProposalNotFoundError,
    TierPromotionRefusedError,
)
from evoruntime.api.schemas import (
    AdmissionRecordView,
    ApprovalDecisionView,
    ApprovalRequestDetail,
    ApprovalRequestView,
    CompensationPlanView,
)
from evoruntime.campaign.compensation import (
    CompensationPlanBuildError,
)
from evoruntime.campaign.compensation import (
    compensation_plan_body as _shared_compensation_plan_body,
)
from evoruntime.campaign.compensation import (
    validate_compensation_actions as _shared_validate_compensation_actions,
)
from evoruntime.core.ids import new_id
from evoruntime.core.principal import Principal
from evoruntime.db.base import session_scope
from evoruntime.db.models.approvals import (
    DECISION_KINDS,
    PROMOTION_REQUEST_KINDS,
    REQUEST_KINDS,
    AdmissionRecord,
    ApprovalDecision,
    ApprovalRequest,
    CompensationPlan,
)
from evoruntime.db.models.registry import ArtifactContent, ProposalRecord
from evoruntime.plugins.privileged import (
    AdmissionRequest,
    ApprovalRecord,
    PinnedVersion,
    PrivilegedAdmissionDeniedError,
    PrivilegedRole,
    SignedAdmissionRecord,
    admit_privileged,
    request_digest,
)
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.signing import DetachedSignature, sign, verify
from evoruntime.selection.authority import (
    APPROVAL_FREE_MAX_TIER,
    AuthorityTier,
    ResolvedRelease,
    TierApprovalEvidence,
    assert_phase2_admissible,
    resolve_authority_tier,
)
from evoruntime.selection.errors import TierRejectedError
from evoruntime.tenancy.policy import TenantPolicyRegistry

_DIGEST_PREFIX = "sha256:"

#: Privileged admissions are governance acts regardless of what the
#: plugin does (FR-022): admitting an adapter or evaluator is a tier-3
#: act even though no campaign artifact is involved.
PRIVILEGED_ADMISSION_TIER = int(AuthorityTier.TIER_3)


# The canonical plan bytes have one definition (F5): the campaign
# package owns them, and this API surface signs over the same bytes —
# a plan the API accepted and a plan the runtime verifies cannot
# disagree about what was signed.
compensation_plan_body = _shared_compensation_plan_body


def promotion_body(
    *,
    request_id: str,
    proposal_digest: str,
    tier: int,
    requested_by: str,
    approvers: tuple[str, ...],
    kind: str = "tier3_promotion",
) -> bytes:
    """Canonical bytes a promotion record's signature covers.

    G7: ``kind`` distinguishes the tier-3 and tier-4 promotion kinds —
    the tier-4 record is signed over the same fields but its kind names
    the scaffold-class promotion it attests, so a tier-3 record can never
    be re-presented as a tier-4 admission (or vice versa).
    """
    body = {
        "kind": kind,
        "request_id": request_id,
        "proposal_digest": proposal_digest,
        "tier": tier,
        "requested_by": requested_by,
        "approvers": sorted(approvers),
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_compensation_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate the F5 action shape: per-artifact compensating actions,
    each CAS or requires-execution, with an executed flag.

    Delegates to the campaign package's validator (one definition of the
    action shape) and translates the domain error into this API's
    ``InvalidSpecError`` so the HTTP contract is unchanged.
    """
    try:
        return _shared_validate_compensation_actions(actions)
    except CompensationPlanBuildError as exc:
        raise InvalidSpecError(str(exc)) from exc


class ApprovalWorkflowService:
    """The F10 review-board service bound to one deployment's signing key."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        signing_key: Ed25519PrivateKey,
        evaluator_subject: str,
        tenant_policies: TenantPolicyRegistry | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._signing_key = signing_key
        self._evaluator_subject = evaluator_subject
        # G7: the per-environment approval defaults (G6's policy plane).
        # An empty registry means every tenant resolves to the production
        # default — the conservative reading: tier 4 stays closed.
        self._tenant_policies = (
            tenant_policies if tenant_policies is not None else TenantPolicyRegistry()
        )

    # ------------------------------------------------------------------
    # Requests
    # ------------------------------------------------------------------

    def create_request(
        self,
        principal: Principal,
        *,
        kind: str,
        justification: str,
        campaign_id: str | None = None,
        proposal_id: str | None = None,
        plugin_id: str | None = None,
        content_digest: str | None = None,
        privileged_role: str | None = None,
        human_signoff: bool = False,
        manually_initiated: bool = False,
    ) -> ApprovalRequestDetail:
        """Open a review-board request and compute the tier it will be
        judged at.

        G7: a ``tier4_promotion`` request additionally records the two
        non-approver evidence legs at creation — ``human_signoff`` and
        ``manually_initiated``. They are immutable once persisted (the
        migration's evidence guard), so a request opened without them can
        never grow the legs after the fact.
        """
        if kind not in REQUEST_KINDS:
            kinds = ", ".join(REQUEST_KINDS)
            raise InvalidSpecError(f"request kind {kind!r} must be one of {kinds}")
        if not justification.strip():
            raise InvalidSpecError("justification must be a non-empty rationale")

        if kind == "privileged_admission":
            if human_signoff or manually_initiated:
                raise InvalidSpecError(
                    "human_signoff and manually_initiated are tier-4 evidence legs — "
                    "a privileged-admission request is not judged on them"
                )
            tier = self._require_privileged_target(
                plugin_id=plugin_id,
                content_digest=content_digest,
                privileged_role=privileged_role,
            )
            if campaign_id is not None or proposal_id is not None:
                raise InvalidSpecError(
                    "a privileged-admission request does not target a campaign candidate"
                )
        else:
            if plugin_id is not None or content_digest is not None or privileged_role is not None:
                raise InvalidSpecError(
                    "a promotion request does not target a plugin — use "
                    "kind='privileged_admission' for plugin admissions"
                )
            if campaign_id is None or proposal_id is None:
                raise InvalidSpecError("a promotion request requires campaign_id and proposal_id")
            tier = self._proposal_tier(principal, campaign_id, proposal_id)
            if kind == "tier4_promotion":
                self._require_tier4_admissible(
                    principal,
                    tier,
                    human_signoff=human_signoff,
                    manually_initiated=manually_initiated,
                )
            elif human_signoff or manually_initiated:
                raise InvalidSpecError(
                    "human_signoff and manually_initiated are tier-4 evidence legs — "
                    "a tier-3 promotion request is not judged on them"
                )

        request_id = new_id("apr")
        with session_scope(self._session_factory) as session:
            session.add(
                ApprovalRequest(
                    tenant_id=principal.tenant_id,
                    request_id=request_id,
                    kind=kind,
                    campaign_id=campaign_id,
                    proposal_id=proposal_id,
                    plugin_id=plugin_id,
                    content_digest=content_digest,
                    privileged_role=privileged_role,
                    tier=tier,
                    justification=justification,
                    requested_by=principal.identity_id,
                    human_signoff=human_signoff,
                    manually_initiated=manually_initiated,
                    status="pending",
                )
            )
        return self.get_request(principal, request_id)

    def _require_privileged_target(
        self,
        *,
        plugin_id: str | None,
        content_digest: str | None,
        privileged_role: str | None,
    ) -> int:
        """Validate the FR-022 target shape; the PinnedVersion model
        carries the digest-pin requirement, so construct it here to fail
        the request before anything is persisted."""
        if not plugin_id or not content_digest or not privileged_role:
            raise InvalidSpecError(
                "a privileged-admission request requires plugin_id, content_digest, "
                "and privileged_role"
            )
        try:
            PrivilegedRole(privileged_role)
        except ValueError as exc:
            raise InvalidSpecError(
                f"privileged_role {privileged_role!r} must be one of "
                f"{', '.join(r.value for r in PrivilegedRole)}"
            ) from exc
        try:
            PinnedVersion(plugin_id=plugin_id, digest=content_digest)
        except Exception as exc:
            raise InvalidSpecError(
                f"content_digest {content_digest!r} is not a pinned version: {exc}"
            ) from exc
        return PRIVILEGED_ADMISSION_TIER

    def _proposal_tier(self, principal: Principal, campaign_id: str, proposal_id: str) -> int:
        """The §13.3 tier the candidate's artifact class resolves to.

        Computed by the E4 engine on a single-class resolved release —
        the same classification the release plane will apply at
        promotion, so the review board and the gate can never disagree
        about what a candidate is worth.
        """
        with session_scope(self._session_factory) as session:
            proposal = self._require_proposal(
                session, principal.tenant_id, campaign_id, proposal_id
            )
            artifact = session.execute(
                select(ArtifactContent).where(
                    ArtifactContent.tenant_id == principal.tenant_id,
                    ArtifactContent.digest == proposal.proposed_digest,
                )
            ).scalar_one_or_none()
            if artifact is None:
                raise ProposalNotFoundError(f"no candidate {proposal_id!r} in this tenant")
            artifact_type = artifact.artifact_type
        tier = resolve_authority_tier(ResolvedRelease(artifact_classes=(artifact_type,)))
        if tier <= APPROVAL_FREE_MAX_TIER:
            raise InvalidSpecError(
                f"candidate {proposal_id!r} resolves to tier {int(tier)} "
                f"({artifact_type}) — review-board approval is only for tier-3/4 promotions"
            )
        return int(tier)

    def get_request(self, principal: Principal, request_id: str) -> ApprovalRequestDetail:
        with session_scope(self._session_factory) as session:
            request = self._require_request(session, principal.tenant_id, request_id)
            decisions = self._request_decisions(session, principal.tenant_id, request_id)
            return _request_detail(request, decisions)

    def list_requests(
        self, principal: Principal, *, campaign_id: str | None = None
    ) -> list[ApprovalRequestView]:
        with session_scope(self._session_factory) as session:
            query = select(ApprovalRequest).where(ApprovalRequest.tenant_id == principal.tenant_id)
            if campaign_id is not None:
                query = query.where(ApprovalRequest.campaign_id == campaign_id)
            rows = session.scalars(query.order_by(ApprovalRequest.created_at)).all()
            return [_request_view(row) for row in rows]

    # ------------------------------------------------------------------

    def _require_tier4_admissible(
        self,
        principal: Principal,
        tier: int,
        *,
        human_signoff: bool,
        manually_initiated: bool,
    ) -> None:
        """G7 — refuse a tier-4 request that cannot carry the full chain.

        Three refusals, each typed at the boundary where it is knowable:

        - the candidate must actually resolve to tier 4 (a scaffold-class
          promotion opened as ``tier4_promotion`` when the E4 engine says
          tier 3 is a vocabulary error, not a weaker request);
        - the tenant's per-environment approval defaults (G6's policy
          plane) must allow tier 4 at all — production tenants cannot
          open tier-4 requests no matter what evidence they attach;
        - both non-approver evidence legs must already be present, since
          the columns are immutable once persisted.
        """
        if tier != 4:
            raise InvalidSpecError(
                f"candidate resolves to tier {tier}, not 4 — open a "
                f"tier3_promotion request for this candidate"
            )
        policy = self._tenant_policies.policy_for(principal.tenant_id)
        if policy is None or not policy.allows_tier(4):
            raise ApprovalDeniedError(
                "tier4_environment_refused",
                "this tenant's approval policy does not allow tier-4 promotions — "
                "tier-4 requests require a tier-4-allowing policy document (G7)",
            )
        if not (human_signoff and manually_initiated):
            missing = [
                name
                for name, value in (
                    ("human_signoff", human_signoff),
                    ("manually_initiated", manually_initiated),
                )
                if not value
            ]
            raise InvalidSpecError(
                "a tier-4 promotion request requires the full evidence chain at "
                f"creation; missing: {', '.join(missing)} (G7)"
            )

    # Decisions
    # ------------------------------------------------------------------

    def decide(
        self,
        principal: Principal,
        *,
        request_id: str,
        decision: str,
        note: str = "",
    ) -> ApprovalDecisionView:
        """Record one review-board decision by the *verified* caller.

        The approver is ``principal.identity_id`` — the authenticated
        workload identity, never a body field. Self-approval is refused
        (the requester cannot approve their own request), and a second
        decision by the same identity is refused: one person, one
        decision, no matter how many times they call.
        """
        if decision not in DECISION_KINDS:
            raise InvalidSpecError(
                f"decision {decision!r} must be one of {', '.join(DECISION_KINDS)}"
            )
        approver = principal.identity_id
        with session_scope(self._session_factory) as session:
            request = self._require_request(session, principal.tenant_id, request_id)
            if request.status in ("rejected", "admitted"):
                raise ApprovalDeniedError(
                    "review_closed",
                    f"request {request_id} is {request.status} — the review is closed",
                )
            if decision == "approve" and approver.casefold() == request.requested_by.casefold():
                raise ApprovalDeniedError(
                    "self_approval",
                    f"requester {approver!r} cannot approve their own request "
                    "(self-approval refused)",
                )
            existing = session.execute(
                select(ApprovalDecision).where(
                    ApprovalDecision.tenant_id == principal.tenant_id,
                    ApprovalDecision.request_id == request_id,
                    ApprovalDecision.approver == approver,
                )
            ).scalar_one_or_none()
            if existing is not None:
                raise ApprovalDeniedError(
                    "duplicate_approver",
                    f"{approver!r} has already decided request {request_id} ({existing.decision})",
                )
            decision_row = ApprovalDecision(
                tenant_id=principal.tenant_id,
                decision_id=new_id("dec"),
                request_id=request_id,
                decision=decision,
                approver=approver,
                approver_role=principal.role.value,
                note=note,
            )
            session.add(decision_row)
            # autoflush is off on this session factory: the projection
            # re-queries decisions, so the row just added must be flushed
            # or the rejection/approval it carries is invisible to it.
            session.flush()
            self._project_request_status(session, request)
        return self.get_decision(principal, request_id, approver)

    def _project_request_status(self, session: Session, request: ApprovalRequest) -> None:
        """Recompute the request's status from its decisions.

        Any rejection closes the review; two distinct approvals mark it
        approved (admission still has to mint the signed record).
        """
        decisions = self._request_decisions(session, request.tenant_id, request.request_id)
        if any(row.decision == "reject" for row in decisions):
            request.status = "rejected"
        elif len({row.approver.casefold() for row in rows_where(decisions, "approve")}) >= 2:
            request.status = "approved"
        request.updated_at = datetime.now(UTC)

    def get_decision(
        self, principal: Principal, request_id: str, approver: str
    ) -> ApprovalDecisionView:
        with session_scope(self._session_factory) as session:
            self._require_request(session, principal.tenant_id, request_id)
            row = session.execute(
                select(ApprovalDecision).where(
                    ApprovalDecision.tenant_id == principal.tenant_id,
                    ApprovalDecision.request_id == request_id,
                    ApprovalDecision.approver == approver,
                )
            ).scalar_one_or_none()
            if row is None:
                raise ApprovalRequestNotFoundError(
                    f"no decision by {approver!r} on request {request_id!r}"
                )
            return _decision_view(row)

    # ------------------------------------------------------------------
    # Admission (the two-person gate)
    # ------------------------------------------------------------------

    def admit(self, principal: Principal, *, request_id: str) -> AdmissionRecordView:
        """Mint the signed admission record for a fully-approved request.

        The two-person gate is delegated, never reimplemented: tier-3
        promotion evidence goes through the Phase 2 tier gate, privileged
        admissions through FR-022's ``admit_privileged`` (which also
        re-checks that only the evaluator role signs governance
        artifacts). A refusal is a refusal — the promotion is never
        downgraded to a lower tier to let it through.
        """
        try:
            return self._admit_locked(principal, request_id)
        except IntegrityError as exc:
            # Privileged record ids are content-derived (FR-022): a byte-
            # identical admission already minted its record. Surface that
            # as the governance fact it is, not as a 500.
            raise ApprovalDeniedError(
                "already_admitted",
                "an identical signed admission record already exists",
            ) from exc

    def _admit_locked(self, principal: Principal, request_id: str) -> AdmissionRecordView:
        with session_scope(self._session_factory) as session:
            request = self._require_request(session, principal.tenant_id, request_id)
            if request.status == "admitted":
                raise ApprovalDeniedError(
                    "already_admitted",
                    f"request {request_id} already has a signed admission record",
                )
            if request.status == "rejected":
                raise ApprovalDeniedError(
                    "review_rejected",
                    f"request {request_id} was rejected by the review board",
                )
            if request.status != "approved" and request.kind == "tier4_promotion":
                # The projection only marks a request approved once two
                # DISTINCT verified approvers have signed off — this is
                # where the two-person rule binds a tier-4 promotion (the
                # tier gate judges the human-evidence legs, not the
                # approver count).
                raise ApprovalDeniedError(
                    "review_not_approved",
                    f"request {request_id} does not yet carry two distinct "
                    "approvals — admission requires an approved review",
                )
            # A tier-3 request that is not yet approved falls through to
            # the Phase 2 gate below, which refuses with the tier-bearing
            # error the FR-022 contract promises (the 403 body names the
            # tier that was asked for).
            decisions = self._request_decisions(session, principal.tenant_id, request_id)
            approvals = [
                ApprovalRecord(
                    approver=row.approver, approver_role=row.approver_role, note=row.note
                )
                for row in rows_where(decisions, "approve")
            ]

            if request.kind == "privileged_admission":
                signed = self._admit_privileged(request, approvals)
                record_id = signed.record_id
                request_digest_value: str | None = signed.request_digest
                proposal_digest: str | None = None
                signature = base64.b64decode(signed.signature_b64, validate=True)
                public_key = base64.b64decode(signed.signer_public_key_b64, validate=True)
                approvals_payload: list[dict[str, Any]] = [
                    approval.model_dump() for approval in signed.approvals
                ]
            else:
                approver_ids = tuple(row.approver for row in rows_where(decisions, "approve"))
                proposal = self._require_proposal(
                    session,
                    principal.tenant_id,
                    str(request.campaign_id),
                    str(request.proposal_id),
                )
                proposal_digest = proposal.proposed_digest
                # G7: the tier-4 legs ride the same evidence object the
                # Phase 2 gate already consumes — the two-person rule and
                # the non-approver legs are one admissibility check, not
                # two. The legs were frozen at request creation (the
                # migration's evidence guard), so what is judged here is
                # exactly what was recorded when the request was opened.
                try:
                    assert_phase2_admissible(
                        AuthorityTier(request.tier),
                        TierApprovalEvidence(
                            approvers=approver_ids,
                            requested_by=request.requested_by,
                            human_signoff=request.human_signoff,
                            manually_initiated=request.manually_initiated,
                        ),
                    )
                except TierRejectedError as exc:
                    raise TierPromotionRefusedError(request.tier, str(exc)) from exc
                record_id = new_id("adm")
                request_digest_value = None
                body = promotion_body(
                    request_id=request_id,
                    proposal_digest=proposal_digest,
                    tier=request.tier,
                    requested_by=request.requested_by,
                    approvers=approver_ids,
                    kind=request.kind,
                )
                detached = sign(self._signing_key, body)
                signature, public_key = detached.signature, detached.public_key
                approvals_payload = [
                    {"approver": row.approver, "approver_role": row.approver_role, "note": row.note}
                    for row in rows_where(decisions, "approve")
                ]

            session.add(
                AdmissionRecord(
                    tenant_id=principal.tenant_id,
                    record_id=record_id,
                    request_id=request_id,
                    kind=request.kind,
                    decision="admitted",
                    plugin_id=request.plugin_id,
                    content_digest=request.content_digest,
                    privileged_role=request.privileged_role,
                    proposal_digest=proposal_digest,
                    tier=request.tier,
                    requested_by=request.requested_by,
                    request_digest=request_digest_value,
                    approvals=approvals_payload,
                    signature=signature,
                    signer_public_key=public_key,
                )
            )
            request.status = "admitted"
            request.updated_at = datetime.now(UTC)
        return self.get_admission(principal, record_id)

    def _admit_privileged(
        self, request: ApprovalRequest, approvals: list[ApprovalRecord]
    ) -> SignedAdmissionRecord:
        """Run the FR-022 privileged-admission gate and map its denial
        reasons onto control-plane errors."""
        admission_request = AdmissionRequest(
            pinned=PinnedVersion(
                plugin_id=str(request.plugin_id), digest=str(request.content_digest)
            ),
            privileged_role=PrivilegedRole(str(request.privileged_role)),
            requested_by=request.requested_by,
            justification=request.justification,
        )
        signer_identity = WorkloadIdentity(
            role=WorkloadRole.EVALUATOR, subject=self._evaluator_subject
        )
        try:
            return admit_privileged(
                admission_request,
                approvals,
                signer_identity=signer_identity,
                private_key=self._signing_key,
            )
        except PrivilegedAdmissionDeniedError as exc:
            raise ApprovalDeniedError(exc.reason.value, str(exc)) from exc

    def get_admission(self, principal: Principal, record_id: str) -> AdmissionRecordView:
        with session_scope(self._session_factory) as session:
            row = self._require_admission(session, principal.tenant_id, record_id)
            return _admission_view(row)

    def list_admissions(
        self, principal: Principal, *, request_id: str | None = None
    ) -> list[AdmissionRecordView]:
        with session_scope(self._session_factory) as session:
            query = select(AdmissionRecord).where(AdmissionRecord.tenant_id == principal.tenant_id)
            if request_id is not None:
                query = query.where(AdmissionRecord.request_id == request_id)
            rows = session.scalars(query.order_by(AdmissionRecord.created_at)).all()
            return [_admission_view(row) for row in rows]

    # ------------------------------------------------------------------
    # Compensation plans (F5 record type — F10 read surface)
    # ------------------------------------------------------------------

    def record_compensation_plan(
        self,
        principal: Principal,
        *,
        actions: list[dict[str, Any]],
        campaign_id: str | None = None,
        manifest_digest: str | None = None,
    ) -> CompensationPlanView:
        """Validate, digest, sign, and persist a compensation plan.

        F10 ships the record type and its write/read surface; the
        orchestrator hooks that execute plans between APPROVE and CANARY
        are F5's, and the release-plane check that refuses promotion on
        an unexecuted requires-execution action reads these rows.
        """
        validated = validate_compensation_actions(actions)
        plan_id = new_id("cpl")
        body = compensation_plan_body(
            plan_id=plan_id,
            campaign_id=campaign_id,
            manifest_digest=manifest_digest,
            actions=validated,
        )
        plan_digest = _DIGEST_PREFIX + hashlib.sha256(body).hexdigest()
        detached = sign(self._signing_key, body)
        with session_scope(self._session_factory) as session:
            session.add(
                CompensationPlan(
                    tenant_id=principal.tenant_id,
                    plan_id=plan_id,
                    campaign_id=campaign_id,
                    manifest_digest=manifest_digest,
                    actions=validated,
                    plan_digest=plan_digest,
                    signature=detached.signature,
                    signer_public_key=detached.public_key,
                )
            )
        return self.get_compensation_plan(principal, plan_id)

    def get_compensation_plan(self, principal: Principal, plan_id: str) -> CompensationPlanView:
        with session_scope(self._session_factory) as session:
            row = session.execute(
                select(CompensationPlan).where(
                    CompensationPlan.tenant_id == principal.tenant_id,
                    CompensationPlan.plan_id == plan_id,
                )
            ).scalar_one_or_none()
            if row is None:
                raise CompensationPlanNotFoundError(
                    f"no compensation plan {plan_id!r} in this tenant"
                )
            return _compensation_plan_view(row)

    def list_compensation_plans(
        self, principal: Principal, *, campaign_id: str | None = None
    ) -> list[CompensationPlanView]:
        with session_scope(self._session_factory) as session:
            query = select(CompensationPlan).where(
                CompensationPlan.tenant_id == principal.tenant_id
            )
            if campaign_id is not None:
                query = query.where(CompensationPlan.campaign_id == campaign_id)
            rows = session.scalars(query.order_by(CompensationPlan.created_at)).all()
            return [_compensation_plan_view(row) for row in rows]

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _require_request(
        self, session: Session, tenant_id: str, request_id: str
    ) -> ApprovalRequest:
        request = session.execute(
            select(ApprovalRequest).where(
                ApprovalRequest.tenant_id == tenant_id,
                ApprovalRequest.request_id == request_id,
            )
        ).scalar_one_or_none()
        if request is None:
            raise ApprovalRequestNotFoundError(f"no approval request {request_id!r} in this tenant")
        return request

    def _require_proposal(
        self, session: Session, tenant_id: str, campaign_id: str, proposal_id: str
    ) -> ProposalRecord:
        proposal = session.execute(
            select(ProposalRecord).where(
                ProposalRecord.tenant_id == tenant_id,
                ProposalRecord.proposal_id == proposal_id,
            )
        ).scalar_one_or_none()
        if proposal is None:
            raise ProposalNotFoundError(f"no candidate {proposal_id!r} in this tenant")
        if proposal.campaign_id != campaign_id:
            raise InvalidSpecError(
                f"candidate {proposal_id} does not belong to campaign {campaign_id}"
            )
        return proposal

    def _require_admission(
        self, session: Session, tenant_id: str, record_id: str
    ) -> AdmissionRecord:
        row = session.execute(
            select(AdmissionRecord).where(
                AdmissionRecord.tenant_id == tenant_id,
                AdmissionRecord.record_id == record_id,
            )
        ).scalar_one_or_none()
        if row is None:
            raise AdmissionRecordNotFoundError(f"no admission record {record_id!r} in this tenant")
        return row

    def _request_decisions(
        self, session: Session, tenant_id: str, request_id: str
    ) -> list[ApprovalDecision]:
        rows = session.scalars(
            select(ApprovalDecision)
            .where(
                ApprovalDecision.tenant_id == tenant_id,
                ApprovalDecision.request_id == request_id,
            )
            .order_by(ApprovalDecision.created_at)
        ).all()
        return list(rows)


# ----------------------------------------------------------------------
# Module-level helpers
# ----------------------------------------------------------------------


def dict_rows(values: list[object]) -> list[dict[str, Any]]:
    """Validate a JSONB-stored list into a list of dicts.

    JSONB columns are typed ``list[object]`` because PostgreSQL will
    happily return any JSON shape; every writer in this module stores
    dicts, so a non-dict element means the row was written by something
    else — surface that instead of rendering a lie.
    """
    rows: list[dict[str, Any]] = []
    for item in values:
        if not isinstance(item, dict):
            raise ValueError(f"expected a JSON object, got {type(item).__name__}")
        rows.append(item)
    return rows


def rows_where(decisions: list[ApprovalDecision], decision: str) -> list[ApprovalDecision]:
    """The decisions matching one verdict, in recorded order."""
    return [row for row in decisions if row.decision == decision]


def _request_view(row: ApprovalRequest) -> ApprovalRequestView:
    return ApprovalRequestView(
        request_id=row.request_id,
        kind=row.kind,
        campaign_id=row.campaign_id,
        proposal_id=row.proposal_id,
        plugin_id=row.plugin_id,
        content_digest=row.content_digest,
        privileged_role=row.privileged_role,
        tier=row.tier,
        justification=row.justification,
        requested_by=row.requested_by,
        human_signoff=row.human_signoff,
        manually_initiated=row.manually_initiated,
        status=row.status,
        created_at=row.created_at,
    )


def _decision_view(row: ApprovalDecision) -> ApprovalDecisionView:
    return ApprovalDecisionView(
        decision_id=row.decision_id,
        request_id=row.request_id,
        decision=row.decision,
        approver=row.approver,
        approver_role=row.approver_role,
        note=row.note,
        created_at=row.created_at,
    )


def _request_detail(
    row: ApprovalRequest, decisions: list[ApprovalDecision]
) -> ApprovalRequestDetail:
    detail = _request_view(row).model_dump()
    detail["decisions"] = tuple(_decision_view(decision) for decision in decisions)
    return ApprovalRequestDetail.model_validate(detail)


def _admission_view(row: AdmissionRecord) -> AdmissionRecordView:
    return AdmissionRecordView(
        record_id=row.record_id,
        request_id=row.request_id,
        kind=row.kind,
        decision=row.decision,
        plugin_id=row.plugin_id,
        content_digest=row.content_digest,
        privileged_role=row.privileged_role,
        proposal_digest=row.proposal_digest,
        tier=row.tier,
        requested_by=row.requested_by,
        request_digest=row.request_digest,
        approvals=dict_rows(row.approvals),
        signature_b64=base64.b64encode(row.signature).decode("ascii"),
        signer_public_key_b64=base64.b64encode(row.signer_public_key).decode("ascii"),
        created_at=row.created_at,
    )


def _compensation_plan_view(row: CompensationPlan) -> CompensationPlanView:
    return CompensationPlanView(
        plan_id=row.plan_id,
        campaign_id=row.campaign_id,
        manifest_digest=row.manifest_digest,
        actions=dict_rows(row.actions),
        plan_digest=row.plan_digest,
        signature_b64=base64.b64encode(row.signature).decode("ascii"),
        signer_public_key_b64=base64.b64encode(row.signer_public_key).decode("ascii"),
        created_at=row.created_at,
    )


def verify_admission_signature(
    row: AdmissionRecord, *, request: AdmissionRequest | None = None
) -> bool:
    """Verify a stored admission record's signature against its body.

    For privileged admissions the body is the FR-022 record's canonical
    unsigned bytes; for tier-3/4 promotions it is the canonical promotion
    body (the kind is part of the signed bytes, so a tier-3 record can
    never verify as a tier-4 admission). False means the record no longer
    vouches for an admission anyone made — tampering, not a soft failure.
    """
    detached = DetachedSignature(signature=row.signature, public_key=row.signer_public_key)
    if row.kind in PROMOTION_REQUEST_KINDS:
        approvers = tuple(
            str(item.get("approver", "")) for item in row.approvals if isinstance(item, dict)
        )
        body = promotion_body(
            request_id=row.request_id,
            proposal_digest=str(row.proposal_digest),
            tier=int(row.tier or 0),
            requested_by=row.requested_by,
            approvers=approvers,
            kind=row.kind,
        )
        return verify(detached, body)
    if request is None:
        return False
    unsigned = {
        "record_id": row.record_id,
        "request_digest": row.request_digest,
        "decision": row.decision,
        "admitted_version": {
            "plugin_id": row.plugin_id,
            "digest": row.content_digest,
        },
        "privileged_role": row.privileged_role,
        "approvals": list(row.approvals),
    }
    canonical = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    return verify(detached, canonical)


def admission_request_digest(request: AdmissionRequest) -> str:
    """Re-export of the FR-022 request digest for callers that need the
    request's content address without importing the plugin module."""
    return request_digest(request)


__all__ = [
    "PRIVILEGED_ADMISSION_TIER",
    "ApprovalWorkflowService",
    "admission_request_digest",
    "compensation_plan_body",
    "promotion_body",
    "validate_compensation_actions",
    "verify_admission_signature",
]
