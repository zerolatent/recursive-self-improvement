"""The §12.6 claim-issuance operator path (H11).

The gate machinery — :func:`evaluate_recursive_claim`,
:func:`claim_label`, :func:`assert_recursive_label_allowed` — has existed
since G4. What it lacked was an operator path: a way for a research-tenant
operator to take assembled evidence, have the label decided by the gate
(not by the operator), and have the decision *recorded* — issued or
refused — in an append-only ledger.

Two disciplines this service enforces, in order:

1. **The gate decides, the operator records.** The label comes from
   :func:`claim_label` — the honest-label function — never from the
   request. A caller who submits unsatisfied evidence gets the honest
   label recorded as a refusal, not a recursive-improvement label.
2. **Refusals are records, not just exceptions.** A refusal is written to
   the append-only ``recursive_claim_decisions`` ledger (and to the G6
   tenant-policy refusal matrix via
   :func:`assert_recursive_label_allowed`) *before* the refusal is raised,
   so the operator path's refusals are as auditable as its issuances. The
   ledger's database trigger makes both shapes immutable after the fact.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from evoruntime.api.errors import ClaimDecisionNotFoundError, ClaimRefusedError
from evoruntime.api.schemas import ClaimDecisionView
from evoruntime.core.principal import Principal
from evoruntime.db.base import session_scope
from evoruntime.db.models.claims import RecursiveClaimDecision
from evoruntime.selection.recursive_evidence import canonical_evidence_dict, evidence_digest
from evoruntime.selection.recursive_gate import (
    RECURSIVE_IMPROVEMENT_LABEL,
    RecursiveClaimEvidence,
    RecursiveClaimVerdict,
    claim_label,
    evaluate_recursive_claim,
)
from evoruntime.tenancy.audit import assert_recursive_label_allowed as _assert_allowed
from evoruntime.tenancy.policy import TenantPolicyRegistry


class ClaimIssuanceService:
    """Append-only claim-label decisions for the §12.6 operator path."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        tenant_policies: TenantPolicyRegistry | None = None,
    ) -> None:
        self._session_factory = session_factory
        # An empty registry fails closed: every tenant is production, and
        # the recursive-improvement label is research-only.
        self._tenant_policies = tenant_policies or TenantPolicyRegistry()

    def issue_claim_label(
        self,
        principal: Principal,
        *,
        evidence: RecursiveClaimEvidence,
        campaign_id: str | None = None,
        generation1_release_digest: str | None = None,
        generation2_release_digest: str | None = None,
    ) -> ClaimDecisionView:
        """Decide the claim label from the evidence and record the decision.

        The verdict is the gate's; the label is the honest label
        :func:`claim_label` assigns under the caller's tenant policy. When
        the recursive-improvement label is refused — the evidence does not
        back it, or the tenant is not research-enabled — the refusal is
        recorded append-only first, then raised as
        :class:`ClaimRefusedError` carrying the decision id.

        Raises:
            ClaimRefusedError: the evidence does not back the
                recursive-improvement label (the refusal is already
                recorded; the error carries its decision id and reason).
        """
        verdict = evaluate_recursive_claim(evidence)
        document = self._tenant_policies.policy_for(principal.tenant_id)
        label = claim_label(verdict, tenant_policy=document)
        issued = label == RECURSIVE_IMPROVEMENT_LABEL
        actor = principal.identity_id

        if not issued:
            refusal_reason = self._record_boundary_refusal(principal, verdict, actor)
            decision = self._record_decision(
                principal,
                label=label,
                issued=False,
                verdict_satisfied=verdict.satisfied,
                refusal_reason=refusal_reason,
                evidence=evidence,
                campaign_id=campaign_id,
                generation1_release_digest=generation1_release_digest,
                generation2_release_digest=generation2_release_digest,
                actor=actor,
            )
            raise ClaimRefusedError(decision.decision_id, refusal_reason)

        decision = self._record_decision(
            principal,
            label=label,
            issued=True,
            verdict_satisfied=verdict.satisfied,
            refusal_reason=None,
            evidence=evidence,
            campaign_id=campaign_id,
            generation1_release_digest=generation1_release_digest,
            generation2_release_digest=generation2_release_digest,
            actor=actor,
        )
        return decision

    def list_claim_decisions(self, principal: Principal) -> list[ClaimDecisionView]:
        """The tenant's claim decisions, oldest first."""
        with session_scope(self._session_factory) as session:
            rows = session.scalars(
                select(RecursiveClaimDecision)
                .where(RecursiveClaimDecision.tenant_id == principal.tenant_id)
                .order_by(RecursiveClaimDecision.decided_at.asc())
            ).all()
            return [_decision_view(row) for row in rows]

    def get_claim_decision(self, principal: Principal, decision_id: str) -> ClaimDecisionView:
        """One claim decision, tenant-scoped.

        Raises:
            ClaimDecisionNotFoundError: no such decision in the caller's
                tenant (a decision in another tenant is indistinguishable
                from a decision at all).
        """
        with session_scope(self._session_factory) as session:
            row = self._get_row(session, principal, decision_id)
            return _decision_view(row)

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _record_boundary_refusal(
        self, principal: Principal, verdict: RecursiveClaimVerdict, actor: str
    ) -> str:
        """Record the G6 boundary refusal for an unissuable label.

        :func:`assert_recursive_label_allowed` audits the refusal into the
        tenant-policy refusal matrix before it raises; the raised message
        is the machine-readable reason the decision ledger stores. The
        refusal must land before the caller sees anything — a refusal that
        only raises is a refusal nobody can audit.
        """
        with session_scope(self._session_factory) as session:
            try:
                _assert_allowed(
                    session,
                    tenant_id=principal.tenant_id,
                    policies=self._tenant_policies,
                    label=RECURSIVE_IMPROVEMENT_LABEL,
                    verdict=verdict,
                    actor=actor,
                )
            except Exception as exc:
                return str(exc)
        # Unreachable in practice — an unissuable label always raises —
        # but a silent success here would hide a policy-wiring bug.
        return "the recursive-improvement label was refused for an unrecorded reason"

    def _record_decision(
        self,
        principal: Principal,
        *,
        label: str,
        issued: bool,
        verdict_satisfied: bool,
        refusal_reason: str | None,
        evidence: RecursiveClaimEvidence,
        campaign_id: str | None,
        generation1_release_digest: str | None,
        generation2_release_digest: str | None,
        actor: str,
    ) -> ClaimDecisionView:
        """Insert one append-only decision row and return its view."""
        row = RecursiveClaimDecision(
            tenant_id=principal.tenant_id,
            label=label,
            issued=issued,
            verdict_satisfied=verdict_satisfied,
            refusal_reason=refusal_reason,
            evidence=canonical_evidence_dict(evidence),
            evidence_digest=evidence_digest(evidence),
            campaign_id=campaign_id,
            generation1_release_digest=generation1_release_digest,
            generation2_release_digest=generation2_release_digest,
            actor=actor,
        )
        with session_scope(self._session_factory) as session:
            session.add(row)
            session.flush()
            return _decision_view(row)

    def _get_row(
        self, session: Session, principal: Principal, decision_id: str
    ) -> RecursiveClaimDecision:
        row = session.get(RecursiveClaimDecision, decision_id)
        if row is None or row.tenant_id != principal.tenant_id:
            raise ClaimDecisionNotFoundError(
                f"no claim decision {decision_id!r} in tenant {principal.tenant_id!r}"
            )
        return row


def _decision_view(row: RecursiveClaimDecision) -> ClaimDecisionView:
    """The wire view of one decision row."""
    return ClaimDecisionView(
        decision_id=row.id,
        tenant_id=row.tenant_id,
        label=row.label,
        issued=row.issued,
        verdict_satisfied=row.verdict_satisfied,
        refusal_reason=row.refusal_reason,
        evidence=dict(row.evidence),
        evidence_digest=row.evidence_digest,
        campaign_id=row.campaign_id,
        generation1_release_digest=row.generation1_release_digest,
        generation2_release_digest=row.generation2_release_digest,
        actor=row.actor,
        decided_at=row.decided_at,
    )


__all__ = ["ClaimIssuanceService"]
