"""Refusal auditing for the tenant-environment plane (Phase 3, G6).

Every scaffold-mutation boundary refusal is recorded — the append-only
``tenant_policy_refusals`` table is the durable record, and the
``evoruntime.audit`` log line is what a SIEM alerts on. The pattern is the
holdout query ledger's (D5): denials are committed *before* they are
raised, because a refusal recorded inside the transaction that then
raises would be rolled back with it — an audit trail of successes only is
not an audit trail.

The pure spec constructor (:mod:`evoruntime.campaign.spec`) has no
session and cannot write rows; its refusals are audited by the control
plane that invoked it (``CampaignApiService.create_campaign`` records the
``spec_construction`` boundary before re-raising).
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from evoruntime.db.models.tenancy import TenantPolicyRefusal
from evoruntime.selection.errors import RecursiveClaimDeniedError
from evoruntime.selection.recursive_gate import (
    RecursiveClaimVerdict,
    assert_label_allowed,
)
from evoruntime.tenancy.boundaries import (
    AUTO_PROMOTION_REQUIRES_REVIEW,
    RECURSIVE_CLAIMS_RESEARCH_ONLY,
    SCAFFOLD_REQUIRES_RESEARCH,
    RefusalBoundary,
)
from evoruntime.tenancy.environment import TenantEnvironment
from evoruntime.tenancy.errors import TenantRefusalError
from evoruntime.tenancy.policy import TenantPolicyRegistry

__all__ = [
    "AUTO_PROMOTION_REQUIRES_REVIEW",
    "RECURSIVE_CLAIMS_RESEARCH_ONLY",
    "RefusalBoundary",
    "SCAFFOLD_REQUIRES_RESEARCH",
    "assert_auto_promotion_allowed",
    "assert_recursive_label_allowed",
    "record_refusal",
]

audit_log = logging.getLogger("evoruntime.audit")


def record_refusal(
    session: Session,
    *,
    tenant_id: str,
    boundary: RefusalBoundary,
    reason: str,
    detail: dict[str, Any] | None = None,
    actor: str = "",
) -> TenantPolicyRefusal:
    """Append one refusal row to the ledger and emit the audit log line.

    The caller owns the commit discipline: record the row, commit, *then*
    raise — the datasets service's rule. The log line is emitted here so
    every refusal path sounds the same alarm without each boundary having
    to remember to.
    """
    row = TenantPolicyRefusal(
        tenant_id=tenant_id,
        boundary=boundary,
        reason=reason,
        detail=detail or {},
        actor=actor,
    )
    session.add(row)
    session.flush()
    audit_log.warning(
        "tenancy.refusal",
        extra={
            "tenant_id": tenant_id,
            "boundary": boundary.value,
            "reason": reason,
            "actor": actor,
        },
    )
    return row


def assert_recursive_label_allowed(
    session: Session,
    *,
    tenant_id: str,
    policies: TenantPolicyRegistry,
    label: str,
    verdict: RecursiveClaimVerdict | None,
    actor: str = "",
) -> None:
    """Boundary 4 — the recursive-label gate, environment-scoped (G4/G6).

    Routes the label through :func:`assert_label_allowed` with the
    tenant's resolved policy document — the enablement is per-environment
    policy data (G4), so the gate reads the document, not a module
    constant. A refusal is recorded in the ledger before the error is
    raised, same commit discipline as every other boundary. Callers with
    a session use this; the pure :func:`assert_label_allowed` stays
    importable for sessionless code.
    """
    document = policies.policy_for(tenant_id)
    environment = document.environment if document is not None else TenantEnvironment.PRODUCTION
    try:
        assert_label_allowed(label, verdict, tenant_policy=document)
    except RecursiveClaimDeniedError as exc:
        record_refusal(
            session,
            tenant_id=tenant_id,
            boundary=RefusalBoundary.RECURSIVE_LABEL,
            reason=RECURSIVE_CLAIMS_RESEARCH_ONLY,
            detail={"label": label, "environment": environment.value},
            actor=actor,
        )
        raise TenantRefusalError(
            RefusalBoundary.RECURSIVE_LABEL,
            RECURSIVE_CLAIMS_RESEARCH_ONLY,
            str(exc),
        ) from exc


def assert_auto_promotion_allowed(
    session: Session,
    *,
    tenant_id: str,
    policies: TenantPolicyRegistry,
    tier: int,
    actor: str = "",
) -> None:
    """The §21 decision-5 auto-promotion boundary.

    Answers one question: may this tenant's approval defaults promote
    `tier` automatically after canary, or does the promotion have to go
    through two-person review-board approval? The production seed makes
    tier 1–2 auto-eligible and tier 3+ review-gated; the regulated seed
    gates every tier. An unmapped tenant resolves to the fail-closed
    production default shape — the same answer
    :meth:`TenantPolicyRegistry.environment_for` gives — so the default
    mirrors the behavior the release plane already exhibits rather than
    inventing a stricter one.

    A refusal is recorded in the ledger before the error is raised, same
    commit discipline as every other boundary. This is the policy-plane
    primitive: like the D7 scaffolding, it ships the check, not the call
    sites — the release plane consumes it at its own promotion boundary
    when that wiring lands.
    """
    document = policies.policy_for(tenant_id)
    if document is None:
        # Fail closed to the production default shape (G6's rule), which
        # under §21 decision 5 auto-promotes tier 1–2 only.
        from evoruntime.tenancy.policy import TenantPolicyDocument

        document = TenantPolicyDocument(
            tenant_id=tenant_id,
            policy_id=f"fail-closed-default:{tenant_id}",
            environment=TenantEnvironment.PRODUCTION,
        )
    if document.auto_eligible(tier):
        return
    record_refusal(
        session,
        tenant_id=tenant_id,
        boundary=RefusalBoundary.AUTO_PROMOTION,
        reason=AUTO_PROMOTION_REQUIRES_REVIEW,
        detail={
            "tier": tier,
            "environment": document.environment.value,
            "auto_promotion_max_tier": document.auto_promotion_max_tier,
            "require_review_for_all_tiers": document.require_review_for_all_tiers,
        },
        actor=actor,
    )
    raise TenantRefusalError(
        RefusalBoundary.AUTO_PROMOTION,
        AUTO_PROMOTION_REQUIRES_REVIEW,
        f"tier-{tier} promotion is not auto-eligible under this tenant's approval "
        "defaults (§21 decision 5) — two-person review-board approval is required",
    )
