"""HTTP-level contract tests for the G7 tier-4 review-board approval flow.

Tier 4 is the scaffold-class promotion kind — the highest-risk approval
the review board issues — so its contract is proven over the wire, not
just at the Python layer:

- the full evidence chain: two distinct verified approvers (neither the
  requester) AND the two immutable non-approver legs recorded at request
  creation (``human_signoff``, ``manually_initiated``);
- every missing leg is refused with a typed error at the boundary where
  it is knowable — creation for the legs, admission for the approvals;
- the per-environment approval defaults (G6's policy plane) gate the
  request kind itself: a tenant whose policy does not allow tier 4
  cannot even open a tier-4 request, no matter what evidence it claims.

The client here overrides the approval-service dependency with one bound
to a research-tenant policy registry built from the G7 seed documents —
the same signed policy data a deployment loads.
"""

from __future__ import annotations

import base64
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from evoruntime.api.approvals import ApprovalWorkflowService, verify_admission_signature
from evoruntime.api.service import CampaignApiService
from evoruntime.db.base import session_scope
from evoruntime.db.models.approvals import AdmissionRecord
from evoruntime.db.models.registry import ProposalRecord
from evoruntime.registry.service import RegistryService
from evoruntime.security.signing import generate_signing_key
from evoruntime.server.app import create_app
from evoruntime.server.dependencies import (
    get_approval_service,
    get_campaign_service,
    get_session_factory,
)
from evoruntime.tenancy.policy import TenantPolicyRegistry
from evoruntime.tenancy.seed import (
    seed_production_tenant_policy,
    seed_research_tenant_policy,
)
from tests.server.test_approval_flows import _decide, _headers

#: A scaffold-class candidate body (G1 class; the registry is
#: class-agnostic — the tier comes from the artifact class).
SCAFFOLD_BUNDLE = base64.b64encode(b"scaffold candidate body (g7 fixture)").decode()


@pytest.fixture
def tier4_client(session_factory: sessionmaker[Session], tenant_id: str) -> TestClient:
    """The API with both services bound to a research-tenant policy
    registry built from the G7 seed document for this test's tenant."""
    app = create_app()
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    registry = TenantPolicyRegistry([seed_research_tenant_policy(tenant_id)])
    app.dependency_overrides[get_campaign_service] = lambda: CampaignApiService(
        session_factory,
        signing_key=generate_signing_key(),
        evaluator_subject="svc_evaluator_g7",
        tenant_policies=registry,
    )
    app.dependency_overrides[get_approval_service] = lambda: ApprovalWorkflowService(
        session_factory,
        signing_key=generate_signing_key(),
        evaluator_subject="svc_evaluator_g7",
        tenant_policies=registry,
    )
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _plan_scaffold_campaign(client: TestClient, headers: dict[str, str]) -> dict[str, Any]:
    """Create a scaffold-mutable campaign in the research tenant (G1+G6)."""
    from tests.support.factories import make_campaign_spec_mapping

    spec = make_campaign_spec_mapping()
    spec["incumbent"]["artifact_type"] = "scaffold"
    spec["mutable_artifact"]["artifact_type"] = "scaffold"
    spec["environment"] = "research"
    spec["tier4_policy_digest"] = "sha256:" + "a" * 64
    # G3: scaffold-mutable specs pin their mutation classes; G4: they
    # carry exactly one fixed-editor arm.
    spec["mutation_classes"] = [
        {
            "class_id": "prompt_module_edit",
            "risk_dossier_digest": "sha256:" + "b" * 64,
            "max_tier": "executable",
        },
    ]
    spec["arms"] = [
        *spec["arms"],
        {"id": "fixed-editor", "kind": "fixed-editor", "editor_ref": "evo-prompt-strategist@gen-0"},
    ]
    response = client.post("/v1/campaigns", json={"spec": spec}, headers=headers)
    assert response.status_code == 201, response.text
    return dict(response.json())


def _register_scaffold_candidate(
    client: TestClient, headers: dict[str, str], campaign_id: str
) -> dict[str, Any]:
    """Register a scaffold-class candidate (resolves to tier 4)."""
    response = client.post(
        "/v1/candidates",
        json={
            "artifact_type": "scaffold",
            "canonical_bytes_b64": SCAFFOLD_BUNDLE,
            "strategy_id": "evo-prompt-strategist",
            "campaign_id": campaign_id,
        },
        headers=headers,
    )
    return dict(response.json()) | {"_status": response.status_code, "_body": response.text}


def _open_tier4_request(
    client: TestClient,
    headers: dict[str, str],
    campaign_id: str,
    proposal_id: str,
    *,
    human_signoff: bool = True,
    manually_initiated: bool = True,
) -> Any:
    """Open a tier-4 promotion request; returns the response object."""
    return client.post(
        "/v1/approvals/requests",
        json={
            "kind": "tier4_promotion",
            "justification": "promoting a mutated scaffold (G7)",
            "campaign_id": campaign_id,
            "proposal_id": proposal_id,
            "human_signoff": human_signoff,
            "manually_initiated": manually_initiated,
        },
        headers=headers,
    )


# ----------------------------------------------------------------------
# The happy path: full evidence chain, two distinct approvers, signed record
# ----------------------------------------------------------------------


def test_tier4_promotion_full_chain_admits_and_signs(
    tier4_client: TestClient, tenant_id: str
) -> None:
    headers = _headers(tenant_id)
    campaign = _plan_scaffold_campaign(tier4_client, headers)
    candidate = tier4_client.post(
        "/v1/candidates",
        json={
            "artifact_type": "scaffold",
            "canonical_bytes_b64": SCAFFOLD_BUNDLE,
            "strategy_id": "evo-prompt-strategist",
            "campaign_id": campaign["campaign_id"],
        },
        headers=headers,
    )
    assert candidate.status_code == 201, candidate.text
    proposal_id = candidate.json()["proposal_id"]

    opened = _open_tier4_request(tier4_client, headers, campaign["campaign_id"], proposal_id)
    assert opened.status_code == 201, opened.text
    request = opened.json()
    assert request["tier"] == 4
    assert request["kind"] == "tier4_promotion"
    assert request["human_signoff"] is True
    assert request["manually_initiated"] is True
    assert request["status"] == "pending"

    # One approval short: the two-person gate refuses the admission.
    first = _decide(tier4_client, tenant_id, request["request_id"], "svc_board_1", "approve")
    assert first.status_code == 201, first.text
    refused = tier4_client.post(
        f"/v1/approvals/requests/{request['request_id']}/admission", headers=headers
    )
    assert refused.status_code == 403, refused.text
    assert refused.json()["reason"] == "review_not_approved"

    second = _decide(tier4_client, tenant_id, request["request_id"], "svc_board_2", "approve")
    assert second.status_code == 201, second.text

    admitted = tier4_client.post(
        f"/v1/approvals/requests/{request['request_id']}/admission", headers=headers
    )
    assert admitted.status_code == 201, admitted.text
    record = admitted.json()
    assert record["kind"] == "tier4_promotion"
    assert record["tier"] == 4
    assert record["decision"] == "admitted"
    assert record["proposal_digest"] == candidate.json()["artifact_digest"]
    assert {a["approver"] for a in record["approvals"]} == {"svc_board_1", "svc_board_2"}
    assert record["signature_b64"] and record["signer_public_key_b64"]

    # The signature covers the tier-4 kind: a tier-3 record can never be
    # re-presented as a tier-4 admission.
    row = AdmissionRecord(
        record_id=record["record_id"],
        request_id=record["request_id"],
        kind=record["kind"],
        decision=record["decision"],
        plugin_id=None,
        content_digest=None,
        privileged_role=None,
        proposal_digest=record["proposal_digest"],
        tier=record["tier"],
        requested_by=record["requested_by"],
        request_digest=None,
        approvals=record["approvals"],
        signature=base64.b64decode(record["signature_b64"]),
        signer_public_key=base64.b64decode(record["signer_public_key_b64"]),
    )
    assert verify_admission_signature(row) is True


# ----------------------------------------------------------------------
# Each missing leg is refused at creation
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("human_signoff", "manually_initiated", "missing"),
    [
        (False, False, "human_signoff, manually_initiated"),
        (True, False, "manually_initiated"),
        (False, True, "human_signoff"),
    ],
)
def test_tier4_request_missing_leg_is_refused_at_creation(
    tier4_client: TestClient,
    tenant_id: str,
    human_signoff: bool,
    manually_initiated: bool,
    missing: str,
) -> None:
    """A tier-4 request opened without any leg is refused — the legs are
    immutable once persisted, so they cannot be added later."""
    headers = _headers(tenant_id)
    campaign = _plan_scaffold_campaign(tier4_client, headers)
    candidate = tier4_client.post(
        "/v1/candidates",
        json={
            "artifact_type": "scaffold",
            "canonical_bytes_b64": SCAFFOLD_BUNDLE,
            "strategy_id": "evo-prompt-strategist",
            "campaign_id": campaign["campaign_id"],
        },
        headers=headers,
    )
    assert candidate.status_code == 201, candidate.text
    refused = _open_tier4_request(
        tier4_client,
        headers,
        campaign["campaign_id"],
        candidate.json()["proposal_id"],
        human_signoff=human_signoff,
        manually_initiated=manually_initiated,
    )
    assert refused.status_code == 400, refused.text
    assert missing in refused.json()["detail"]


def test_tier4_request_for_a_tier3_candidate_is_refused(
    tier4_client: TestClient, tenant_id: str
) -> None:
    """A tool_spec candidate resolves to tier 3 — opening a tier-4
    request for it is a vocabulary error, not a weaker request."""
    headers = _headers(tenant_id)
    campaign = _plan_scaffold_campaign(tier4_client, headers)
    candidate = tier4_client.post(
        "/v1/candidates",
        json={
            "artifact_type": "tool_spec",
            "canonical_bytes_b64": base64.b64encode(b"def run(x): return x\n").decode(),
            "strategy_id": "evo-prompt-strategist",
            "campaign_id": campaign["campaign_id"],
        },
        headers=headers,
    )
    assert candidate.status_code == 201, candidate.text
    refused = _open_tier4_request(
        tier4_client, headers, campaign["campaign_id"], candidate.json()["proposal_id"]
    )
    assert refused.status_code == 400, refused.text
    assert "tier 3" in refused.json()["detail"]


# ----------------------------------------------------------------------
# The environment gate: tier-4 requests need a tier-4-allowing policy
# ----------------------------------------------------------------------


def test_tier4_request_in_production_tenant_is_refused(
    session_factory: sessionmaker[Session], tenant_id: str
) -> None:
    """A tenant whose approval defaults do not allow tier 4 cannot open a
    tier-4 request at all — no evidence chain can buy its way in.

    The G6 API boundary already refuses scaffold candidates in production,
    so the tier-4 candidate is planted at the registry level (the registry
    is class-agnostic — G6's own fixtures do the same) and this test
    isolates the approval plane's own environment gate."""
    app = create_app()
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    production_registry = TenantPolicyRegistry([seed_production_tenant_policy(tenant_id)])
    app.dependency_overrides[get_approval_service] = lambda: ApprovalWorkflowService(
        session_factory,
        signing_key=generate_signing_key(),
        evaluator_subject="svc_evaluator_g7",
        tenant_policies=production_registry,
    )
    with TestClient(app) as client:
        headers = _headers(tenant_id)
        # A plain (non-scaffold) campaign is legal in production.
        from tests.support.factories import make_campaign_spec_mapping

        response = client.post(
            "/v1/campaigns",
            json={"spec": make_campaign_spec_mapping()},
            headers=headers,
        )
        assert response.status_code == 201, response.text
        campaign_id = response.json()["campaign_id"]

        # Plant a tier-4 (scaffold-class) candidate directly through the
        # registry, bypassing the G6 API boundary. Proposal ids are
        # globally unique, so the planted row uses a per-run id.
        proposal_id = f"prop_g7_prod_gate_{uuid.uuid4().hex[:12]}"
        with session_scope(session_factory) as session:
            artifact = RegistryService(session).register_artifact(
                tenant_id=tenant_id,
                artifact_type="scaffold",
                canonical_bytes=b"scaffold candidate body (g7 production gate)",
            )
            session.add(
                ProposalRecord(
                    tenant_id=tenant_id,
                    proposal_id=proposal_id,
                    proposed_digest=artifact.digest,
                    strategy_id="evo-prompt-strategist",
                    campaign_id=campaign_id,
                )
            )

        refused = _open_tier4_request(client, headers, campaign_id, proposal_id)
    assert refused.status_code == 403, refused.text
    assert refused.json()["reason"] == "tier4_environment_refused"


# ----------------------------------------------------------------------
# The evidence legs belong to tier 4 only
# ----------------------------------------------------------------------


def test_tier3_request_cannot_carry_tier4_evidence_legs(
    tier4_client: TestClient, tenant_id: str
) -> None:
    headers = _headers(tenant_id)
    campaign = _plan_scaffold_campaign(tier4_client, headers)
    candidate = tier4_client.post(
        "/v1/candidates",
        json={
            "artifact_type": "tool_spec",
            "canonical_bytes_b64": base64.b64encode(b"def run(x): return x\n").decode(),
            "strategy_id": "evo-prompt-strategist",
            "campaign_id": campaign["campaign_id"],
        },
        headers=headers,
    )
    assert candidate.status_code == 201, candidate.text
    refused = tier4_client.post(
        "/v1/approvals/requests",
        json={
            "kind": "tier3_promotion",
            "justification": "tier-3 promotion",
            "campaign_id": campaign["campaign_id"],
            "proposal_id": candidate.json()["proposal_id"],
            "human_signoff": True,
            "manually_initiated": True,
        },
        headers=headers,
    )
    assert refused.status_code == 400, refused.text
    assert "tier-4 evidence legs" in refused.json()["detail"]
