"""HTTP-level contract tests for the F10 review-board approval flows.

Exercises the real request/response cycle through the full app factory —
two-person tier-3 promotion, self-approval refusal, executable
registration gated by FR-018 admission + F3 static analysis BEFORE any
artifact row exists, and the signed read-only records (admissions,
compensation plans, analysis reports) — because two-person semantics is
a wire contract: it must hold for the exact bytes a caller sends, not
just for Python calls.

Follows the `tests/server/test_campaign_api.py` pattern: the shared
`client` fixture from `tests/conftest.py` plus per-test tenant ids.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient

from tests.support.factories import make_campaign_spec_mapping

#: A clean executable candidate: one Python file, no network, no
#: subprocess, no dynamic exec — passes FR-018 admission and F3 analysis.
CLEAN_BUNDLE = json.dumps(
    {"files": [{"path": "tool.py", "content": "def run(x: int) -> int:\n    return x + 1\n"}]}
).encode()

#: A candidate the F3 static-analysis gate must refuse: direct network
#: egress is exactly what candidates never get.
NETWORK_BUNDLE = json.dumps(
    {"files": [{"path": "net.py", "content": "import socket\n\nsocket.create_connection\n"}]}
).encode()

#: A candidate FR-018 output admission must refuse before any content is
#: parsed: a parent-relative path escapes the output bundle.
ESCAPE_BUNDLE = json.dumps({"files": [{"path": "../escape.py", "content": "x = 1\n"}]}).encode()


def _headers(tenant_id: str, identity: str = "svc_evaluator_1") -> dict[str, str]:
    """Evaluator-role workload-identity headers for one caller."""
    return {
        "x-evoruntime-identity": identity,
        "x-evoruntime-role": "evaluator",
        "x-evoruntime-tenant": tenant_id,
    }


def _plan_campaign(client: TestClient, headers: dict[str, str]) -> dict[str, Any]:
    """Create one campaign through the API and return its detail body."""
    response = client.post(
        "/v1/campaigns", json={"spec": make_campaign_spec_mapping()}, headers=headers
    )
    assert response.status_code == 201, response.text
    return dict(response.json())


def _register_executable(
    client: TestClient,
    headers: dict[str, str],
    content: bytes,
    *,
    campaign_id: str | None = None,
) -> dict[str, Any]:
    """Register a tier-3 executable candidate (tool_spec class)."""
    payload: dict[str, Any] = {
        "artifact_type": "tool_spec",
        "canonical_bytes_b64": base64.b64encode(content).decode(),
        "strategy_id": "evo-prompt-strategist",
    }
    if campaign_id is not None:
        payload["campaign_id"] = campaign_id
    response = client.post("/v1/candidates", json=payload, headers=headers)
    return dict(response.json()) | {"_status": response.status_code, "_body": response.text}


def _open_tier3_request(
    client: TestClient,
    headers: dict[str, str],
    campaign_id: str,
    proposal_id: str,
) -> dict[str, Any]:
    """Open a tier-3 promotion review-board request."""
    response = client.post(
        "/v1/approvals/requests",
        json={
            "kind": "tier3_promotion",
            "justification": "promoting an executable tool spec",
            "campaign_id": campaign_id,
            "proposal_id": proposal_id,
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return dict(response.json())


def _decide(
    client: TestClient,
    tenant_id: str,
    request_id: str,
    identity: str,
    decision: str,
) -> Any:
    """Record one decision as a specific verified caller."""
    return client.post(
        f"/v1/approvals/requests/{request_id}/decisions",
        json={"decision": decision, "note": f"decided by {identity}"},
        headers=_headers(tenant_id, identity),
    )


# ----------------------------------------------------------------------
# Tier-3 promotion: two-person semantics
# ----------------------------------------------------------------------


def test_tier3_promotion_requires_two_distinct_approvers(
    client: TestClient, tenant_id: str
) -> None:
    """One approval is not enough: admission is refused until a second
    *distinct* verified approver signs off, then the signed record reads
    back intact."""
    headers = _headers(tenant_id)
    campaign = _plan_campaign(client, headers)
    candidate = _register_executable(
        client, headers, CLEAN_BUNDLE, campaign_id=campaign["campaign_id"]
    )
    assert candidate["_status"] == 201, candidate["_body"]
    request = _open_tier3_request(
        client, headers, campaign["campaign_id"], candidate["proposal_id"]
    )
    assert request["tier"] == 3
    assert request["status"] == "pending"

    first = _decide(client, tenant_id, request["request_id"], "svc_board_1", "approve")
    assert first.status_code == 201, first.text

    # One approver short: the two-person gate refuses the admission.
    refused = client.post(
        f"/v1/approvals/requests/{request['request_id']}/admission", headers=headers
    )
    assert refused.status_code == 403, refused.text
    assert refused.json()["tier"] == 3

    second = _decide(client, tenant_id, request["request_id"], "svc_board_2", "approve")
    assert second.status_code == 201, second.text

    admitted = client.post(
        f"/v1/approvals/requests/{request['request_id']}/admission", headers=headers
    )
    assert admitted.status_code == 201, admitted.text
    record = admitted.json()
    assert record["tier"] == 3
    assert record["decision"] == "admitted"
    assert record["proposal_digest"] == candidate["artifact_digest"]
    assert len(record["approvals"]) == 2
    assert {a["approver"] for a in record["approvals"]} == {"svc_board_1", "svc_board_2"}
    assert record["signature_b64"] and record["signer_public_key_b64"]

    # The signed record is surfaced read-only and reads back intact.
    read_back = client.get(f"/v1/approvals/admissions/{record['record_id']}", headers=headers)
    assert read_back.status_code == 200, read_back.text
    assert read_back.json() == record

    # The request itself is closed: no third decision, no re-admission.
    third = _decide(client, tenant_id, request["request_id"], "svc_board_3", "approve")
    assert third.status_code == 403
    assert third.json()["reason"] == "review_closed"
    again = client.post(
        f"/v1/approvals/requests/{request['request_id']}/admission", headers=headers
    )
    assert again.status_code == 403
    assert again.json()["reason"] == "already_admitted"


def test_tier3_promotion_refused_without_any_approval(client: TestClient, tenant_id: str) -> None:
    """Zero approvals: the gate refuses with the tier it was asked for."""
    headers = _headers(tenant_id)
    campaign = _plan_campaign(client, headers)
    candidate = _register_executable(
        client, headers, CLEAN_BUNDLE, campaign_id=campaign["campaign_id"]
    )
    request = _open_tier3_request(
        client, headers, campaign["campaign_id"], candidate["proposal_id"]
    )
    refused = client.post(
        f"/v1/approvals/requests/{request['request_id']}/admission", headers=headers
    )
    assert refused.status_code == 403, refused.text
    assert refused.json()["tier"] == 3


def test_self_approval_is_refused(client: TestClient, tenant_id: str) -> None:
    """The requester cannot approve their own request — the approver is
    the verified caller identity, so a body field cannot launder it."""
    headers = _headers(tenant_id, "svc_requester_1")
    campaign = _plan_campaign(client, headers)
    candidate = _register_executable(
        client, headers, CLEAN_BUNDLE, campaign_id=campaign["campaign_id"]
    )
    request = _open_tier3_request(
        client, headers, campaign["campaign_id"], candidate["proposal_id"]
    )
    self_approval = _decide(client, tenant_id, request["request_id"], "svc_requester_1", "approve")
    assert self_approval.status_code == 403, self_approval.text
    assert self_approval.json()["reason"] == "self_approval"

    # The refusal left no decision behind: the review is still pending.
    detail = client.get(f"/v1/approvals/requests/{request['request_id']}", headers=headers)
    assert detail.status_code == 200
    assert detail.json()["status"] == "pending"
    assert detail.json()["decisions"] == []


def test_duplicate_approver_is_refused(client: TestClient, tenant_id: str) -> None:
    """One person, one decision: a second decision by the same verified
    identity is refused no matter how many times they call."""
    headers = _headers(tenant_id)
    campaign = _plan_campaign(client, headers)
    candidate = _register_executable(
        client, headers, CLEAN_BUNDLE, campaign_id=campaign["campaign_id"]
    )
    request = _open_tier3_request(
        client, headers, campaign["campaign_id"], candidate["proposal_id"]
    )
    first = _decide(client, tenant_id, request["request_id"], "svc_board_1", "approve")
    assert first.status_code == 201
    second = _decide(client, tenant_id, request["request_id"], "svc_board_1", "approve")
    assert second.status_code == 403, second.text
    assert second.json()["reason"] == "duplicate_approver"

    # One recorded approval — the duplicate never landed.
    detail = client.get(f"/v1/approvals/requests/{request['request_id']}", headers=headers)
    assert len(detail.json()["decisions"]) == 1


def test_rejection_closes_the_review(client: TestClient, tenant_id: str) -> None:
    """Any rejection closes the review regardless of approval count."""
    headers = _headers(tenant_id)
    campaign = _plan_campaign(client, headers)
    candidate = _register_executable(
        client, headers, CLEAN_BUNDLE, campaign_id=campaign["campaign_id"]
    )
    request = _open_tier3_request(
        client, headers, campaign["campaign_id"], candidate["proposal_id"]
    )
    assert _decide(client, tenant_id, request["request_id"], "svc_board_1", "approve")
    assert _decide(client, tenant_id, request["request_id"], "svc_board_2", "reject")
    refused = client.post(
        f"/v1/approvals/requests/{request['request_id']}/admission", headers=headers
    )
    assert refused.status_code == 403
    assert refused.json()["reason"] == "review_rejected"


def test_review_board_requests_are_tenant_scoped(client: TestClient, tenant_id: str) -> None:
    """Another tenant's request is indistinguishable from no request."""
    headers = _headers(tenant_id)
    campaign = _plan_campaign(client, headers)
    candidate = _register_executable(
        client, headers, CLEAN_BUNDLE, campaign_id=campaign["campaign_id"]
    )
    request = _open_tier3_request(
        client, headers, campaign["campaign_id"], candidate["proposal_id"]
    )
    stranger = client.get(
        f"/v1/approvals/requests/{request['request_id']}",
        headers=_headers("tenant-other-9"),
    )
    assert stranger.status_code == 404


# ----------------------------------------------------------------------
# Executable registration: gated BEFORE the artifact row exists
# ----------------------------------------------------------------------


def test_executable_registration_refused_with_violation_payloads(
    client: TestClient, tenant_id: str
) -> None:
    """A network-importing tool_spec is refused at registration with the
    F3 static-analysis violation payloads — and leaves no artifact row."""
    response = client.post(
        "/v1/candidates",
        json={
            "artifact_type": "tool_spec",
            "canonical_bytes_b64": base64.b64encode(NETWORK_BUNDLE).decode(),
            "strategy_id": "evo-prompt-strategist",
        },
        headers=_headers(tenant_id),
    )
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["source"] == "static_analysis"
    assert body["violations"], "a refusal must carry its violations"
    codes = {violation["code"] for violation in body["violations"]}
    assert "network_import" in codes

    # Nothing was registered: the refused candidate has no artifact.
    listed = client.get("/v1/candidates", headers=_headers(tenant_id))
    assert all(row["proposal_id"] != body.get("proposal_id") for row in listed.json())


def test_executable_registration_refused_by_output_admission(
    client: TestClient, tenant_id: str
) -> None:
    """A parent-relative path is refused by FR-018 admission before any
    content is even parsed — the metadata plane fires first."""
    response = client.post(
        "/v1/candidates",
        json={
            "artifact_type": "tool_spec",
            "canonical_bytes_b64": base64.b64encode(ESCAPE_BUNDLE).decode(),
            "strategy_id": "evo-prompt-strategist",
        },
        headers=_headers(tenant_id),
    )
    assert response.status_code == 422, response.text
    body = response.json()
    assert body["source"] == "fr018_output_admission"
    assert body["violations"]


def test_clean_executable_registration_persists_signed_analysis_report(
    client: TestClient, tenant_id: str
) -> None:
    """A clean executable candidate registers and its F3 verdict is
    persisted signed — and reads back through the read-only endpoint."""
    headers = _headers(tenant_id)
    candidate = _register_executable(client, headers, CLEAN_BUNDLE)
    assert candidate["_status"] == 201, candidate["_body"]

    listed = client.get(
        "/v1/approvals/analysis-reports",
        params={"candidate_digest": candidate["artifact_digest"]},
        headers=headers,
    )
    assert listed.status_code == 200, listed.text
    reports = listed.json()
    assert len(reports) == 1
    report = reports[0]
    assert report["outcome"] == "pass"
    assert report["artifact_type"] == "tool_spec"
    assert report["candidate_digest"] == candidate["artifact_digest"]
    assert report["signature_b64"] and report["signer_public_key_b64"]

    single = client.get(f"/v1/approvals/analysis-reports/{report['report_id']}", headers=headers)
    assert single.status_code == 200, single.text
    assert single.json() == report


def test_non_executable_registration_skips_the_gate(client: TestClient, tenant_id: str) -> None:
    """Tier-1/2 classes (prompt_bundle) register as before — no analysis
    report is minted for them, and no gate fires on their content."""
    headers = _headers(tenant_id)
    response = client.post(
        "/v1/candidates",
        json={
            "artifact_type": "prompt_bundle",
            "canonical_bytes_b64": base64.b64encode(b"prompt v2: careful").decode(),
            "strategy_id": "evo-prompt-strategist",
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    listed = client.get("/v1/approvals/analysis-reports", headers=headers)
    assert listed.json() == []


# ----------------------------------------------------------------------
# Privileged admission (FR-022) through the review board
# ----------------------------------------------------------------------


def test_privileged_admission_two_person_flow(client: TestClient, tenant_id: str) -> None:
    """A privileged adapter admission is a tier-3 governance act: two
    distinct approvers mint one signed, pinned admission record."""
    # A per-run digest keeps the test hermetic: privileged record ids are
    # content-derived, so a fixed digest would collide on re-runs against
    # a persistent database.
    digest = "sha256:" + hashlib.sha256(uuid.uuid4().bytes).hexdigest()
    headers = _headers(tenant_id, "svc_requester_1")
    request = client.post(
        "/v1/approvals/requests",
        json={
            "kind": "privileged_admission",
            "justification": "pin the reference adapter for production",
            "plugin_id": "evo-reference-adapter",
            "content_digest": digest,
            "privileged_role": "adapter",
        },
        headers=headers,
    )
    assert request.status_code == 201, request.text
    body = request.json()
    assert body["tier"] == 3

    assert _decide(client, tenant_id, body["request_id"], "svc_board_1", "approve")
    refused = client.post(f"/v1/approvals/requests/{body['request_id']}/admission", headers=headers)
    assert refused.status_code == 403, refused.text
    assert refused.json()["reason"] == "insufficient_approvals"

    assert _decide(client, tenant_id, body["request_id"], "svc_board_2", "approve")
    admitted = client.post(
        f"/v1/approvals/requests/{body['request_id']}/admission", headers=headers
    )
    assert admitted.status_code == 201, admitted.text
    record = admitted.json()
    assert record["plugin_id"] == "evo-reference-adapter"
    assert record["content_digest"] == digest
    assert record["request_digest"]
    assert len(record["approvals"]) == 2

    listed = client.get(
        "/v1/approvals/admissions",
        params={"request_id": body["request_id"]},
        headers=headers,
    )
    assert [row["record_id"] for row in listed.json()] == [record["record_id"]]


def test_privileged_admission_rejects_floating_tag(client: TestClient, tenant_id: str) -> None:
    """A floating tag cannot be constructed into a pinned version, so the
    request is refused before anything is persisted."""
    response = client.post(
        "/v1/approvals/requests",
        json={
            "kind": "privileged_admission",
            "justification": "floating tags are not pins",
            "plugin_id": "evo-reference-adapter",
            "content_digest": "latest",
            "privileged_role": "adapter",
        },
        headers=_headers(tenant_id),
    )
    assert response.status_code == 400, response.text


# ----------------------------------------------------------------------
# Compensation plans (F5 record type)
# ----------------------------------------------------------------------


def test_compensation_plan_is_signed_and_read_back(client: TestClient, tenant_id: str) -> None:
    """A declared plan is signed over its canonical bytes and reads back
    byte-identical through the read-only endpoint."""
    headers = _headers(tenant_id)
    actions = [
        {"artifact_digest": "sha256:" + "c" * 64, "mode": "cas", "order": 1},
        {
            "artifact_digest": "sha256:" + "d" * 64,
            "mode": "requires_execution",
            "order": 2,
        },
    ]
    created = client.post(
        "/v1/approvals/compensation-plans",
        json={"actions": actions},
        headers=headers,
    )
    assert created.status_code == 201, created.text
    plan = created.json()
    # The service normalizes each action into its executable shape:
    # mode + artifact_digest carried through, execution state defaulted.
    stored = plan["actions"]
    assert [action["mode"] for action in stored] == ["cas", "requires_execution"]
    assert [action["artifact_digest"] for action in stored] == [
        "sha256:" + "c" * 64,
        "sha256:" + "d" * 64,
    ]
    assert all(action["executed"] is False for action in stored)
    assert plan["plan_digest"].startswith("sha256:")
    assert plan["signature_b64"] and plan["signer_public_key_b64"]

    read = client.get(f"/v1/approvals/compensation-plans/{plan['plan_id']}", headers=headers)
    assert read.status_code == 200, read.text
    assert read.json() == plan

    scoped = client.get(
        "/v1/approvals/compensation-plans",
        params={"campaign_id": "campaign-none"},
        headers=headers,
    )
    assert scoped.json() == []


def test_compensation_plan_rejects_empty_actions(client: TestClient, tenant_id: str) -> None:
    """A plan with no actions is not a plan."""
    response = client.post(
        "/v1/approvals/compensation-plans",
        json={"actions": []},
        headers=_headers(tenant_id),
    )
    assert response.status_code == 422, response.text


# ----------------------------------------------------------------------
# Review-board request validation
# ----------------------------------------------------------------------


def test_request_kind_and_target_shapes_are_validated(client: TestClient, tenant_id: str) -> None:
    """Unknown kinds, mixed targets, and missing candidates are refused
    before anything is persisted."""
    headers = _headers(tenant_id)
    bad_kind = client.post(
        "/v1/approvals/requests",
        json={"kind": "tier2_promotion", "justification": "not a review-board kind"},
        headers=headers,
    )
    assert bad_kind.status_code == 400

    empty_justification = client.post(
        "/v1/approvals/requests",
        json={"kind": "tier3_promotion", "justification": "   "},
        headers=headers,
    )
    assert empty_justification.status_code == 400

    mixed = client.post(
        "/v1/approvals/requests",
        json={
            "kind": "tier3_promotion",
            "justification": "tier-3 requests do not target plugins",
            "campaign_id": "campaign-x",
            "proposal_id": "proposal-x",
            "plugin_id": "plugin-x",
        },
        headers=headers,
    )
    assert mixed.status_code == 400

    missing_candidate = client.post(
        "/v1/approvals/requests",
        json={
            "kind": "tier3_promotion",
            "justification": "no such candidate",
            "campaign_id": "campaign-x",
            "proposal_id": "proposal-x",
        },
        headers=headers,
    )
    assert missing_candidate.status_code == 404


def test_tier1_candidate_is_not_a_review_board_matter(client: TestClient, tenant_id: str) -> None:
    """A tier-1 prompt bundle resolves below the review-board threshold:
    the request is refused, not silently downgraded to a lower tier."""
    headers = _headers(tenant_id)
    campaign = _plan_campaign(client, headers)
    response = client.post(
        "/v1/candidates",
        json={
            "artifact_type": "prompt_bundle",
            "canonical_bytes_b64": base64.b64encode(b"prompt v2: careful").decode(),
            "strategy_id": "evo-prompt-strategist",
            "campaign_id": campaign["campaign_id"],
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    candidate = response.json()
    refused = client.post(
        "/v1/approvals/requests",
        json={
            "kind": "tier3_promotion",
            "justification": "a prompt bundle is not a tier-3 promotion",
            "campaign_id": campaign["campaign_id"],
            "proposal_id": candidate["proposal_id"],
        },
        headers=headers,
    )
    assert refused.status_code == 400, refused.text


@pytest.mark.parametrize("decision", ["abstain", "maybe"])
def test_invalid_decision_kind_is_refused(
    client: TestClient, tenant_id: str, decision: str
) -> None:
    """Only approve/reject are decisions; anything else is a spec error."""
    headers = _headers(tenant_id)
    campaign = _plan_campaign(client, headers)
    candidate = _register_executable(
        client, headers, CLEAN_BUNDLE, campaign_id=campaign["campaign_id"]
    )
    request = _open_tier3_request(
        client, headers, campaign["campaign_id"], candidate["proposal_id"]
    )
    response = _decide(client, tenant_id, request["request_id"], "svc_board_1", decision)
    assert response.status_code == 400, response.text
