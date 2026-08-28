"""HTTP-level contract tests for the FR-014 control-plane API.

Exercises the real request/response cycle through the full app factory —
routing, workload-identity dependencies, tenant scoping, and the Postgres
append-only triggers the migration installs — because the FR-014 contract
(compare parents, diffs, evidence, costs, gains, regressions, approvals)
is a wire contract, not a Python one.

Follows the `tests/server/test_ingest_api.py` pattern: the shared `client`
fixture from `tests/conftest.py` (real `create_app()`, session factory
overridden to the test database) plus per-test tenant ids so rows never
collide across tests.
"""

from __future__ import annotations

import base64
from typing import Any

import pytest
from fastapi.testclient import TestClient

from evoruntime.server.settings import get_settings
from tests.support.factories import make_campaign_spec_mapping

PARENT_BYTES = b"prompt v1: answer carefully"
CANDIDATE_BYTES = b"prompt v2: answer carefully, step by step"


def _headers(tenant_id: str) -> dict[str, str]:
    """Evaluator-role workload-identity headers for the test tenant."""
    return {
        "x-evoruntime-identity": "svc_evaluator_1",
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


def _register_candidate(
    client: TestClient,
    headers: dict[str, str],
    *,
    content: bytes,
    strategy_id: str = "evo-prompt-strategist",
    campaign_id: str | None = None,
    parent_digest: str | None = None,
) -> dict[str, Any]:
    """Register a candidate proposal (the artifact registry computes the
    digest from the canonical bytes)."""
    payload: dict[str, Any] = {
        "artifact_type": "prompt_bundle",
        "canonical_bytes_b64": base64.b64encode(content).decode(),
        "strategy_id": strategy_id,
    }
    if campaign_id is not None:
        payload["campaign_id"] = campaign_id
    if parent_digest is not None:
        payload["parent_digest"] = parent_digest
    response = client.post("/v1/candidates", json=payload, headers=headers)
    assert response.status_code == 201, response.text
    return dict(response.json())


def _record_evaluation(
    client: TestClient, headers: dict[str, str], artifact_digest: str, metrics: dict[str, float]
) -> dict[str, Any]:
    """Record one signed evaluation outcome for an artifact."""
    response = client.post(
        "/v1/evaluations",
        json={"artifact_digest": artifact_digest, "outcome": "pass", "metrics": metrics},
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return dict(response.json())


# ----------------------------------------------------------------------
# campaigns
# ----------------------------------------------------------------------


def test_campaign_plan_returns_pinned_detail(client: TestClient, tenant_id: str) -> None:
    headers = _headers(tenant_id)

    body = _plan_campaign(client, headers)

    assert body["campaign_id"].startswith("camp_")
    assert body["name"] == "prompt-bundle-campaign-1"
    assert body["phase"] == "discover"
    assert body["spec_digest"].startswith("sha256:")
    # The E3 machine logs only explicit moves — landing in `discover` is
    # the initial state, not a transition.
    assert body["transitions"] == []


def test_campaign_list_scoped_to_tenant(client: TestClient, tenant_id: str) -> None:
    headers = _headers(tenant_id)
    planned = _plan_campaign(client, headers)

    response = client.get("/v1/campaigns", headers=headers)

    assert response.status_code == 200
    ids = [row["campaign_id"] for row in response.json()]
    assert planned["campaign_id"] in ids


def test_invalid_spec_is_rejected_with_reason(client: TestClient, tenant_id: str) -> None:
    headers = _headers(tenant_id)
    spec = make_campaign_spec_mapping()
    del spec["name"]

    response = client.post("/v1/campaigns", json={"spec": spec}, headers=headers)

    assert response.status_code == 400
    assert "name" in response.json()["detail"]


def test_campaign_transition_moves_phase(client: TestClient, tenant_id: str) -> None:
    headers = _headers(tenant_id)
    planned = _plan_campaign(client, headers)

    response = client.post(
        f"/v1/campaigns/{planned['campaign_id']}/transitions",
        json={"to_phase": "plan", "reason": "golden path"},
        headers=headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["phase"] == "plan"
    assert body["transitions"][-1]["to_phase"] == "plan"


def test_invalid_transition_is_conflict(client: TestClient, tenant_id: str) -> None:
    headers = _headers(tenant_id)
    planned = _plan_campaign(client, headers)

    response = client.post(
        f"/v1/campaigns/{planned['campaign_id']}/transitions",
        # A valid phase name on an edge the machine does not define.
        json={"to_phase": "holdout"},
        headers=headers,
    )

    assert response.status_code == 409


def test_campaign_of_another_tenant_is_not_found(client: TestClient, tenant_id: str) -> None:
    headers = _headers(tenant_id)
    planned = _plan_campaign(client, headers)

    response = client.get(
        f"/v1/campaigns/{planned['campaign_id']}", headers=_headers("tnt_" + "f" * 12)
    )

    assert response.status_code == 404


# ----------------------------------------------------------------------
# candidates: registration, parents, diffs
# ----------------------------------------------------------------------


def test_candidate_registration_computes_digest_and_links_parent(
    client: TestClient, tenant_id: str
) -> None:
    headers = _headers(tenant_id)
    planned = _plan_campaign(client, headers)
    parent = _register_candidate(client, headers, content=PARENT_BYTES)

    candidate = _register_candidate(
        client,
        headers,
        content=CANDIDATE_BYTES,
        campaign_id=planned["campaign_id"],
        parent_digest=parent["artifact_digest"],
    )

    assert candidate["proposal_id"].startswith("prp_")
    assert candidate["artifact_digest"].startswith("sha256:")
    assert candidate["artifact_digest"] != parent["artifact_digest"]
    assert candidate["parent_digest"] == parent["artifact_digest"]
    assert candidate["strategy_id"] == "evo-prompt-strategist"


def test_candidate_for_unknown_campaign_is_not_found(client: TestClient, tenant_id: str) -> None:
    headers = _headers(tenant_id)

    response = client.post(
        "/v1/candidates",
        json={
            "artifact_type": "prompt_bundle",
            "canonical_bytes_b64": base64.b64encode(CANDIDATE_BYTES).decode(),
            "strategy_id": "evo-prompt-strategist",
            "campaign_id": "camp_nevercreated",
        },
        headers=headers,
    )

    assert response.status_code == 404


def test_semantic_diff_requires_a_configured_adapter(client: TestClient, tenant_id: str) -> None:
    """Without an adapter the endpoint fails closed with 503 — never a
    silent empty diff."""
    headers = _headers(tenant_id)
    parent = _register_candidate(client, headers, content=PARENT_BYTES)
    candidate = _register_candidate(
        client, headers, content=CANDIDATE_BYTES, parent_digest=parent["artifact_digest"]
    )

    response = client.get(f"/v1/candidates/{candidate['proposal_id']}/diff", headers=headers)

    assert response.status_code == 503


@pytest.fixture
def reference_adapter(monkeypatch: pytest.MonkeyPatch) -> None:
    """Point the deployment's adapter command at the E7 reference plugin.

    The subprocess runs under the scrubbed plugin environment, so the
    command must be resolvable with only PATH/HOME — `python -m` from the
    repo root (the test process's cwd) satisfies that.
    """
    monkeypatch.setenv("EVORUNTIME_ADAPTER_COMMAND", "python -m tests.plugins.reference_plugin")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_semantic_diff_compares_candidate_to_parent(
    client: TestClient, tenant_id: str, reference_adapter: None
) -> None:
    headers = _headers(tenant_id)
    parent = _register_candidate(client, headers, content=PARENT_BYTES)
    candidate = _register_candidate(
        client, headers, content=CANDIDATE_BYTES, parent_digest=parent["artifact_digest"]
    )

    response = client.get(f"/v1/candidates/{candidate['proposal_id']}/diff", headers=headers)

    assert response.status_code == 200
    diff = response.json()
    assert diff["proposal_id"] == candidate["proposal_id"]
    assert diff["base_digest"] == parent["artifact_digest"]
    assert diff["candidate_digest"] == candidate["artifact_digest"]
    assert diff["unified"]  # the adapter produced a real unified diff


def test_diff_for_parentless_candidate_is_unavailable(
    client: TestClient, tenant_id: str, reference_adapter: None
) -> None:
    headers = _headers(tenant_id)
    orphan = _register_candidate(client, headers, content=CANDIDATE_BYTES)

    response = client.get(f"/v1/candidates/{orphan['proposal_id']}/diff", headers=headers)

    assert response.status_code == 422


# ----------------------------------------------------------------------
# evidence
# ----------------------------------------------------------------------


def test_evidence_bundle_is_recorded_and_listed_by_digest(
    client: TestClient, tenant_id: str
) -> None:
    headers = _headers(tenant_id)
    planned = _plan_campaign(client, headers)
    candidate = _register_candidate(
        client, headers, content=CANDIDATE_BYTES, campaign_id=planned["campaign_id"]
    )
    items = [{"kind": "trace_ref", "digest": "sha256:" + "3" * 64, "summary": "passing run"}]

    created = client.post(
        "/v1/evidence",
        json={
            "campaign_id": planned["campaign_id"],
            "artifact_digest": candidate["artifact_digest"],
            "redacted_items": items,
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text
    bundle = created.json()
    assert bundle["bundle_id"].startswith("evb_")
    assert bundle["redacted_items"] == items

    listed = client.get(
        "/v1/evidence", params={"artifact_digest": candidate["artifact_digest"]}, headers=headers
    )

    assert listed.status_code == 200
    assert [row["bundle_id"] for row in listed.json()] == [bundle["bundle_id"]]


def test_evidence_for_unknown_artifact_is_not_found(client: TestClient, tenant_id: str) -> None:
    headers = _headers(tenant_id)

    response = client.post(
        "/v1/evidence",
        json={
            "artifact_digest": "sha256:" + "e" * 64,
            "redacted_items": [{"kind": "trace_ref", "digest": "sha256:" + "4" * 64}],
        },
        headers=headers,
    )

    # Dangling evidence is refused at the API boundary, not left to the FK.
    assert response.status_code == 404


# ----------------------------------------------------------------------
# evaluations (signed outcomes) and the Pareto comparison they feed
# ----------------------------------------------------------------------


def test_evaluation_is_signed_and_listed(client: TestClient, tenant_id: str) -> None:
    headers = _headers(tenant_id)
    # Attestations hang off registered artifacts — the E1 registry is the
    # boundary, so the digest must exist first.
    registered = _register_candidate(client, headers, content=CANDIDATE_BYTES)
    digest = registered["artifact_digest"]

    created = _record_evaluation(client, headers, digest, {"task_success_rate": 0.83})

    assert created["attestation_id"]
    assert created["outcome"] == "pass"
    assert created["result_metrics"] == {"task_success_rate": 0.83}
    assert created["evaluation_payload_digest"].startswith("sha256:")

    listed = client.get("/v1/evaluations", params={"artifact_digest": digest}, headers=headers)
    assert listed.status_code == 200
    assert [row["attestation_id"] for row in listed.json()] == [created["attestation_id"]]


def test_evaluation_rejects_unknown_outcome(client: TestClient, tenant_id: str) -> None:
    headers = _headers(tenant_id)

    response = client.post(
        "/v1/evaluations",
        json={"artifact_digest": "sha256:" + "6" * 64, "outcome": "maybe", "metrics": {}},
        headers=headers,
    )

    assert response.status_code == 400


def test_campaign_pareto_splits_gains_regressions_and_costs(
    client: TestClient, tenant_id: str
) -> None:
    headers = _headers(tenant_id)
    planned = _plan_campaign(client, headers)
    parent = _register_candidate(client, headers, content=PARENT_BYTES)
    candidate = _register_candidate(
        client,
        headers,
        content=CANDIDATE_BYTES,
        campaign_id=planned["campaign_id"],
        parent_digest=parent["artifact_digest"],
    )
    _record_evaluation(
        client,
        headers,
        parent["artifact_digest"],
        {"task_success_rate": 0.75, "wall_clock_s": 100.0},
    )
    _record_evaluation(
        client,
        headers,
        candidate["artifact_digest"],
        {"task_success_rate": 0.83, "wall_clock_s": 120.0},
    )

    response = client.get(f"/v1/campaigns/{planned['campaign_id']}/pareto", headers=headers)

    assert response.status_code == 200
    report = response.json()
    assert report["campaign_id"] == planned["campaign_id"]
    entries = report["entries"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["proposal_id"] == candidate["proposal_id"]
    assert entry["parent_digest"] == parent["artifact_digest"]
    assert entry["outcome"] == "pass"
    # +0.08 success is a gain; +20s wall clock is a regression that the
    # costs column surfaces so a reviewer sees what the gain cost.
    assert entry["gains"]["task_success_rate"] == pytest.approx(0.08)
    assert entry["regressions"]["wall_clock_s"] == pytest.approx(20.0)
    assert entry["costs"] == {"wall_clock_s": 120.0}


# ----------------------------------------------------------------------
# approvals
# ----------------------------------------------------------------------


def test_approval_is_recorded_and_listed_per_campaign(client: TestClient, tenant_id: str) -> None:
    headers = _headers(tenant_id)
    planned = _plan_campaign(client, headers)
    candidate = _register_candidate(
        client, headers, content=CANDIDATE_BYTES, campaign_id=planned["campaign_id"]
    )

    created = client.post(
        "/v1/approvals",
        json={
            "campaign_id": planned["campaign_id"],
            "proposal_id": candidate["proposal_id"],
            "decision": "nominate",
            "reason": "pareto-dominant on dev partition",
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text
    approval = created.json()
    assert approval["kind"] == "nominate"
    assert approval["artifact_digest"] == candidate["artifact_digest"]
    assert approval["actor_identity"] == "svc_evaluator_1"

    listed = client.get(f"/v1/campaigns/{planned['campaign_id']}/approvals", headers=headers)
    assert listed.status_code == 200
    assert [row["event_id"] for row in listed.json()] == [approval["event_id"]]


def test_approval_rejects_candidate_from_another_campaign(
    client: TestClient, tenant_id: str
) -> None:
    headers = _headers(tenant_id)
    planned = _plan_campaign(client, headers)
    other = _plan_campaign(client, headers)
    candidate = _register_candidate(
        client, headers, content=CANDIDATE_BYTES, campaign_id=other["campaign_id"]
    )

    response = client.post(
        "/v1/approvals",
        json={
            "campaign_id": planned["campaign_id"],
            "proposal_id": candidate["proposal_id"],
            "decision": "nominate",
        },
        headers=headers,
    )

    assert response.status_code == 400


# ----------------------------------------------------------------------
# releases: canary, promote, rollback status
# ----------------------------------------------------------------------


def _release_payload(artifact_digest: str) -> dict[str, Any]:
    return {
        "artifact_digests": [artifact_digest],
        "adapter_versions": {"evo-prompt-strategist": "1.2.0"},
        "model_routes": {"default": "gpt-5-mini"},
        "policies": {"tier": "tier-2-standard"},
        "status": "canary",
    }


def test_release_canary_then_promote_then_rollback(client: TestClient, tenant_id: str) -> None:
    headers = _headers(tenant_id)
    registered = _register_candidate(client, headers, content=CANDIDATE_BYTES)

    created = client.post(
        "/v1/releases", json=_release_payload(registered["artifact_digest"]), headers=headers
    )
    assert created.status_code == 201, created.text
    digest = created.json()["manifest_digest"]
    assert created.json()["status"] == "canary"

    status = client.get(f"/v1/releases/{digest}/rollback-status", headers=headers)
    assert status.status_code == 200
    assert status.json()["status"] == "canary"

    promoted = client.post(f"/v1/releases/{digest}/promote", headers=headers)
    assert promoted.status_code == 200
    assert promoted.json()["status"] == "active"

    rolled_back = client.post(f"/v1/releases/{digest}/rollback", headers=headers)
    assert rolled_back.status_code == 200
    assert rolled_back.json()["status"] == "rolled_back"

    final = client.get(f"/v1/releases/{digest}/rollback-status", headers=headers)
    assert final.json()["status"] == "rolled_back"


def test_release_promote_requires_canary_state(client: TestClient, tenant_id: str) -> None:
    headers = _headers(tenant_id)
    registered = _register_candidate(client, headers, content=CANDIDATE_BYTES)
    created = client.post(
        "/v1/releases", json=_release_payload(registered["artifact_digest"]), headers=headers
    )
    digest = created.json()["manifest_digest"]
    client.post(f"/v1/releases/{digest}/promote", headers=headers)

    # Already active: promoting again is a conflict, not a silent no-op.
    second = client.post(f"/v1/releases/{digest}/promote", headers=headers)

    assert second.status_code == 409


def test_release_list_scoped_to_tenant(client: TestClient, tenant_id: str) -> None:
    headers = _headers(tenant_id)
    registered = _register_candidate(client, headers, content=CANDIDATE_BYTES)
    created = client.post(
        "/v1/releases", json=_release_payload(registered["artifact_digest"]), headers=headers
    )

    listed = client.get("/v1/releases", headers=headers)

    assert listed.status_code == 200
    assert created.json()["manifest_digest"] in [row["manifest_digest"] for row in listed.json()]


# ----------------------------------------------------------------------
# agents
# ----------------------------------------------------------------------


def test_agent_registration_round_trip(client: TestClient, tenant_id: str) -> None:
    headers = _headers(tenant_id)

    created = client.post(
        "/v1/agents",
        json={
            "plugin_id": "evo-prompt-strategist",
            "kind": "strategy",
            "pinned_image": "ghcr.io/evoruntime/strategist@sha256:" + "b" * 64,
            "artifact_types": ["prompt_bundle"],
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text

    listed = client.get("/v1/agents", headers=headers)
    assert listed.status_code == 200
    assert "evo-prompt-strategist" in [row["plugin_id"] for row in listed.json()]
