"""HTTP-level tests for the discovery report endpoints (deliverable H3).

Exercises the real request/response cycle (FastAPI TestClient -> handler ->
Postgres) against traces ingested through the real `/v1/events:ingest`
endpoint with detail bodies registered through the real `/v1/payloads`
endpoint, so discovery is proven against what the write paths actually
persisted — the same discipline as the H2 trace-read tests.

Uses the shared `client` fixture from `tests/conftest.py`; each test scopes
itself to fresh tenant ids and asserts only on rows it wrote.
"""

from __future__ import annotations

import base64
import json
import uuid

from fastapi.testclient import TestClient

from evoruntime.core.principal import Principal
from tests.support.factories import make_raw_event


def _ingest(client: TestClient, headers: dict[str, str], events: list[dict]) -> None:
    response = client.post("/v1/events:ingest", json={"events": events}, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["rejected"] == []


def _register_payload(client: TestClient, headers: dict[str, str], body: dict) -> str:
    """Register a detail body through the real H2 payload endpoint."""
    response = client.post(
        "/v1/payloads",
        params={"classification": "internal"},
        content=json.dumps(body).encode("utf-8"),
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return response.json()["payload_digest"]


def _ingest_trace(
    client: TestClient,
    headers: dict[str, str],
    tenant_id: str,
    trace_id: str,
    index: int,
    *,
    tool_ok: bool,
    tool: str = "shell",
    agent_id: str = "agt_test",
) -> None:
    """One trace: a tool call plus a trace end whose ok flag matches."""
    tool_digest = _register_payload(client, headers, {"name": tool, "ok": tool_ok})
    end_digest = _register_payload(client, headers, {"ok": tool_ok})
    events = [
        make_raw_event(
            index,
            tenant_id=tenant_id,
            trace_id=trace_id,
            agent_id=agent_id,
            event_type="tool.completed",
        ),
        make_raw_event(
            index + 1,
            tenant_id=tenant_id,
            trace_id=trace_id,
            agent_id=agent_id,
            event_type="trace.ended",
        ),
    ]
    events[0]["payload_digest"] = tool_digest
    events[1]["payload_digest"] = end_digest
    _ingest(client, headers, events)


def test_run_discovery_clusters_ingested_failures(
    client: TestClient, auth_headers, evaluator: Principal
) -> None:
    headers = auth_headers(evaluator)
    tenant = evaluator.tenant_id
    _ingest_trace(client, headers, tenant, f"trc_{uuid.uuid4().hex[:12]}", 0, tool_ok=False)
    _ingest_trace(client, headers, tenant, f"trc_{uuid.uuid4().hex[:12]}", 10, tool_ok=False)
    _ingest_trace(
        client, headers, tenant, f"trc_{uuid.uuid4().hex[:12]}", 20, tool_ok=True, tool="edit"
    )

    response = client.post("/v1/discovery", json={}, headers=headers)

    assert response.status_code == 201, response.text
    report = response.json()
    assert report["traces_scanned"] == 3
    assert report["failure_count"] == 2
    assert report["unclassified_count"] == 0
    assert report["categories_hit"] == ["dependency_misuse"]
    assert len(report["clusters"]) == 1
    cluster = report["clusters"][0]
    assert cluster["category"] == "dependency_misuse"
    assert cluster["failure_signature"] == "shell"
    assert cluster["count"] == 2
    assert len(cluster["representative_trace_ids"]) == 2
    # The report is signed: digest plus detached signature and the signer's
    # public key, all base64 — the same tamper-evidence shape as every other
    # signed record on the analysis-report path.
    assert report["report_digest"].startswith("sha256:")
    base64.b64decode(report["signature_b64"], validate=True)
    base64.b64decode(report["signer_public_key_b64"], validate=True)


def test_discovery_is_deterministic_over_the_same_traces(
    client: TestClient, auth_headers, evaluator: Principal
) -> None:
    headers = auth_headers(evaluator)
    tenant = evaluator.tenant_id
    _ingest_trace(client, headers, tenant, f"trc_{uuid.uuid4().hex[:12]}", 0, tool_ok=False)
    _ingest_trace(client, headers, tenant, f"trc_{uuid.uuid4().hex[:12]}", 10, tool_ok=False)

    first = client.post("/v1/discovery", json={}, headers=headers)
    second = client.post("/v1/discovery", json={}, headers=headers)
    assert first.status_code == 201 and second.status_code == 201

    # Same inputs → identical report digest: the clustering is a pure
    # function of the trace reads, so a re-run re-signs the same bytes.
    assert first.json()["report_digest"] == second.json()["report_digest"]


def test_discovery_scopes_by_agent(client: TestClient, auth_headers, evaluator: Principal) -> None:
    headers = auth_headers(evaluator)
    tenant = evaluator.tenant_id
    match_trace = f"trc_{uuid.uuid4().hex[:12]}"
    _ingest_trace(client, headers, tenant, match_trace, 0, tool_ok=False, agent_id="agt_match")
    _ingest_trace(
        client,
        headers,
        tenant,
        f"trc_{uuid.uuid4().hex[:12]}",
        10,
        tool_ok=False,
        agent_id="agt_other",
    )

    response = client.post("/v1/discovery", json={"agent_id": "agt_match"}, headers=headers)

    assert response.status_code == 201, response.text
    report = response.json()
    assert report["agent_id"] == "agt_match"
    assert report["traces_scanned"] == 1
    clustered = {tid for c in report["clusters"] for tid in c["trace_ids"]}
    assert clustered == {match_trace}


def test_unregistered_payload_bodies_degrade_to_unresolved(
    client: TestClient, auth_headers, evaluator: Principal
) -> None:
    headers = auth_headers(evaluator)
    tenant = evaluator.tenant_id
    trace_id = f"trc_{uuid.uuid4().hex[:12]}"
    # make_raw_event's payload_digest references bytes that were never
    # registered — discovery counts the unresolved events and still clusters
    # the trace from the envelope-level signals.
    _ingest(
        client,
        headers,
        [make_raw_event(0, tenant_id=tenant, trace_id=trace_id, event_type="trace.ended")],
    )

    response = client.post("/v1/discovery", json={}, headers=headers)

    assert response.status_code == 201, response.text
    report = response.json()
    assert report["traces_scanned"] == 1
    assert report["unresolved_events"] == 1


def test_discovery_report_get_and_list_roundtrip(
    client: TestClient, auth_headers, evaluator: Principal
) -> None:
    headers = auth_headers(evaluator)
    _ingest_trace(
        client, headers, evaluator.tenant_id, f"trc_{uuid.uuid4().hex[:12]}", 0, tool_ok=False
    )
    created = client.post("/v1/discovery", json={}, headers=headers)
    assert created.status_code == 201, created.text
    report_id = created.json()["report_id"]

    fetched = client.get(f"/v1/discovery/{report_id}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["report_digest"] == created.json()["report_digest"]

    listed = client.get("/v1/discovery", headers=headers)
    assert listed.status_code == 200
    assert [r["report_id"] for r in listed.json()] == [report_id]


def test_cross_tenant_discovery_report_is_not_found(
    client: TestClient, auth_headers, evaluator: Principal, foreign_evaluator: Principal
) -> None:
    own_headers = auth_headers(evaluator)
    foreign_headers = auth_headers(foreign_evaluator)
    _ingest_trace(
        client, own_headers, evaluator.tenant_id, f"trc_{uuid.uuid4().hex[:12]}", 0, tool_ok=False
    )
    created = client.post("/v1/discovery", json={}, headers=own_headers)
    assert created.status_code == 201, created.text

    # Same 404 for "no such report" and "another tenant's report" — the
    # distinction would let a caller enumerate foreign report ids.
    response = client.get(f"/v1/discovery/{created.json()['report_id']}", headers=foreign_headers)
    assert response.status_code == 404

    foreign_list = client.get("/v1/discovery", headers=foreign_headers)
    assert foreign_list.status_code == 200
    assert foreign_list.json() == []


def test_discovery_requires_the_evaluator_role(
    client: TestClient, auth_headers, candidate_runner: Principal
) -> None:
    headers = auth_headers(candidate_runner)

    response = client.post("/v1/discovery", json={}, headers=headers)

    assert response.status_code == 400, response.text
    assert "only the evaluator role" in response.json()["detail"]


def test_unknown_discovery_report_is_not_found(
    client: TestClient, auth_headers, evaluator: Principal
) -> None:
    response = client.get(
        f"/v1/discovery/drpt_{uuid.uuid4().hex[:12]}", headers=auth_headers(evaluator)
    )
    assert response.status_code == 404
