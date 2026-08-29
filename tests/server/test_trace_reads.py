"""HTTP-level tests for the tenant-scoped trace read endpoints (H2).

Exercises the real request/response cycle (FastAPI TestClient -> handler ->
Postgres) against events ingested through the real `/v1/events:ingest`
endpoint, so the read surface is proven against what the write path actually
persisted — not against hand-inserted rows.

Uses the shared `client` fixture from `tests/conftest.py`; each test scopes
itself to fresh tenant ids and asserts only on rows it wrote (same isolation
pattern as the D2 ingest tests).
"""

from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from evoruntime.core.principal import Principal
from tests.support.factories import make_raw_event


def _ingest(client: TestClient, headers: dict[str, str], events: list[dict]) -> None:
    response = client.post("/v1/events:ingest", json={"events": events}, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["rejected"] == []


def test_list_traces_is_tenant_scoped(
    client: TestClient, auth_headers, evaluator: Principal, foreign_evaluator: Principal
) -> None:
    own_headers = auth_headers(evaluator)
    foreign_headers = auth_headers(foreign_evaluator)

    # make_raw_event derives trace_id from the event index, so give each
    # tenant its own trace ids — the point is that the same trace_id must
    # never be visible from two tenants.
    own_events = [
        make_raw_event(i, tenant_id=evaluator.tenant_id, trace_id=f"trc_own{i:012d}")
        for i in range(3)
    ]
    foreign_events = [
        make_raw_event(i, tenant_id=foreign_evaluator.tenant_id, trace_id=f"trc_frg{i:012d}")
        for i in range(2)
    ]
    _ingest(client, own_headers, own_events)
    _ingest(client, foreign_headers, foreign_events)

    own = client.get("/v1/traces", headers=own_headers)
    assert own.status_code == 200
    own_trace_ids = {t["trace_id"] for t in own.json()}
    assert own_trace_ids == {e["trace_id"] for e in own_events}

    foreign = client.get("/v1/traces", headers=foreign_headers)
    assert foreign.status_code == 200
    foreign_trace_ids = {t["trace_id"] for t in foreign.json()}
    assert foreign_trace_ids == {e["trace_id"] for e in foreign_events}
    # The two views must not overlap: neither tenant sees the other's traces.
    assert own_trace_ids.isdisjoint(foreign_trace_ids)


def test_list_traces_filters_by_agent_campaign_and_release(
    client: TestClient, auth_headers, evaluator: Principal
) -> None:
    headers = auth_headers(evaluator)
    tenant = evaluator.tenant_id

    matching = make_raw_event(0, tenant_id=tenant, agent_id="agt_match")
    matching["campaign_id"] = "cmp_match"
    matching["release_id"] = "rel_match"
    other_agent = make_raw_event(1, tenant_id=tenant, agent_id="agt_other")
    _ingest(client, headers, [matching, other_agent])

    by_agent = client.get("/v1/traces", params={"agent_id": "agt_match"}, headers=headers)
    assert [t["trace_id"] for t in by_agent.json()] == [matching["trace_id"]]

    by_campaign = client.get("/v1/traces", params={"campaign_id": "cmp_match"}, headers=headers)
    assert [t["trace_id"] for t in by_campaign.json()] == [matching["trace_id"]]

    by_release = client.get("/v1/traces", params={"release_id": "rel_match"}, headers=headers)
    assert [t["trace_id"] for t in by_release.json()] == [matching["trace_id"]]


def test_trace_events_reconstructs_the_sequence(
    client: TestClient, auth_headers, evaluator: Principal
) -> None:
    headers = auth_headers(evaluator)
    trace_id = f"trc_{uuid.uuid4().hex[:12]}"
    events = [make_raw_event(i, tenant_id=evaluator.tenant_id, trace_id=trace_id) for i in range(4)]
    _ingest(client, headers, events)

    response = client.get(f"/v1/traces/{trace_id}/events", headers=headers)

    assert response.status_code == 200
    body = response.json()
    assert body["trace_id"] == trace_id
    assert body["event_count"] == 4
    assert body["valid"] is True
    # Reconstruction returns the events in ingest (chain_seq) order, each
    # with a passing integrity verdict.
    assert [e["chain_seq"] for e in body["events"]] == sorted(
        e["chain_seq"] for e in body["events"]
    )
    assert [e["event_id"] for e in body["events"]] == [e["event_id"] for e in events]
    assert all(e["hash_valid"] for e in body["events"])
    # The envelope round-trips through the same EventEnvelope type the hash
    # was computed over at ingest time.
    assert body["events"][0]["envelope"]["event_id"] == events[0]["event_id"]
    assert body["events"][0]["envelope"]["trace_id"] == trace_id


def test_cross_tenant_trace_read_is_denied(
    client: TestClient, auth_headers, evaluator: Principal, foreign_evaluator: Principal
) -> None:
    own_headers = auth_headers(evaluator)
    foreign_headers = auth_headers(foreign_evaluator)
    trace_id = f"trc_{uuid.uuid4().hex[:12]}"
    _ingest(
        client,
        own_headers,
        [make_raw_event(i, tenant_id=evaluator.tenant_id, trace_id=trace_id) for i in range(2)],
    )

    # Right role, wrong tenant: the foreign trace id renders as the same 404
    # as a missing one — the distinction would enable trace-id enumeration.
    response = client.get(f"/v1/traces/{trace_id}/events", headers=foreign_headers)
    assert response.status_code == 404


def test_unknown_trace_is_404(client: TestClient, auth_headers, evaluator: Principal) -> None:
    response = client.get(
        f"/v1/traces/trc_{uuid.uuid4().hex[:12]}/events", headers=auth_headers(evaluator)
    )
    assert response.status_code == 404


def test_trace_reads_require_identity_headers(client: TestClient) -> None:
    assert client.get("/v1/traces").status_code == 401
    assert client.get("/v1/traces/trc_whatever/events").status_code == 401
