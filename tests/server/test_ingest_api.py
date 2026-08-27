"""HTTP-level tests for the batched ingest and chain-verify endpoints.

Exercises the real request/response cycle (FastAPI TestClient -> JSON body
-> handler -> Postgres), which is what actually proves the JSON-mode
validation fix in `evoruntime.core.events.parse_wire_envelope`: these
payloads are plain `client.post(json=...)` calls, so if the handler ever
regresses back to `EventEnvelope.model_validate()` on the raw dict, every
one of these "valid event" assertions fails.

Uses the shared `client` fixture from `tests/conftest.py` (a `TestClient`
built from the real `create_app()` with `get_session_factory` overridden
to the test database) rather than constructing its own app instance, so
routing and dependency wiring are exercised exactly as production sees
them.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.support.factories import make_raw_batch, make_raw_event


def test_valid_batch_is_fully_accepted(client: TestClient) -> None:
    events = make_raw_batch(5, tenant_id="tnt_apivalid")

    response = client.post("/v1/events:ingest", json={"events": events})

    assert response.status_code == 200
    body = response.json()
    assert body["accepted_event_ids"] == [e["event_id"] for e in events]
    assert body["rejected"] == []


def test_malformed_event_is_rejected_others_still_accepted(client: TestClient) -> None:
    events = make_raw_batch(3, tenant_id="tnt_apipartial")
    del events[1]["occurred_at"]  # malformed: missing required field

    response = client.post("/v1/events:ingest", json={"events": events})

    assert response.status_code == 200
    body = response.json()
    assert body["accepted_event_ids"] == [events[0]["event_id"], events[2]["event_id"]]
    assert len(body["rejected"]) == 1
    rejected = body["rejected"][0]
    assert rejected["index"] == 1
    assert rejected["error_type"] == "schema_validation_error"
    assert any(detail["loc"] == ["occurred_at"] for detail in rejected["details"])


def test_duplicate_event_is_rejected_with_typed_error(client: TestClient) -> None:
    event = make_raw_event(0, tenant_id="tnt_apidup")

    first = client.post("/v1/events:ingest", json={"events": [event]})
    second = client.post("/v1/events:ingest", json={"events": [event]})

    assert first.json()["accepted_event_ids"] == [event["event_id"]]
    second_body = second.json()
    assert second_body["accepted_event_ids"] == []
    assert second_body["rejected"][0]["error_type"] == "duplicate_event"


def test_empty_batch_is_rejected_by_request_validation(client: TestClient) -> None:
    response = client.post("/v1/events:ingest", json={"events": []})

    assert response.status_code == 422


def test_chain_verify_endpoint_reports_valid_chain(client: TestClient) -> None:
    tenant_id = "tnt_apiverify"
    events = make_raw_batch(4, tenant_id=tenant_id)
    client.post("/v1/events:ingest", json={"events": events})

    response = client.get(f"/v1/tenants/{tenant_id}/chain/verify")

    assert response.status_code == 200
    body = response.json()
    assert body["tenant_id"] == tenant_id
    assert body["event_count"] == 4
    assert body["valid"] is True
    assert body["violations"] == []


def test_chain_verify_endpoint_for_unknown_tenant_is_valid_and_empty(client: TestClient) -> None:
    response = client.get("/v1/tenants/tntneverseenviaapi/chain/verify")

    assert response.status_code == 200
    body = response.json()
    assert body["event_count"] == 0
    assert body["valid"] is True
