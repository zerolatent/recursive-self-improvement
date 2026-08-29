"""HTTP-level tests for the payload-registration endpoints (H2).

Round-trip with classification, tombstone deletion through the D4 flow, and
the tenant boundary: a digest that exists for another tenant must be
indistinguishable from one that never existed.
"""

from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient

from evoruntime.core.principal import Principal


def _digest(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


def _post_payload(client: TestClient, headers: dict[str, str], content: bytes, classification: str):
    return client.post(
        "/v1/payloads",
        params={"classification": classification},
        content=content,
        headers={**headers, "content-type": "application/octet-stream"},
    )


def test_payload_round_trip_with_classification(
    client: TestClient, auth_headers, evaluator: Principal
) -> None:
    headers = auth_headers(evaluator)
    content = b"the patch body a fixture agent produced"

    response = _post_payload(client, headers, content, "confidential")

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["payload_digest"] == _digest(content)
    assert body["byte_size"] == len(content)
    assert body["data_classification"] == "confidential"

    read = client.get(f"/v1/payloads/{body['payload_digest']}", headers=headers)
    assert read.status_code == 200
    assert read.content == content
    assert read.headers["x-evoruntime-data-classification"] == "confidential"


def test_registration_is_idempotent_by_content(
    client: TestClient, auth_headers, evaluator: Principal
) -> None:
    headers = auth_headers(evaluator)
    content = b"same bytes, twice"

    first = _post_payload(client, headers, content, "internal")
    second = _post_payload(client, headers, content, "internal")

    assert first.status_code == 201 and second.status_code == 201
    assert first.json()["payload_digest"] == second.json()["payload_digest"]


def test_invalid_classification_is_rejected(
    client: TestClient, auth_headers, evaluator: Principal
) -> None:
    response = _post_payload(client, auth_headers(evaluator), b"content", "not-a-real-tier")
    assert response.status_code == 422


def test_unauthenticated_upload_is_401(client: TestClient) -> None:
    response = client.post(
        "/v1/payloads",
        params={"classification": "internal"},
        content=b"content",
        headers={"content-type": "application/octet-stream"},
    )
    assert response.status_code == 401


def test_tombstone_deletion_revokes_access(
    client: TestClient, auth_headers, evaluator: Principal
) -> None:
    headers = auth_headers(evaluator)
    content = b"payload that will be deleted on request"
    digest = _post_payload(client, headers, content, "restricted").json()["payload_digest"]

    deleted = client.delete(f"/v1/payloads/{digest}", headers=headers)
    assert deleted.status_code == 200, deleted.text
    assert deleted.json()["payload_digest"] == digest
    assert deleted.json()["access_revoked_at"] is not None

    # Access revoked: the read is 410 Gone — provably deleted on request,
    # not silently missing.
    read = client.get(f"/v1/payloads/{digest}", headers=headers)
    assert read.status_code == 410

    # Idempotent: deleting an already-revoked digest returns the existing
    # tombstone rather than opening a second deletion request.
    again = client.delete(f"/v1/payloads/{digest}", headers=headers)
    assert again.status_code == 200
    assert again.json()["tombstone_id"] == deleted.json()["tombstone_id"]


def test_delete_unknown_payload_is_404(
    client: TestClient, auth_headers, evaluator: Principal
) -> None:
    response = client.delete(f"/v1/payloads/sha256:{'cd' * 32}", headers=auth_headers(evaluator))
    assert response.status_code == 404


def test_cross_tenant_payload_access_is_denied(
    client: TestClient, auth_headers, evaluator: Principal, foreign_evaluator: Principal
) -> None:
    own_headers = auth_headers(evaluator)
    foreign_headers = auth_headers(foreign_evaluator)
    content = b"tenant A's secret bytes"
    digest = _post_payload(client, own_headers, content, "confidential").json()["payload_digest"]

    # Right role, wrong tenant: same 404 as a digest that never existed.
    read = client.get(f"/v1/payloads/{digest}", headers=foreign_headers)
    assert read.status_code == 404

    delete = client.delete(f"/v1/payloads/{digest}", headers=foreign_headers)
    assert delete.status_code == 404

    # The owner's access is untouched by the denied attempts.
    assert client.get(f"/v1/payloads/{digest}", headers=own_headers).content == content
