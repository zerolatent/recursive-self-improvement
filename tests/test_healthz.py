"""Tests for the evaluation-plane service's liveness endpoint."""

from __future__ import annotations

from fastapi.testclient import TestClient

from evoruntime.server.app import create_app


def test_healthz_returns_200_ok() -> None:
    client = TestClient(create_app())

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
