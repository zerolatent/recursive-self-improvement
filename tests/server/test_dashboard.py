"""Smoke tests for the minimal read-only dashboard.

The dashboard is deliberately minimal (API-first per locked decision #7):
server-rendered HTML *shells* whose tables are populated client-side by
fetching the same tenant-scoped /v1 endpoints the JSON API exposes. These
tests prove the shells render, wire the right endpoints, and never let a
campaign id inject markup — not that the HTML is pretty. Tenant scoping
itself is enforced (and tested) at the API layer the shells call.
"""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_dashboard_home_renders_campaign_list_shell(client: TestClient) -> None:
    response = client.get("/dashboard")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "EvoRuntime" in response.text
    # The list is populated from the tenant-scoped campaigns resource.
    assert "fetch('/v1/campaigns')" in response.text


def test_dashboard_campaign_page_wires_comparison_endpoints(client: TestClient) -> None:
    response = client.get("/dashboard/campaigns/camp_abc123")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "camp_abc123" in response.text
    # Candidate comparison, evidence, approvals, and release state all come
    # from the JSON API — the shell only references those resources.
    for endpoint in ("/pareto", "/v1/evidence", "/approvals", "/v1/releases"):
        assert endpoint in response.text


def test_dashboard_escapes_campaign_id_in_page(client: TestClient) -> None:
    # A campaign id is untrusted input (it arrives on the URL path); the
    # shell must escape it everywhere it interpolates.
    # A slash-free payload: Starlette routes on the decoded path, so a
    # decoded `/` would split the segment and 404 before the shell renders.
    response = client.get("/dashboard/campaigns/camp_x%22%3E%3Csvg%20onload%3Dalert(1)%3E")

    assert response.status_code == 200
    assert "<svg onload=alert(1)>" not in response.text
    assert "&lt;svg onload=alert(1)&gt;" in response.text
