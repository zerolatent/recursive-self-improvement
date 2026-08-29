"""Typed HTTP client for the FR-014 control-plane API.

The `evo` CLI and any CI/CD integration talk to the evaluation plane
through this client and nothing else: every method maps to exactly one
API call, every call carries the workload-identity headers, and every
non-2xx becomes an `EvoApiError` carrying the server's detail — the CLI
has no error-handling logic of its own to get wrong.
"""

from __future__ import annotations

from typing import Any

import httpx


class EvoApiError(RuntimeError):
    """A control-plane request failed, with the API's status and detail."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(f"HTTP {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail


class EvoApiClient:
    """Thin, typed wrapper over the `/v1` control-plane endpoints."""

    def __init__(
        self,
        base_url: str,
        *,
        identity: str,
        role: str,
        tenant: str,
        timeout: float = 30.0,
    ) -> None:
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=timeout,
            headers={
                "x-evoruntime-identity": identity,
                "x-evoruntime-role": role,
                "x-evoruntime-tenant": tenant,
            },
        )

    def close(self) -> None:
        """Release the underlying HTTP connection pool."""
        self._client.close()

    def __enter__(self) -> EvoApiClient:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ------------------------------------------------------------------
    # transport
    # ------------------------------------------------------------------

    def _request_dict(self, method: str, path: str, json_body: Any = None) -> dict[str, Any]:
        """Perform a request that must return a JSON object."""
        payload = self._request(method, path, json_body)
        if not isinstance(payload, dict):
            raise EvoApiError(
                502, f"expected an object response from {path}, got {type(payload).__name__}"
            )
        return payload

    def _request_list(self, method: str, path: str, json_body: Any = None) -> list[dict[str, Any]]:
        """Perform a request that must return a JSON array of objects."""
        payload = self._request(method, path, json_body)
        if not isinstance(payload, list):
            raise EvoApiError(
                502, f"expected an array response from {path}, got {type(payload).__name__}"
            )
        return [item for item in payload if isinstance(item, dict)]

    def _request(self, method: str, path: str, json_body: Any = None) -> Any:
        response = self._client.request(method, path, json=json_body)
        if response.status_code >= 400:
            detail = "request failed"
            try:
                payload = response.json()
            except ValueError:
                payload = {}
            if isinstance(payload, dict) and "detail" in payload:
                detail = str(payload["detail"])
            raise EvoApiError(response.status_code, detail)
        if response.status_code == 204 or not response.content:
            return None
        return response.json()

    # ------------------------------------------------------------------
    # campaigns
    # ------------------------------------------------------------------

    def create_campaign(self, spec: dict[str, Any]) -> dict[str, Any]:
        """POST /v1/campaigns — validate, pin, sign, and persist a spec."""
        return self._request_dict("POST", "/v1/campaigns", {"spec": spec})

    def list_campaigns(self) -> list[dict[str, Any]]:
        """GET /v1/campaigns."""
        return self._request_list("GET", "/v1/campaigns")

    def get_campaign(self, campaign_id: str) -> dict[str, Any]:
        """GET /v1/campaigns/{id} — detail with transition history."""
        return self._request_dict("GET", f"/v1/campaigns/{campaign_id}")

    def transition_campaign(
        self, campaign_id: str, to_phase: str, *, reason: str = ""
    ) -> dict[str, Any]:
        """POST /v1/campaigns/{id}/transitions — one lifecycle move."""
        return self._request_dict(
            "POST",
            f"/v1/campaigns/{campaign_id}/transitions",
            {"to_phase": to_phase, "reason": reason},
        )

    def campaign_pareto(self, campaign_id: str) -> dict[str, Any]:
        """GET /v1/campaigns/{id}/pareto — comparison vs parents."""
        return self._request_dict("GET", f"/v1/campaigns/{campaign_id}/pareto")

    def campaign_approvals(self, campaign_id: str) -> list[dict[str, Any]]:
        """GET /v1/campaigns/{id}/approvals."""
        return self._request_list("GET", f"/v1/campaigns/{campaign_id}/approvals")

    # ------------------------------------------------------------------
    # agents
    # ------------------------------------------------------------------

    def register_agent(
        self,
        *,
        plugin_id: str,
        kind: str,
        pinned_image: str,
        artifact_types: list[str],
        agent_id: str | None = None,
    ) -> dict[str, Any]:
        """POST /v1/agents."""
        body: dict[str, Any] = {
            "plugin_id": plugin_id,
            "kind": kind,
            "pinned_image": pinned_image,
            "artifact_types": artifact_types,
        }
        if agent_id is not None:
            body["agent_id"] = agent_id
        return self._request_dict("POST", "/v1/agents", body)

    def list_agents(self) -> list[dict[str, Any]]:
        """GET /v1/agents."""
        return self._request_list("GET", "/v1/agents")

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        """GET /v1/agents/{id}."""
        return self._request_dict("GET", f"/v1/agents/{agent_id}")

    # ------------------------------------------------------------------
    # candidates
    # ------------------------------------------------------------------

    def register_candidate(
        self,
        *,
        artifact_type: str,
        canonical_bytes_b64: str,
        strategy_id: str,
        campaign_id: str | None = None,
        parent_digest: str | None = None,
        proposal_metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """POST /v1/candidates."""
        body: dict[str, Any] = {
            "artifact_type": artifact_type,
            "canonical_bytes_b64": canonical_bytes_b64,
            "strategy_id": strategy_id,
        }
        if campaign_id is not None:
            body["campaign_id"] = campaign_id
        if parent_digest is not None:
            body["parent_digest"] = parent_digest
        if proposal_metadata is not None:
            body["proposal_metadata"] = proposal_metadata
        return self._request_dict("POST", "/v1/candidates", body)

    def list_candidates(self, *, campaign_id: str | None = None) -> list[dict[str, Any]]:
        """GET /v1/candidates, optionally scoped to a campaign."""
        params = f"?campaign_id={campaign_id}" if campaign_id else ""
        return self._request_list("GET", f"/v1/candidates{params}")

    def get_candidate(self, proposal_id: str) -> dict[str, Any]:
        """GET /v1/candidates/{id}."""
        return self._request_dict("GET", f"/v1/candidates/{proposal_id}")

    def candidate_diff(self, proposal_id: str) -> dict[str, Any]:
        """GET /v1/candidates/{id}/diff — semantic diff via the adapter."""
        return self._request_dict("GET", f"/v1/candidates/{proposal_id}/diff")

    # ------------------------------------------------------------------
    # evidence
    # ------------------------------------------------------------------

    def record_evidence(
        self,
        *,
        redacted_items: list[dict[str, Any]],
        campaign_id: str | None = None,
        artifact_digest: str | None = None,
        bundle_id: str | None = None,
    ) -> dict[str, Any]:
        """POST /v1/evidence."""
        body: dict[str, Any] = {"redacted_items": redacted_items}
        if campaign_id is not None:
            body["campaign_id"] = campaign_id
        if artifact_digest is not None:
            body["artifact_digest"] = artifact_digest
        if bundle_id is not None:
            body["bundle_id"] = bundle_id
        return self._request_dict("POST", "/v1/evidence", body)

    def list_evidence(
        self, *, campaign_id: str | None = None, artifact_digest: str | None = None
    ) -> list[dict[str, Any]]:
        """GET /v1/evidence, optionally filtered."""
        params: list[str] = []
        if campaign_id:
            params.append(f"campaign_id={campaign_id}")
        if artifact_digest:
            params.append(f"artifact_digest={artifact_digest}")
        suffix = f"?{'&'.join(params)}" if params else ""
        return self._request_list("GET", f"/v1/evidence{suffix}")

    def get_evidence(self, bundle_id: str) -> dict[str, Any]:
        """GET /v1/evidence/{bundle_id}."""
        return self._request_dict("GET", f"/v1/evidence/{bundle_id}")

    # ------------------------------------------------------------------
    # evaluations
    # ------------------------------------------------------------------

    def record_evaluation(
        self, *, artifact_digest: str, outcome: str, metrics: dict[str, Any]
    ) -> dict[str, Any]:
        """POST /v1/evaluations — signed outcome attestation."""
        return self._request_dict(
            "POST",
            "/v1/evaluations",
            {"artifact_digest": artifact_digest, "outcome": outcome, "metrics": metrics},
        )

    def list_evaluations(self, *, artifact_digest: str | None = None) -> list[dict[str, Any]]:
        """GET /v1/evaluations, optionally filtered by artifact."""
        suffix = f"?artifact_digest={artifact_digest}" if artifact_digest else ""
        return self._request_list("GET", f"/v1/evaluations{suffix}")

    # ------------------------------------------------------------------
    # approvals
    # ------------------------------------------------------------------

    def record_approval(
        self, *, campaign_id: str, proposal_id: str, decision: str, reason: str | None = None
    ) -> dict[str, Any]:
        """POST /v1/approvals — an E1 status event on the candidate."""
        body: dict[str, Any] = {
            "campaign_id": campaign_id,
            "proposal_id": proposal_id,
            "decision": decision,
        }
        if reason is not None:
            body["reason"] = reason
        return self._request_dict("POST", "/v1/approvals", body)

    # ------------------------------------------------------------------
    # review board (F10)
    # ------------------------------------------------------------------

    def create_approval_request(
        self,
        *,
        kind: str,
        justification: str,
        campaign_id: str | None = None,
        proposal_id: str | None = None,
        plugin_id: str | None = None,
        content_digest: str | None = None,
        privileged_role: str | None = None,
    ) -> dict[str, Any]:
        """POST /v1/approvals/requests — open a review-board request."""
        body: dict[str, Any] = {"kind": kind, "justification": justification}
        for key, value in (
            ("campaign_id", campaign_id),
            ("proposal_id", proposal_id),
            ("plugin_id", plugin_id),
            ("content_digest", content_digest),
            ("privileged_role", privileged_role),
        ):
            if value is not None:
                body[key] = value
        return self._request_dict("POST", "/v1/approvals/requests", body)

    def list_approval_requests(self, *, campaign_id: str | None = None) -> list[dict[str, Any]]:
        """GET /v1/approvals/requests, optionally scoped to a campaign."""
        params = f"?campaign_id={campaign_id}" if campaign_id else ""
        return self._request_list("GET", f"/v1/approvals/requests{params}")

    def get_approval_request(self, request_id: str) -> dict[str, Any]:
        """GET /v1/approvals/requests/{id} — one request with its decisions."""
        return self._request_dict("GET", f"/v1/approvals/requests/{request_id}")

    def decide_approval_request(
        self, request_id: str, *, decision: str, note: str = ""
    ) -> dict[str, Any]:
        """POST /v1/approvals/requests/{id}/decisions — the verified caller decides."""
        return self._request_dict(
            "POST",
            f"/v1/approvals/requests/{request_id}/decisions",
            {"decision": decision, "note": note},
        )

    def admit_approval_request(self, request_id: str) -> dict[str, Any]:
        """POST /v1/approvals/requests/{id}/admission — mint the signed record."""
        return self._request_dict("POST", f"/v1/approvals/requests/{request_id}/admission", {})

    def list_admissions(self, *, request_id: str | None = None) -> list[dict[str, Any]]:
        """GET /v1/approvals/admissions — signed admission records (read-only)."""
        params = f"?request_id={request_id}" if request_id else ""
        return self._request_list("GET", f"/v1/approvals/admissions{params}")

    def get_admission(self, record_id: str) -> dict[str, Any]:
        """GET /v1/approvals/admissions/{id} — one signed admission record."""
        return self._request_dict("GET", f"/v1/approvals/admissions/{record_id}")

    def get_analysis_report(self, report_id: str) -> dict[str, Any]:
        """GET /v1/approvals/analysis-reports/{id} — one signed F3 verdict."""
        return self._request_dict("GET", f"/v1/approvals/analysis-reports/{report_id}")

    # ------------------------------------------------------------------
    # discovery (H3)
    # ------------------------------------------------------------------

    def run_discovery(
        self,
        *,
        campaign_id: str | None = None,
        agent_id: str | None = None,
        release_id: str | None = None,
    ) -> dict[str, Any]:
        """POST /v1/discovery — cluster trace failures into a signed report."""
        body: dict[str, Any] = {}
        if campaign_id is not None:
            body["campaign_id"] = campaign_id
        if agent_id is not None:
            body["agent_id"] = agent_id
        if release_id is not None:
            body["release_id"] = release_id
        return self._request_dict("POST", "/v1/discovery", body)

    def list_discovery_reports(self, *, campaign_id: str | None = None) -> list[dict[str, Any]]:
        """GET /v1/discovery — signed discovery reports, optionally scoped."""
        params = f"?campaign_id={campaign_id}" if campaign_id else ""
        return self._request_list("GET", f"/v1/discovery{params}")

    def get_discovery_report(self, report_id: str) -> dict[str, Any]:
        """GET /v1/discovery/{id} — one signed discovery report."""
        return self._request_dict("GET", f"/v1/discovery/{report_id}")

    def get_compensation_plan(self, plan_id: str) -> dict[str, Any]:
        """GET /v1/approvals/compensation-plans/{id} — one signed F5 plan."""
        return self._request_dict("GET", f"/v1/approvals/compensation-plans/{plan_id}")

    # ------------------------------------------------------------------
    # releases
    # ------------------------------------------------------------------

    def create_release(
        self,
        *,
        artifact_digests: list[str],
        adapter_versions: dict[str, Any],
        model_routes: dict[str, Any],
        policies: dict[str, Any],
        prior_release_digest: str | None = None,
        status: str = "canary",
    ) -> dict[str, Any]:
        """POST /v1/releases — sign a manifest and record activation."""
        body: dict[str, Any] = {
            "artifact_digests": artifact_digests,
            "adapter_versions": adapter_versions,
            "model_routes": model_routes,
            "policies": policies,
            "status": status,
        }
        if prior_release_digest is not None:
            body["prior_release_digest"] = prior_release_digest
        return self._request_dict("POST", "/v1/releases", body)

    def list_releases(self) -> list[dict[str, Any]]:
        """GET /v1/releases."""
        return self._request_list("GET", "/v1/releases")

    def promote_release(self, manifest_digest: str) -> dict[str, Any]:
        """POST /v1/releases/{digest}/promote — canary to active."""
        return self._request_dict("POST", f"/v1/releases/{manifest_digest}/promote")

    def rollback_release(self, manifest_digest: str) -> dict[str, Any]:
        """POST /v1/releases/{digest}/rollback."""
        return self._request_dict("POST", f"/v1/releases/{manifest_digest}/rollback")

    def rollback_status(self, manifest_digest: str) -> dict[str, Any]:
        """GET /v1/releases/{digest}/rollback-status."""
        return self._request_dict("GET", f"/v1/releases/{manifest_digest}/rollback-status")
