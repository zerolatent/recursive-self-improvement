"""H6 canary monitoring service tests: §17.1 steps 8–9 measured as a
service, not a library.

The library assertions (fixed horizon, ≤5% allocation, ≥200 paired tasks,
100% digest reporting, severity-1 stop) are re-run here against the
service surface — the HTTP endpoints over the real control-plane
database — plus the service-only behaviors: eligibility admission
refusals, severity-1 auto-rollback driving the release rollback path, and
candidate-state namespacing enforced at the service boundary.
"""

from __future__ import annotations

import base64
import itertools
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from evoruntime.registry.service import RegistryService
from evoruntime.release import (
    CANDIDATE_NAMESPACE,
    INCUMBENT_NAMESPACE,
    CompressedClock,
    InProcessFleetSimulator,
    NamespaceViolationError,
    ReleaseController,
    UnknownSessionError,
)
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.selection import InMemoryPointerAuditLog, ReleasePointerStore
from evoruntime.server.dependencies import get_release_plane

# Manifest digests are content-derived and the test database is shared
# across tests, so every test registers unique prompt bytes.
_variant = itertools.count()


def _incumbent_bytes() -> bytes:
    return f"prompt v1: answer carefully (variant {next(_variant)})".encode()


def _candidate_bytes() -> bytes:
    return f"prompt v2: answer carefully, step by step (variant {next(_variant)})".encode()


def _headers(tenant_id: str) -> dict[str, str]:
    """Evaluator-role workload-identity headers for the test tenant."""
    return {
        "x-evoruntime-identity": "svc_evaluator_1",
        "x-evoruntime-role": "evaluator",
        "x-evoruntime-tenant": tenant_id,
    }


@pytest.fixture
def fresh_release_plane(client: TestClient) -> None:
    """A fresh release plane per test: pointer, fleet, and clock are
    deployment singletons in production, but each test needs its own so
    pointer state from a previous test cannot leak into this one."""
    clock = CompressedClock(scale=3600.0)
    fleet = InProcessFleetSimulator(worker_count=100, latency_sampler=lambda: 60.0, clock=clock)
    controller = ReleaseController(
        ReleasePointerStore(audit_log=InMemoryPointerAuditLog()),
        WorkloadIdentity(role=WorkloadRole.RELEASE_CONTROLLER, subject="svc-release-controller"),
    )
    client.app.dependency_overrides[get_release_plane] = lambda: (controller, fleet, clock)


def _register_candidate(
    client: TestClient, headers: dict[str, str], *, content: bytes
) -> dict[str, Any]:
    response = client.post(
        "/v1/candidates",
        json={
            "artifact_type": "prompt_bundle",
            "canonical_bytes_b64": base64.b64encode(content).decode(),
            "strategy_id": "evo-prompt-strategist",
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return dict(response.json())


def _create_release(
    client: TestClient,
    headers: dict[str, str],
    artifact_digest: str,
    *,
    prior_release_digest: str | None = None,
) -> dict[str, Any]:
    response = client.post(
        "/v1/releases",
        json={
            "artifact_digests": [artifact_digest],
            "adapter_versions": {"evo-prompt-strategist": "1.2.0"},
            "model_routes": {"default": "gpt-5-mini"},
            "policies": {"tier": "tier-2-standard"},
            "status": "canary",
            "prior_release_digest": prior_release_digest,
        },
        headers=headers,
    )
    assert response.status_code == 201, response.text
    return dict(response.json())


def _activate_incumbent(
    client: TestClient, headers: dict[str, str], content: bytes
) -> dict[str, Any]:
    """Register a prompt bundle, release it, and promote it to active —
    the incumbent every canary in this module compares against."""
    registered = _register_candidate(client, headers, content=content)
    release = _create_release(client, headers, registered["artifact_digest"])
    promoted = client.post(f"/v1/releases/{release['manifest_digest']}/promote", headers=headers)
    assert promoted.status_code == 200, promoted.text
    return release


def _start_canary(
    client: TestClient,
    headers: dict[str, str],
    manifest_digest: str,
    body: dict[str, Any] | None = None,
) -> Any:
    return client.post(f"/v1/releases/{manifest_digest}/canary/start", json=body, headers=headers)


class TestCanaryRunAsAService:
    def test_completed_run_meets_the_library_conformance_thresholds(
        self, client: TestClient, tenant_id: str, fresh_release_plane: None
    ) -> None:
        headers = _headers(tenant_id)
        incumbent = _activate_incumbent(client, headers, _incumbent_bytes())
        registered = _register_candidate(client, headers, content=_candidate_bytes())
        candidate = _create_release(
            client,
            headers,
            registered["artifact_digest"],
            prior_release_digest=incumbent["manifest_digest"],
        )

        response = _start_canary(client, headers, candidate["manifest_digest"])

        assert response.status_code == 201, response.text
        run = response.json()
        # The §17.3 row-8 library assertions, re-measured at the service:
        assert run["outcome"] == "completed"
        assert run["paired_tasks"] == 200  # ≥200 paired tasks
        assert run["candidate_allocation"] <= 0.05  # ≤5% allocation
        assert run["digest_report_coverage"] == 1.0  # 100% digest reporting
        assert run["observation_elapsed_seconds"] >= 24 * 3600  # fixed 24h horizon
        assert run["release_status"] == "canary"  # completed, not rolled back
        assert run["rolled_back_to"] is None

    def test_canary_status_reads_the_live_ledger(
        self, client: TestClient, tenant_id: str, fresh_release_plane: None
    ) -> None:
        headers = _headers(tenant_id)
        incumbent = _activate_incumbent(client, headers, _incumbent_bytes())
        registered = _register_candidate(client, headers, content=_candidate_bytes())
        candidate = _create_release(
            client,
            headers,
            registered["artifact_digest"],
            prior_release_digest=incumbent["manifest_digest"],
        )

        before = client.get(
            f"/v1/releases/{candidate['manifest_digest']}/canary-status", headers=headers
        )
        assert before.status_code == 200
        assert before.json()["release_status"] == "canary"
        assert before.json()["latest_run"] is None  # nothing has run yet

        started = _start_canary(client, headers, candidate["manifest_digest"])
        run_id = started.json()["run_id"]

        after = client.get(
            f"/v1/releases/{candidate['manifest_digest']}/canary-status", headers=headers
        )
        assert after.status_code == 200
        latest = after.json()["latest_run"]
        assert latest is not None
        assert latest["run_id"] == run_id
        assert latest["outcome"] == "completed"

    def test_severity1_event_rolls_the_release_back_end_to_end(
        self, client: TestClient, tenant_id: str, fresh_release_plane: None
    ) -> None:
        headers = _headers(tenant_id)
        incumbent = _activate_incumbent(client, headers, _incumbent_bytes())
        registered = _register_candidate(client, headers, content=_candidate_bytes())
        candidate = _create_release(
            client,
            headers,
            registered["artifact_digest"],
            prior_release_digest=incumbent["manifest_digest"],
        )

        response = _start_canary(
            client,
            headers,
            candidate["manifest_digest"],
            body={
                "guardrail_events": [{"severity": 1, "kind": "holdout-regression", "task_index": 5}]
            },
        )

        assert response.status_code == 201, response.text
        run = response.json()
        # The harness stopped at the severity-1 event and rolled the
        # pointer back through the release controller.
        assert run["outcome"] == "rolled_back"
        assert "severity-1" in (run["stopped_reason"] or "")
        assert run["rolled_back_to"] == incumbent["manifest_digest"]
        assert run["paired_tasks"] < 200  # the horizon did not complete
        # The service drove the control plane's release rollback path:
        # the activation ledger records the rollback, and the prior
        # release is active again.
        assert run["release_status"] == "rolled_back"
        rollback_status = client.get(
            f"/v1/releases/{candidate['manifest_digest']}/rollback-status", headers=headers
        )
        assert rollback_status.json()["status"] == "rolled_back"
        incumbent_status = client.get(
            f"/v1/releases/{incumbent['manifest_digest']}/rollback-status", headers=headers
        )
        assert incumbent_status.json()["status"] == "active"

    def test_severity_2_events_do_not_stop_the_horizon(
        self, client: TestClient, tenant_id: str, fresh_release_plane: None
    ) -> None:
        headers = _headers(tenant_id)
        incumbent = _activate_incumbent(client, headers, _incumbent_bytes())
        registered = _register_candidate(client, headers, content=_candidate_bytes())
        candidate = _create_release(
            client,
            headers,
            registered["artifact_digest"],
            prior_release_digest=incumbent["manifest_digest"],
        )

        response = _start_canary(
            client,
            headers,
            candidate["manifest_digest"],
            body={
                "guardrail_events": [{"severity": 2, "kind": "elevated-latency", "task_index": 3}]
            },
        )

        assert response.status_code == 201, response.text
        run = response.json()
        assert run["outcome"] == "completed"
        assert run["paired_tasks"] == 200
        assert any(event["kind"] == "elevated-latency" for event in run["guardrail_events"])


class TestCanaryAdmissionRefusals:
    def test_ineligible_release_is_refused_and_nothing_runs(
        self,
        client: TestClient,
        tenant_id: str,
        session_factory: sessionmaker[Any],
        fresh_release_plane: None,
    ) -> None:
        headers = _headers(tenant_id)
        incumbent = _activate_incumbent(client, headers, _incumbent_bytes())
        # A tier-3 executable class: not canary-eligible, registered
        # directly so the F3 candidate gates (out of H6's scope) do not
        # decide this test.
        with session_factory() as session:
            artifact = RegistryService(session).register_artifact(
                tenant_id=tenant_id,
                artifact_type="workflow_graph",
                canonical_bytes=f'{{"steps": [], "variant": {next(_variant)}}}'.encode(),
            )
            digest = artifact.digest
            session.commit()
        candidate = _create_release(
            client,
            headers,
            digest,
            prior_release_digest=incumbent["manifest_digest"],
        )

        response = _start_canary(client, headers, candidate["manifest_digest"])

        assert response.status_code == 422, response.text
        body = response.json()
        assert "workflow_graph" in body["ineligible_classes"]
        # A refusal means the canary never existed: nothing recorded.
        status = client.get(
            f"/v1/releases/{candidate['manifest_digest']}/canary-status", headers=headers
        )
        assert status.json()["latest_run"] is None

    def test_canary_requires_canary_status(
        self, client: TestClient, tenant_id: str, fresh_release_plane: None
    ) -> None:
        headers = _headers(tenant_id)
        incumbent = _activate_incumbent(client, headers, _incumbent_bytes())
        registered = _register_candidate(client, headers, content=_candidate_bytes())
        candidate = _create_release(
            client,
            headers,
            registered["artifact_digest"],
            prior_release_digest=incumbent["manifest_digest"],
        )
        client.post(f"/v1/releases/{candidate['manifest_digest']}/promote", headers=headers)

        response = _start_canary(client, headers, candidate["manifest_digest"])

        assert response.status_code == 409  # already active, not canary

    def test_canary_refuses_a_mismatched_declared_incumbent(
        self, client: TestClient, tenant_id: str, fresh_release_plane: None
    ) -> None:
        headers = _headers(tenant_id)
        incumbent = _activate_incumbent(client, headers, _incumbent_bytes())
        # A real but never-promoted release: it exists in the ledger yet
        # is not what is active — the severity-1 rollback would have
        # nowhere honest to return to.
        decoy_artifact = _register_candidate(
            client, headers, content=b"prompt v1.5: unrelated line"
        )
        decoy = _create_release(client, headers, decoy_artifact["artifact_digest"])
        registered = _register_candidate(client, headers, content=_candidate_bytes())
        candidate = _create_release(
            client,
            headers,
            registered["artifact_digest"],
            prior_release_digest=decoy["manifest_digest"],
        )
        assert decoy["manifest_digest"] != incumbent["manifest_digest"]

        response = _start_canary(client, headers, candidate["manifest_digest"])

        assert response.status_code == 409

    def test_canary_status_of_unknown_release_is_404(
        self, client: TestClient, tenant_id: str, fresh_release_plane: None
    ) -> None:
        headers = _headers(tenant_id)

        response = client.get(
            f"/v1/releases/{'sha256:' + 'cd' * 32}/canary-status", headers=headers
        )

        assert response.status_code == 404


class TestServiceNamespacing:
    """Candidate-state namespacing enforced at the service boundary —
    the same rule the fleet simulator enforces, restated where
    production writes enter."""

    def _wrapped_fleet(self) -> tuple[Any, Any]:
        from evoruntime.api.canary import ServiceNamespacedFleet  # noqa: PLC0415

        clock = CompressedClock()
        inner = InProcessFleetSimulator(worker_count=4, latency_sampler=lambda: 1.0, clock=clock)
        return ServiceNamespacedFleet(inner), inner

    def test_candidate_session_cannot_write_incumbent_state(self) -> None:
        fleet, _ = self._wrapped_fleet()
        fleet.pin_session("s1", "sha256:aa", arm="candidate")

        with pytest.raises(NamespaceViolationError):
            fleet.write_state("s1", "key", "value", namespace=INCUMBENT_NAMESPACE)

    def test_incumbent_session_cannot_write_candidate_state(self) -> None:
        fleet, _ = self._wrapped_fleet()
        fleet.pin_session("s2", "sha256:aa", arm="incumbent")

        with pytest.raises(NamespaceViolationError):
            fleet.write_state("s2", "key", "value", namespace=CANDIDATE_NAMESPACE)

    def test_arm_matched_writes_pass_through(self) -> None:
        fleet, _ = self._wrapped_fleet()
        fleet.pin_session("s3", "sha256:aa", arm="candidate")
        fleet.pin_session("s4", "sha256:bb", arm="incumbent")

        fleet.write_state("s3", "key", "value", namespace=CANDIDATE_NAMESPACE)
        fleet.write_state("s4", "key", "value", namespace=INCUMBENT_NAMESPACE)

    def test_unknown_session_is_refused(self) -> None:
        fleet, _ = self._wrapped_fleet()

        with pytest.raises(UnknownSessionError):
            fleet.write_state("never-pinned", "key", "value", namespace=CANDIDATE_NAMESPACE)
