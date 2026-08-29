"""H11 §12.6 claim-issuance operator path tests.

The gate machinery (``evaluate_recursive_claim``, ``claim_label``,
``assert_label_allowed``) existed since G4; what H11 adds is the operator
path that *records* its decisions. These tests pin the two disciplines the
service enforces:

1. the gate decides and the operator records — a caller who submits
   evidence without a fixed-editor advantage never receives a
   recursive-improvement label, and
2. the refusal is a record, not just an exception — it lands in the
   append-only ``recursive_claim_decisions`` ledger before the error is
   raised, and the ledger's database trigger keeps it there.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session, sessionmaker

from evoruntime.api.claims import ClaimIssuanceService
from evoruntime.api.cli import main as cli_main
from evoruntime.api.errors import ClaimDecisionNotFoundError, ClaimRefusedError
from evoruntime.core.principal import Principal
from evoruntime.db.models.claims import RecursiveClaimDecision
from evoruntime.selection import (
    ARTIFACT_OPTIMIZATION_LABEL,
    RECURSIVE_IMPROVEMENT_LABEL,
    RecursiveClaimEvidence,
)
from evoruntime.server.app import create_app
from evoruntime.server.dependencies import get_claim_service, get_session_factory
from evoruntime.tenancy.environment import TenantEnvironment
from evoruntime.tenancy.policy import TenantPolicyDocument, TenantPolicyRegistry

GEN1_RELEASE = "sha256:" + "1" * 64
GEN2_RELEASE = "sha256:" + "2" * 64


def _evidence(**overrides: object) -> RecursiveClaimEvidence:
    values: dict[str, object] = {
        "successive_promoted_generations": True,
        "shared_error_budget": True,
        "causal_inheritance": True,
        "matched_compute_one_shot_advantage": True,
        "no_inheritance_control_arm": True,
        "fixed_editor_control_arm": True,
        "fixed_editor_advantage": 0.08,
        "fixed_editor_minimum_effect": 0.05,
        "fixed_editor_holm_significant": True,
    }
    values.update(overrides)
    return RecursiveClaimEvidence(**values)  # type: ignore[arg-type]


def _evidence_dict(evidence: RecursiveClaimEvidence) -> dict[str, Any]:
    """The wire form of an evidence object (a slots dataclass, no __dict__)."""
    return asdict(evidence)


def _weak_evidence() -> RecursiveClaimEvidence:
    """Everything satisfied except the fixed-editor advantage: 0.01 against
    a preregistered 0.05 minimum effect — the §12.6 RI-3/RI-4 refusal."""
    return _evidence(fixed_editor_advantage=0.01)


def _policy(
    tenant_id: str,
    *,
    environment: TenantEnvironment = TenantEnvironment.RESEARCH,
    recursive_claims_enabled: bool = True,
) -> TenantPolicyDocument:
    return TenantPolicyDocument(
        tenant_id=tenant_id,
        policy_id=f"pol_{uuid.uuid4().hex[:8]}",
        environment=environment,
        allowed_authority_tiers=(1, 2, 3, 4)
        if environment is TenantEnvironment.RESEARCH
        else (1, 2, 3),
        recursive_claims_enabled=recursive_claims_enabled,
    )


@pytest.fixture
def research_registry(tenant_id: str) -> TenantPolicyRegistry:
    return TenantPolicyRegistry([_policy(tenant_id)])


@pytest.fixture
def production_registry(tenant_id: str) -> TenantPolicyRegistry:
    return TenantPolicyRegistry([_policy(tenant_id, recursive_claims_enabled=False)])


@pytest.fixture
def claim_service(
    session_factory: sessionmaker[Session], research_registry: TenantPolicyRegistry
) -> ClaimIssuanceService:
    return ClaimIssuanceService(session_factory, tenant_policies=research_registry)


class TestIssuanceRecordsAppendOnly:
    def test_satisfied_evidence_issues_the_label(
        self, claim_service: ClaimIssuanceService, evaluator: Principal
    ) -> None:
        decision = claim_service.issue_claim_label(
            evaluator,
            evidence=_evidence(),
            campaign_id="cmp_gen2",
            generation1_release_digest=GEN1_RELEASE,
            generation2_release_digest=GEN2_RELEASE,
        )
        assert decision.issued is True
        assert decision.label == RECURSIVE_IMPROVEMENT_LABEL
        assert decision.verdict_satisfied is True
        assert decision.refusal_reason is None
        assert decision.campaign_id == "cmp_gen2"
        assert decision.generation1_release_digest == GEN1_RELEASE
        assert decision.generation2_release_digest == GEN2_RELEASE
        assert decision.evidence_digest.startswith("sha256:")
        assert decision.actor == evaluator.identity_id

    def test_issued_decision_is_retrievable(
        self, claim_service: ClaimIssuanceService, evaluator: Principal
    ) -> None:
        issued = claim_service.issue_claim_label(evaluator, evidence=_evidence())
        fetched = claim_service.get_claim_decision(evaluator, issued.decision_id)
        assert fetched == issued

    def test_list_returns_the_tenant_decisions_oldest_first(
        self, claim_service: ClaimIssuanceService, evaluator: Principal
    ) -> None:
        first = claim_service.issue_claim_label(evaluator, evidence=_evidence())
        second = claim_service.issue_claim_label(evaluator, evidence=_evidence())
        decisions = claim_service.list_claim_decisions(evaluator)
        assert [d.decision_id for d in decisions] == [first.decision_id, second.decision_id]


class TestRefusalWithoutFixedEditorAdvantage:
    def test_refusal_is_raised_with_the_recorded_decision_id(
        self, claim_service: ClaimIssuanceService, evaluator: Principal
    ) -> None:
        with pytest.raises(ClaimRefusedError) as refused:
            claim_service.issue_claim_label(evaluator, evidence=_weak_evidence())
        assert refused.value.decision_id
        assert refused.value.reason

    def test_refusal_lands_as_an_append_only_record(
        self, claim_service: ClaimIssuanceService, evaluator: Principal
    ) -> None:
        """The acceptance shape: the refusal is recorded, not just raised."""
        with pytest.raises(ClaimRefusedError) as refused:
            claim_service.issue_claim_label(evaluator, evidence=_weak_evidence())

        decision = claim_service.get_claim_decision(evaluator, refused.value.decision_id)
        assert decision.issued is False
        assert decision.verdict_satisfied is False
        # The honest label — never a recursive-improvement label the
        # evidence does not back.
        assert decision.label == ARTIFACT_OPTIMIZATION_LABEL
        assert decision.refusal_reason
        assert decision.evidence_digest.startswith("sha256:")

    def test_refusal_is_recorded_for_a_production_tenant(
        self,
        session_factory: sessionmaker[Session],
        production_registry: TenantPolicyRegistry,
        evaluator: Principal,
    ) -> None:
        service = ClaimIssuanceService(session_factory, tenant_policies=production_registry)
        with pytest.raises(ClaimRefusedError) as refused:
            service.issue_claim_label(evaluator, evidence=_evidence())
        decision = service.get_claim_decision(evaluator, refused.value.decision_id)
        assert decision.issued is False
        assert decision.verdict_satisfied is True  # the gate passed; the tenant refused

    def test_refusal_is_recorded_for_an_unmapped_tenant(
        self, session_factory: sessionmaker[Session], evaluator: Principal
    ) -> None:
        """An empty registry fails closed: every tenant is production."""
        service = ClaimIssuanceService(session_factory)
        with pytest.raises(ClaimRefusedError) as refused:
            service.issue_claim_label(evaluator, evidence=_evidence())
        decision = service.get_claim_decision(evaluator, refused.value.decision_id)
        assert decision.issued is False

    def test_decisions_are_tenant_scoped(
        self,
        claim_service: ClaimIssuanceService,
        evaluator: Principal,
        foreign_evaluator: Principal,
    ) -> None:
        decision = claim_service.issue_claim_label(evaluator, evidence=_evidence())
        with pytest.raises(ClaimDecisionNotFoundError):
            claim_service.get_claim_decision(foreign_evaluator, decision.decision_id)
        assert claim_service.list_claim_decisions(foreign_evaluator) == []


class TestLedgerIsAppendOnly:
    """The migration's trigger, not the service, is the last line."""

    def test_update_is_rejected(
        self,
        claim_service: ClaimIssuanceService,
        evaluator: Principal,
        db_session: Session,
    ) -> None:
        decision = claim_service.issue_claim_label(evaluator, evidence=_evidence())
        db_session.commit()
        with pytest.raises(ProgrammingError, match="append-only table"):
            db_session.execute(
                text("UPDATE recursive_claim_decisions SET label = 'rewritten' WHERE id = :id"),
                {"id": decision.decision_id},
            )
        db_session.rollback()

    def test_delete_is_rejected(
        self,
        claim_service: ClaimIssuanceService,
        evaluator: Principal,
        db_session: Session,
    ) -> None:
        with pytest.raises(ClaimRefusedError) as refused:
            claim_service.issue_claim_label(evaluator, evidence=_weak_evidence())
        db_session.commit()
        with pytest.raises(ProgrammingError, match="append-only table"):
            db_session.execute(
                text("DELETE FROM recursive_claim_decisions WHERE id = :id"),
                {"id": refused.value.decision_id},
            )
        db_session.rollback()

    def test_refusal_row_persists_after_the_exception(
        self,
        session_factory: sessionmaker[Session],
        research_registry: TenantPolicyRegistry,
        evaluator: Principal,
    ) -> None:
        """The refusal is committed before the raise — a fresh session
        (not the raising one) can still read it."""
        service = ClaimIssuanceService(session_factory, tenant_policies=research_registry)
        with pytest.raises(ClaimRefusedError) as refused:
            service.issue_claim_label(evaluator, evidence=_weak_evidence())
        with session_factory() as fresh:
            row = fresh.get(RecursiveClaimDecision, refused.value.decision_id)
            assert row is not None
            assert row.issued is False


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------


def _research_claims_client(
    session_factory: sessionmaker[Session], research_registry: TenantPolicyRegistry
) -> TestClient:
    app = create_app()
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    app.dependency_overrides[get_claim_service] = lambda: ClaimIssuanceService(
        session_factory, tenant_policies=research_registry
    )
    return TestClient(app)


class TestClaimsApi:
    def test_issue_returns_201_for_a_research_tenant(
        self,
        session_factory: sessionmaker[Session],
        research_registry: TenantPolicyRegistry,
        evaluator: Principal,
        auth_headers: Any,
    ) -> None:
        with _research_claims_client(session_factory, research_registry) as client:
            response = client.post(
                "/v1/claims/label",
                json=_evidence_dict(_evidence()),
                headers=auth_headers(evaluator),
            )
        assert response.status_code == 201
        body = response.json()
        assert body["issued"] is True
        assert body["label"] == RECURSIVE_IMPROVEMENT_LABEL

    def test_refusal_is_403_and_the_decision_is_retrievable(
        self,
        session_factory: sessionmaker[Session],
        research_registry: TenantPolicyRegistry,
        evaluator: Principal,
        auth_headers: Any,
    ) -> None:
        with _research_claims_client(session_factory, research_registry) as client:
            response = client.post(
                "/v1/claims/label",
                json=_evidence_dict(_weak_evidence()),
                headers=auth_headers(evaluator),
            )
            assert response.status_code == 403
            decision_id = response.json()["decision_id"]

            fetched = client.get(f"/v1/claims/{decision_id}", headers=auth_headers(evaluator))
        assert fetched.status_code == 200
        assert fetched.json()["issued"] is False
        assert fetched.json()["label"] == ARTIFACT_OPTIMIZATION_LABEL

    def test_decision_lookup_is_tenant_scoped(
        self,
        session_factory: sessionmaker[Session],
        research_registry: TenantPolicyRegistry,
        evaluator: Principal,
        foreign_evaluator: Principal,
        auth_headers: Any,
    ) -> None:
        with _research_claims_client(session_factory, research_registry) as client:
            created = client.post(
                "/v1/claims/label",
                json=_evidence_dict(_evidence()),
                headers=auth_headers(evaluator),
            )
            decision_id = created.json()["decision_id"]
            foreign = client.get(
                f"/v1/claims/{decision_id}", headers=auth_headers(foreign_evaluator)
            )
            listing = client.get("/v1/claims", headers=auth_headers(foreign_evaluator))
        assert foreign.status_code == 404
        assert listing.status_code == 200
        assert listing.json() == []


# ---------------------------------------------------------------------------
# CLI operator path
# ---------------------------------------------------------------------------


@pytest.fixture
def live_server(
    session_factory: sessionmaker[Session], research_registry: TenantPolicyRegistry
) -> Any:
    """The real app served by uvicorn on an ephemeral localhost port."""
    import threading
    import time

    import uvicorn

    app = create_app()
    app.dependency_overrides[get_session_factory] = lambda: session_factory
    app.dependency_overrides[get_claim_service] = lambda: ClaimIssuanceService(
        session_factory, tenant_policies=research_registry
    )
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    if not server.started:
        pytest.fail("uvicorn did not start within 10s")
    port = server.servers[0].sockets[0].getsockname()[1]
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        app.dependency_overrides.clear()


def _run_evo(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, Any]:
    exit_code = cli_main(list(args))
    out = capsys.readouterr().out
    return exit_code, json.loads(out) if out.strip() else None


class TestClaimsCli:
    def test_cli_issue_list_and_status_round_trip(
        self,
        live_server: str,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
        tenant_id: str,
    ) -> None:
        config = tmp_path / "evo-config.json"
        code, body = _run_evo(
            capsys,
            "init",
            "--url",
            live_server,
            "--identity",
            "svc_evaluator_1",
            "--role",
            "evaluator",
            "--tenant",
            tenant_id,
            "--config",
            str(config),
        )
        assert code == 0

        evidence_file = tmp_path / "evidence.json"
        evidence_file.write_text(json.dumps(_evidence_dict(_evidence())), encoding="utf-8")
        code, decision = _run_evo(
            capsys,
            "claim",
            "issue",
            "--evidence-file",
            str(evidence_file),
            "--campaign-id",
            "cmp_gen2",
            "--generation1-release-digest",
            GEN1_RELEASE,
            "--generation2-release-digest",
            GEN2_RELEASE,
            "--config",
            str(config),
        )
        assert code == 0
        assert decision["issued"] is True
        assert decision["label"] == RECURSIVE_IMPROVEMENT_LABEL

        code, listing = _run_evo(capsys, "claim", "list", "--config", str(config))
        assert code == 0
        assert [row["decision_id"] for row in listing] == [decision["decision_id"]]

        code, status = _run_evo(
            capsys,
            "claim",
            "status",
            "--decision-id",
            decision["decision_id"],
            "--config",
            str(config),
        )
        assert code == 0
        assert status == decision

    def test_cli_refusal_exits_nonzero_and_the_record_survives(
        self,
        live_server: str,
        capsys: pytest.CaptureFixture[str],
        tmp_path: Path,
        tenant_id: str,
    ) -> None:
        config = tmp_path / "evo-config.json"
        _run_evo(
            capsys,
            "init",
            "--url",
            live_server,
            "--identity",
            "svc_evaluator_1",
            "--role",
            "evaluator",
            "--tenant",
            tenant_id,
            "--config",
            str(config),
        )
        evidence_file = tmp_path / "weak-evidence.json"
        evidence_file.write_text(json.dumps(_evidence_dict(_weak_evidence())), encoding="utf-8")
        code = cli_main(
            [
                "claim",
                "issue",
                "--evidence-file",
                str(evidence_file),
                "--config",
                str(config),
            ]
        )
        assert code == 1
        capsys.readouterr()  # drain the error output

        # The refusal the operator saw as an error is on the ledger.
        code, listing = _run_evo(capsys, "claim", "list", "--config", str(config))
        assert code == 0
        assert len(listing) == 1
        assert listing[0]["issued"] is False
        assert listing[0]["label"] == ARTIFACT_OPTIMIZATION_LABEL
        assert listing[0]["refusal_reason"]
