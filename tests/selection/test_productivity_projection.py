"""FR-102 projection tests: the typed lineage-productivity projection
reconciles with the raw append-only records it is derived from.

Skips without a reachable PostgreSQL (like the other DB-backed suites);
CI always provides one."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.orm import Session

from evoruntime.db.models.registry import EvaluationAttestation, ProposalRecord
from evoruntime.registry.service import RegistryService
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.signing import generate_signing_key
from evoruntime.selection import (
    LineageProductivityService,
    project_productivity,
    summarize_productivity,
)

TENANT = "tnt_f9_" + uuid.uuid4().hex[:12]
STRATEGY = "strategy-f9"


def _unique_body(label: str) -> bytes:
    return f'{{"tenant":"{TENANT}","label":"{label}","nonce":"{uuid.uuid4().hex}"}}'.encode()


@pytest.fixture
def registry(db_session: Session) -> RegistryService:
    return RegistryService(db_session)


@pytest.fixture
def evaluator() -> WorkloadIdentity:
    return WorkloadIdentity(role=WorkloadRole.EVALUATOR, subject=f"svc_eval_{TENANT}")


def _attest(
    registry: RegistryService,
    evaluator: WorkloadIdentity,
    digest: str,
    metrics: dict[str, object],
) -> str:
    attestation = registry.record_attestation(
        tenant_id=TENANT,
        evaluator=evaluator,
        artifact_digest=digest,
        outcome="pass",
        result_metrics=metrics,
        evaluation_payload_digest="sha256:" + "0" * 64,
        private_key=generate_signing_key(),
    )
    return attestation.attestation_id


class TestProjectionReconciliation:
    """The projection reconciles with the raw attestations + proposals."""

    def test_rebuild_projects_every_proposal_attestation_pair(
        self, db_session: Session, registry: RegistryService, evaluator: WorkloadIdentity
    ) -> None:
        parent = registry.register_artifact(
            tenant_id=TENANT, artifact_type="prompt_bundle", canonical_bytes=_unique_body("parent")
        )
        child = registry.register_artifact(
            tenant_id=TENANT, artifact_type="prompt_bundle", canonical_bytes=_unique_body("child")
        )
        proposal = registry.record_proposal(
            tenant_id=TENANT,
            proposed_digest=child.digest,
            parent_digest=parent.digest,
            strategy_id=STRATEGY,
            campaign_id="campaign-f9",
        )
        attestation_id = _attest(
            registry,
            evaluator,
            child.digest,
            {"total_tokens": 420.0, "cost_usd": 0.13, "accuracy": 0.9},
        )

        service = LineageProductivityService(db_session)
        assert service.rebuild(TENANT) == 1

        rows = service.rows(TENANT)
        assert len(rows) == 1
        row = rows[0]
        assert row.proposal_id == proposal.proposal_id
        assert row.attestation_id == attestation_id
        assert row.artifact_digest == child.digest
        assert row.parent_digest == parent.digest
        assert row.outcome == "pass"
        # Typed cost columns carry the attested values; non-cost metrics
        # (accuracy) and unattested cost metrics stay out.
        assert row.total_tokens == 420.0
        assert row.cost_usd == 0.13
        assert row.tokens is None
        assert service.reconcile(TENANT) == ()

    def test_projection_reconciles_with_raw_attestations_after_rebuild(
        self, db_session: Session, registry: RegistryService, evaluator: WorkloadIdentity
    ) -> None:
        artifacts = [
            registry.register_artifact(
                tenant_id=TENANT,
                artifact_type="prompt_bundle",
                canonical_bytes=_unique_body(f"artifact-{i}"),
            )
            for i in range(3)
        ]
        for i, artifact in enumerate(artifacts):
            registry.record_proposal(
                tenant_id=TENANT, proposed_digest=artifact.digest, strategy_id=STRATEGY
            )
            _attest(registry, evaluator, artifact.digest, {"total_tokens": 100.0 * (i + 1)})
            _attest(registry, evaluator, artifact.digest, {"total_tokens": 50.0 * (i + 1)})

        service = LineageProductivityService(db_session)
        assert service.rebuild(TENANT) == 6
        assert service.reconcile(TENANT) == ()

        # Rebuild is idempotent: a second pass replaces, not duplicates.
        assert service.rebuild(TENANT) == 6
        assert len(service.rows(TENANT)) == 6
        assert service.reconcile(TENANT) == ()

    def test_reconcile_detects_drift_between_projection_and_evidence(
        self, db_session: Session, registry: RegistryService, evaluator: WorkloadIdentity
    ) -> None:
        artifact = registry.register_artifact(
            tenant_id=TENANT, artifact_type="prompt_bundle", canonical_bytes=_unique_body("drift")
        )
        registry.record_proposal(
            tenant_id=TENANT, proposed_digest=artifact.digest, strategy_id=STRATEGY
        )
        _attest(registry, evaluator, artifact.digest, {"total_tokens": 100.0})

        service = LineageProductivityService(db_session)
        service.rebuild(TENANT)
        assert service.reconcile(TENANT) == ()

        # Tamper with the projection (allowed — it is not append-only) and
        # the reconciliation check must catch the drift against the raw
        # attestation.
        row = service.rows(TENANT)[0]
        row.total_tokens = 1.0
        db_session.flush()
        diffs = service.reconcile(TENANT)
        assert len(diffs) == 1
        assert "total_tokens stored 1.0 != attested 100.0" in diffs[0]

    def test_pure_builder_matches_stored_rows(
        self, db_session: Session, registry: RegistryService, evaluator: WorkloadIdentity
    ) -> None:
        artifact = registry.register_artifact(
            tenant_id=TENANT, artifact_type="prompt_bundle", canonical_bytes=_unique_body("pure")
        )
        registry.record_proposal(
            tenant_id=TENANT, proposed_digest=artifact.digest, strategy_id=STRATEGY
        )
        _attest(registry, evaluator, artifact.digest, {"wall_clock_s": 12.5})

        proposals = db_session.query(ProposalRecord).filter_by(tenant_id=TENANT).all()
        attestations = db_session.query(EvaluationAttestation).filter_by(tenant_id=TENANT).all()
        projected = project_productivity(proposals, attestations)

        service = LineageProductivityService(db_session)
        service.rebuild(TENANT)
        stored = service.rows(TENANT)
        assert len(projected) == len(stored) == 1
        assert projected[0].cost["wall_clock_s"] == stored[0].wall_clock_s == 12.5


class TestAggregationSurface:
    """The aggregation surface: per-artifact mean attested costs."""

    def test_summary_aggregates_mean_costs_per_artifact(
        self, db_session: Session, registry: RegistryService, evaluator: WorkloadIdentity
    ) -> None:
        first = registry.register_artifact(
            tenant_id=TENANT, artifact_type="prompt_bundle", canonical_bytes=_unique_body("agg-1")
        )
        second = registry.register_artifact(
            tenant_id=TENANT, artifact_type="prompt_bundle", canonical_bytes=_unique_body("agg-2")
        )
        registry.record_proposal(
            tenant_id=TENANT, proposed_digest=first.digest, strategy_id=STRATEGY
        )
        registry.record_proposal(
            tenant_id=TENANT, proposed_digest=second.digest, strategy_id=STRATEGY
        )
        _attest(registry, evaluator, first.digest, {"total_tokens": 100.0})
        _attest(registry, evaluator, first.digest, {"total_tokens": 300.0})
        _attest(registry, evaluator, second.digest, {"total_tokens": 50.0})

        service = LineageProductivityService(db_session)
        service.rebuild(TENANT)
        summaries = {s.artifact_digest: s for s in service.summary(TENANT)}

        assert summaries[first.digest].attestation_count == 2
        assert summaries[first.digest].proposal_count == 1
        assert summaries[first.digest].mean_cost["total_tokens"] == 200.0
        assert summaries[second.digest].mean_cost["total_tokens"] == 50.0

    def test_pure_summarizer_agrees_with_the_service_surface(
        self, db_session: Session, registry: RegistryService, evaluator: WorkloadIdentity
    ) -> None:
        artifact = registry.register_artifact(
            tenant_id=TENANT,
            artifact_type="prompt_bundle",
            canonical_bytes=_unique_body("pure-agg"),
        )
        registry.record_proposal(
            tenant_id=TENANT, proposed_digest=artifact.digest, strategy_id=STRATEGY
        )
        _attest(registry, evaluator, artifact.digest, {"cost_usd": 1.0})
        _attest(registry, evaluator, artifact.digest, {"cost_usd": 3.0})

        service = LineageProductivityService(db_session)
        service.rebuild(TENANT)
        from_summary = service.summary(TENANT)
        assert len(from_summary) == 1
        assert from_summary[0].mean_cost["cost_usd"] == 2.0

        # The pure summarizer over the pure projection of the raw records
        # produces the same aggregation as the service surface.
        proposals = db_session.query(ProposalRecord).filter_by(tenant_id=TENANT).all()
        attestations = db_session.query(EvaluationAttestation).filter_by(tenant_id=TENANT).all()
        pure = summarize_productivity(project_productivity(proposals, attestations))
        assert len(pure) == 1
        assert pure[0].mean_cost["cost_usd"] == 2.0
        assert pure[0].attestation_count == from_summary[0].attestation_count


class TestProjectionIsRebuildable:
    """The projection is derived, not append-only — the D4 core stays
    untouched."""

    def test_projection_table_has_no_mutation_trigger(
        self, db_session: Session, registry: RegistryService, evaluator: WorkloadIdentity
    ) -> None:
        artifact = registry.register_artifact(
            tenant_id=TENANT, artifact_type="prompt_bundle", canonical_bytes=_unique_body("mut")
        )
        registry.record_proposal(
            tenant_id=TENANT, proposed_digest=artifact.digest, strategy_id=STRATEGY
        )
        _attest(registry, evaluator, artifact.digest, {"total_tokens": 10.0})

        service = LineageProductivityService(db_session)
        service.rebuild(TENANT)

        # Unlike the D4 core, editing a projection row succeeds — and a
        # rebuild restores it from the evidence.
        row = service.rows(TENANT)[0]
        row.total_tokens = 999.0
        db_session.flush()
        assert service.rebuild(TENANT) == 1
        assert service.rows(TENANT)[0].total_tokens == 10.0

    def test_d4_core_stays_append_only(
        self, db_session: Session, registry: RegistryService, evaluator: WorkloadIdentity
    ) -> None:
        artifact = registry.register_artifact(
            tenant_id=TENANT, artifact_type="prompt_bundle", canonical_bytes=_unique_body("d4")
        )
        registry.record_proposal(
            tenant_id=TENANT, proposed_digest=artifact.digest, strategy_id=STRATEGY
        )
        proposal = db_session.query(ProposalRecord).filter_by(tenant_id=TENANT).one()
        with pytest.raises(Exception, match="immutable|append-only"):
            proposal.strategy_id = "rewritten"
            db_session.flush()
        db_session.rollback()
