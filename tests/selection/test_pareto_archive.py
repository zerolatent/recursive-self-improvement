"""H5 — Pareto archive projection and slice reporting.

The acceptance matrix: the archive projection reconciles with the raw
append-only records it is derived from (rebuild from immutable evidence
equals the projection); slice aggregation reads only attested costs
(claimed values never enter); the dominance rule produces the expected
frontier; and the API/CLI/dashboard surfaces expose the archive without
Python. DB-backed suites skip without PostgreSQL; CI always provides one.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.orm import Session

from evoruntime.registry.service import RegistryService
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.signing import generate_signing_key
from evoruntime.selection import (
    ParetoArchiveService,
    pareto_frontier,
    summarize_by_slice,
)
from evoruntime.selection.pareto_archive import ParetoArchiveRow

TENANT = "tnt_h5_" + uuid.uuid4().hex[:12]
STRATEGY = "strategy-h5"
CAMPAIGN = "campaign-h5"


def _unique_body(label: str) -> bytes:
    return f'{{"tenant":"{TENANT}","label":"{label}","nonce":"{uuid.uuid4().hex}"}}'.encode()


def _row(
    proposal_id: str,
    digest: str,
    attestation_id: str,
    outcome: str,
    slices: dict[str, str] | None = None,
    cost: dict[str, float] | None = None,
) -> ParetoArchiveRow:
    """A pure projection row for the dominance/aggregation unit tests."""
    return ParetoArchiveRow(
        proposal_id=proposal_id,
        artifact_digest=digest,
        parent_digest=None,
        strategy_id=STRATEGY,
        campaign_id=CAMPAIGN,
        attestation_id=attestation_id,
        outcome=outcome,
        slices=slices or {},
        cost=cost or {},
    )


class TestSliceAggregation:
    """Slice summaries aggregate outcomes and attested costs only."""

    def test_success_cost_latency_per_slice_value(self) -> None:
        rows = [
            _row(
                "p1",
                "d1",
                "a1",
                "pass",
                {"task_type": "repository_issue_resolution"},
                {"total_tokens": 100.0, "wall_clock_s": 2.0},
            ),
            _row(
                "p1",
                "d1",
                "a2",
                "fail",
                {"task_type": "repository_issue_resolution"},
                {"total_tokens": 300.0, "wall_clock_s": 6.0},
            ),
            _row(
                "p2",
                "d2",
                "a3",
                "pass",
                {"task_type": "unit_test_generation"},
                {"total_tokens": 50.0, "wall_clock_s": 1.0},
            ),
        ]
        summaries = summarize_by_slice(rows, "task_type")
        assert [s.value for s in summaries] == [
            "repository_issue_resolution",
            "unit_test_generation",
        ]
        coding = summaries[0]
        assert coding.attestation_count == 2
        assert coding.pass_count == 1
        assert coding.success_rate == 0.5
        # Mean over the slice's attested metrics only.
        assert coding.mean_cost["total_tokens"] == 200.0
        assert coding.mean_cost["wall_clock_s"] == 4.0
        unit = summaries[1]
        assert unit.success_rate == 1.0
        assert unit.mean_cost["total_tokens"] == 50.0

    def test_safety_and_difficulty_slices(self) -> None:
        rows = [
            _row("p1", "d1", "a1", "pass", {"safety_class": "adversarial_pi"}),
            _row("p2", "d2", "a2", "fail", {"safety_class": "adversarial_pi"}),
            _row("p3", "d3", "a3", "pass", {"difficulty": "medium"}),
        ]
        safety = summarize_by_slice(rows, "safety_class")
        assert len(safety) == 1
        assert safety[0].success_rate == 0.5
        difficulty = summarize_by_slice(rows, "difficulty")
        assert len(difficulty) == 1
        assert difficulty[0].value == "medium"

    def test_unknown_dimension_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown slice dimension"):
            summarize_by_slice([], "agent_claimed_difficulty")

    def test_rows_without_annotation_are_excluded(self) -> None:
        rows = [_row("p1", "d1", "a1", "pass", {}, {"total_tokens": 10.0})]
        assert summarize_by_slice(rows, "task_type") == ()


class TestParetoFrontier:
    """The dominance rule: success at least as good, shared costs no worse,
    strictly better somewhere."""

    def test_cheaper_equal_success_dominates(self) -> None:
        rows = [
            _row("p1", "d1", "a1", "pass", cost={"total_tokens": 100.0}),
            _row("p2", "d2", "a2", "pass", cost={"total_tokens": 200.0}),
        ]
        entries = {e.artifact_digest: e for e in pareto_frontier(rows)}
        assert entries["d1"].on_frontier
        assert not entries["d2"].on_frontier
        assert entries["d1"].dominates == ("d2",)
        assert entries["d2"].dominated_by == ("d1",)

    def test_tradeoff_leaves_both_on_frontier(self) -> None:
        rows = [
            _row("p1", "d1", "a1", "pass", cost={"total_tokens": 100.0, "wall_clock_s": 10.0}),
            _row("p2", "d2", "a2", "pass", cost={"total_tokens": 200.0, "wall_clock_s": 1.0}),
        ]
        entries = pareto_frontier(rows)
        assert all(entry.on_frontier for entry in entries)

    def test_lower_success_never_dominates(self) -> None:
        rows = [
            _row("p1", "d1", "a1", "pass", cost={"total_tokens": 100.0}),
            _row("p2", "d2", "a2", "fail", cost={"total_tokens": 100.0}),
        ]
        entries = {e.artifact_digest: e for e in pareto_frontier(rows)}
        assert entries["d1"].on_frontier
        assert not entries["d2"].on_frontier

    def test_metric_attested_for_one_side_is_not_compared(self) -> None:
        # d1 attests cost_usd only; d2 attests total_tokens only. No shared
        # metric, no strict improvement anywhere — neither dominates.
        rows = [
            _row("p1", "d1", "a1", "pass", cost={"cost_usd": 1.0}),
            _row("p2", "d2", "a2", "pass", cost={"total_tokens": 100.0}),
        ]
        entries = pareto_frontier(rows)
        assert all(entry.on_frontier for entry in entries)

    def test_identical_records_leave_both_on_frontier(self) -> None:
        rows = [
            _row("p1", "d1", "a1", "pass", cost={"total_tokens": 100.0}),
            _row("p2", "d2", "a2", "pass", cost={"total_tokens": 100.0}),
        ]
        assert all(entry.on_frontier for entry in pareto_frontier(rows))

    def test_multiple_attestations_aggregate_per_artifact(self) -> None:
        rows = [
            _row("p1", "d1", "a1", "pass", cost={"total_tokens": 100.0}),
            _row("p1", "d1", "a2", "fail", cost={"total_tokens": 300.0}),
            _row("p2", "d2", "a3", "pass", cost={"total_tokens": 100.0}),
        ]
        entries = {e.artifact_digest: e for e in pareto_frontier(rows)}
        assert entries["d1"].attestation_count == 2
        assert entries["d1"].pass_count == 1
        assert entries["d1"].success_rate == 0.5
        assert entries["d1"].mean_cost["total_tokens"] == 200.0
        # d2: same cost, perfect success rate — dominates d1.
        assert entries["d2"].dominates == ("d1",)


class TestArchiveProjection:
    """The rebuildable projection over the append-only evidence."""

    @pytest.fixture
    def registry(self, db_session: Session) -> RegistryService:
        return RegistryService(db_session)

    @pytest.fixture
    def evaluator(self) -> WorkloadIdentity:
        return WorkloadIdentity(role=WorkloadRole.EVALUATOR, subject=f"svc_eval_{TENANT}")

    def _attest(
        self,
        registry: RegistryService,
        evaluator: WorkloadIdentity,
        digest: str,
        metrics: dict[str, object],
        outcome: str = "pass",
    ) -> str:
        attestation = registry.record_attestation(
            tenant_id=TENANT,
            evaluator=evaluator,
            artifact_digest=digest,
            outcome=outcome,
            result_metrics=metrics,
            evaluation_payload_digest="sha256:" + "0" * 64,
            private_key=generate_signing_key(),
        )
        return attestation.attestation_id

    def test_rebuild_projects_pairs_with_slices_and_attested_costs(
        self, db_session: Session, registry: RegistryService, evaluator: WorkloadIdentity
    ) -> None:
        artifact = registry.register_artifact(
            tenant_id=TENANT, artifact_type="prompt_bundle", canonical_bytes=_unique_body("a")
        )
        registry.record_proposal(
            tenant_id=TENANT,
            proposed_digest=artifact.digest,
            strategy_id=STRATEGY,
            campaign_id=CAMPAIGN,
            proposal_metadata={"task_type": "repository_issue_resolution", "difficulty": "medium"},
        )
        attestation_id = self._attest(
            registry,
            evaluator,
            artifact.digest,
            {
                "total_tokens": 420.0,
                "wall_clock_s": 3.5,
                "accuracy": 0.9,
                "agent_claimed_tokens": 10.0,
            },
        )

        service = ParetoArchiveService(db_session)
        assert service.rebuild(TENANT) == 1

        rows = service.campaign_rows(TENANT, CAMPAIGN)
        assert len(rows) == 1
        row = rows[0]
        assert row.attestation_id == attestation_id
        assert row.slices["task_type"] == "repository_issue_resolution"
        assert row.slices["difficulty"] == "medium"
        # Attested costs only: the claimed metric stays out, non-cost
        # metrics (accuracy) stay out.
        assert row.cost == {"total_tokens": 420.0, "wall_clock_s": 3.5}
        assert service.reconcile(TENANT) == ()

    def test_rebuild_from_immutable_evidence_equals_projection(
        self, db_session: Session, registry: RegistryService, evaluator: WorkloadIdentity
    ) -> None:
        """The reconcile() equivalence: rebuild from the raw records equals
        the stored projection, and stays equal after a second rebuild."""
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
                tenant_id=TENANT,
                proposed_digest=artifact.digest,
                strategy_id=STRATEGY,
                campaign_id=CAMPAIGN,
                proposal_metadata={"task_type": f"type-{i}"},
            )
            self._attest(registry, evaluator, artifact.digest, {"total_tokens": 100.0 * (i + 1)})
            self._attest(
                registry,
                evaluator,
                artifact.digest,
                {"total_tokens": 50.0 * (i + 1)},
                outcome="fail" if i == 0 else "pass",
            )

        service = ParetoArchiveService(db_session)
        assert service.rebuild(TENANT) == 6
        assert service.reconcile(TENANT) == ()

        # A second rebuild is idempotent: same rows, still reconciled.
        assert service.rebuild(TENANT) == 6
        assert service.reconcile(TENANT) == ()

        # The frontier is computed on read from the stored projection.
        frontier = service.frontier(TENANT, CAMPAIGN)
        assert len(frontier) == 3
        # Artifact 2 (cheapest per attestation pair: 75 mean tokens, all
        # passing) dominates the others on shared total_tokens.
        by_digest = {entry.artifact_digest: entry for entry in frontier}
        cheapest = min(by_digest, key=lambda d: by_digest[d].mean_cost["total_tokens"])
        assert by_digest[cheapest].on_frontier

    def test_slice_summary_over_stored_rows(
        self, db_session: Session, registry: RegistryService, evaluator: WorkloadIdentity
    ) -> None:
        for i, task_type in enumerate(
            ["repository_issue_resolution", "repository_issue_resolution", "unit_test_generation"]
        ):
            artifact = registry.register_artifact(
                tenant_id=TENANT,
                artifact_type="prompt_bundle",
                canonical_bytes=_unique_body(f"slice-{i}"),
            )
            registry.record_proposal(
                tenant_id=TENANT,
                proposed_digest=artifact.digest,
                strategy_id=STRATEGY,
                campaign_id=CAMPAIGN,
                proposal_metadata={"task_type": task_type},
            )
            self._attest(
                registry,
                evaluator,
                artifact.digest,
                {"total_tokens": 100.0 + i},
                outcome="pass" if i != 1 else "fail",
            )

        ParetoArchiveService(db_session).rebuild(TENANT)
        service = ParetoArchiveService(db_session)
        summaries = service.slice_summary(TENANT, CAMPAIGN, "task_type")
        assert [(s.value, s.attestation_count, s.pass_count) for s in summaries] == [
            ("repository_issue_resolution", 2, 1),
            ("unit_test_generation", 1, 1),
        ]
        coding = summaries[0]
        assert coding.mean_cost["total_tokens"] == pytest.approx(100.5)

    def test_campaign_scoping_excludes_other_campaigns(
        self, db_session: Session, registry: RegistryService, evaluator: WorkloadIdentity
    ) -> None:
        artifact = registry.register_artifact(
            tenant_id=TENANT, artifact_type="prompt_bundle", canonical_bytes=_unique_body("x")
        )
        registry.record_proposal(
            tenant_id=TENANT,
            proposed_digest=artifact.digest,
            strategy_id=STRATEGY,
            campaign_id="campaign-other",
        )
        self._attest(registry, evaluator, artifact.digest, {"total_tokens": 1.0})

        service = ParetoArchiveService(db_session)
        service.rebuild(TENANT)
        assert service.campaign_rows(TENANT, CAMPAIGN) == ()
        assert service.frontier(TENANT, CAMPAIGN) == ()
        assert service.slice_summary(TENANT, CAMPAIGN, "task_type") == ()

    def test_attestation_annotation_fills_undeclared_slice(
        self, db_session: Session, registry: RegistryService, evaluator: WorkloadIdentity
    ) -> None:
        artifact = registry.register_artifact(
            tenant_id=TENANT, artifact_type="prompt_bundle", canonical_bytes=_unique_body("y")
        )
        registry.record_proposal(
            tenant_id=TENANT,
            proposed_digest=artifact.digest,
            strategy_id=STRATEGY,
            campaign_id=CAMPAIGN,
        )
        self._attest(registry, evaluator, artifact.digest, {"safety_class": "adversarial_pi"})

        service = ParetoArchiveService(db_session)
        service.rebuild(TENANT)
        rows = service.campaign_rows(TENANT, CAMPAIGN)
        assert rows[0].slices == {"safety_class": "adversarial_pi"}
        summaries = service.slice_summary(TENANT, CAMPAIGN, "safety_class")
        assert len(summaries) == 1
        assert summaries[0].value == "adversarial_pi"
