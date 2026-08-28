"""Per-stage alpha accounting (F6): cascade holdout reads through the D5 ledger.

Each cascade stage that touches the sealed holdout resolves through the
holdout service with a purpose that encodes its stage index and name
(`cascade.stage.<n>:<name>`), so every alpha spend is attributable to the
stage that spent it — including the early-exit case, where the ledger
shows exactly which stage failed and which stages never ran.
"""

from __future__ import annotations

from decimal import Decimal

from evoruntime.core.principal import Principal
from evoruntime.datasets.schemas import IssuedHoldoutHandle, PartitionSummary
from evoruntime.datasets.service import HoldoutService
from evoruntime.eval.cascade import (
    CascadeStage,
    EvaluatorCostClass,
    holdout_purpose,
)


def resolve_stage(
    holdout_service: HoldoutService,
    evaluator: Principal,
    handle: IssuedHoldoutHandle,
    stage: CascadeStage,
) -> None:
    """The per-stage holdout read: one ledgered resolution, priced in alpha."""
    holdout_service.resolve(
        evaluator, handle.handle_uri, purpose=holdout_purpose(stage.stage, stage.name)
    )


def make_stages() -> tuple[CascadeStage, ...]:
    return (
        CascadeStage(name="full-holdout", stage=2, cost_class=EvaluatorCostClass.EXPENSIVE),
        CascadeStage(name="test-suite", stage=1, cost_class=EvaluatorCostClass.STANDARD),
        CascadeStage(name="lint", stage=0, cost_class=EvaluatorCostClass.CHEAP),
    )


class TestPerStageAlphaLedger:
    def test_each_stage_spend_is_ledgered_under_its_own_purpose(
        self,
        holdout_service: HoldoutService,
        evaluator: Principal,
        issued_handle: IssuedHoldoutHandle,
    ) -> None:
        for stage in sorted(make_stages(), key=lambda s: s.stage):
            resolve_stage(holdout_service, evaluator, issued_handle, stage)

        entries = holdout_service.read_ledger(evaluator, issued_handle.handle_uri)
        assert [entry.purpose for entry in entries] == [
            "cascade.stage.0:lint",
            "cascade.stage.1:test-suite",
            "cascade.stage.2:full-holdout",
        ]
        assert all(entry.alpha_spent == Decimal("0.01") for entry in entries)

    def test_alpha_remaining_descends_per_stage_in_run_order(
        self,
        holdout_service: HoldoutService,
        evaluator: Principal,
        issued_handle: IssuedHoldoutHandle,
    ) -> None:
        for stage in sorted(make_stages(), key=lambda s: s.stage):
            resolve_stage(holdout_service, evaluator, issued_handle, stage)

        entries = holdout_service.read_ledger(evaluator, issued_handle.handle_uri)
        assert [entry.alpha_remaining for entry in entries] == [
            Decimal("0.03"),
            Decimal("0.02"),
            Decimal("0.01"),
        ]

    def test_early_exit_leaves_the_unrun_stages_alpha_untouched(
        self,
        holdout_service: HoldoutService,
        evaluator: Principal,
        issued_handle: IssuedHoldoutHandle,
    ) -> None:
        """Early exit at stage 0: only the cheap stage's alpha is spent."""
        stages = sorted(make_stages(), key=lambda s: s.stage)
        resolve_stage(holdout_service, evaluator, issued_handle, stages[0])
        # Stages 1 and 2 never run — no resolution, no ledger row, no spend.

        report = holdout_service.budget_report(evaluator, issued_handle.handle_uri)
        assert report.spent == Decimal("0.01")
        assert report.remaining == Decimal("0.03")
        assert report.queries_remaining == 3

        entries = holdout_service.read_ledger(evaluator, issued_handle.handle_uri)
        assert [entry.purpose for entry in entries] == ["cascade.stage.0:lint"]

    def test_stage_purposes_do_not_collide_across_reruns(
        self,
        holdout_service: HoldoutService,
        evaluator: Principal,
        issued_handle: IssuedHoldoutHandle,
        sealed_partition: PartitionSummary,
    ) -> None:
        """A rerun gets a fresh handle; each ledger shows one row per stage."""
        for stage in sorted(make_stages(), key=lambda s: s.stage):
            resolve_stage(holdout_service, evaluator, issued_handle, stage)

        rerun_handle = holdout_service.issue_handle(
            evaluator,
            partition_id=sealed_partition.id,
            owner="eval-team",
            alpha_budget_total=Decimal("0.04"),
            alpha_per_query=Decimal("0.01"),
            freshness_window_days=30,
            rotation_plan="rotate-quarterly",
            contamination_audit={"source": "github-issues-2026-q2", "contaminated": False},
        )
        for stage in sorted(make_stages(), key=lambda s: s.stage):
            resolve_stage(holdout_service, evaluator, rerun_handle, stage)

        expected = [
            "cascade.stage.0:lint",
            "cascade.stage.1:test-suite",
            "cascade.stage.2:full-holdout",
        ]
        first = holdout_service.read_ledger(evaluator, issued_handle.handle_uri)
        second = holdout_service.read_ledger(evaluator, rerun_handle.handle_uri)
        assert [e.purpose for e in first] == expected
        assert [e.purpose for e in second] == expected
