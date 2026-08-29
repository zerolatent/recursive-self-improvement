"""F7 promotion-integration tests (FR-103): per-family suite results feed
promotion condition 6 as real evaluated data, while the Phase 1 rule —
claimed-but-unevaluated scope fails — is preserved."""

from __future__ import annotations

from collections.abc import Mapping

from tests.eval.conftest import frozen_clock, make_tasks, three_arm_experiment

from evoruntime.datasets.partitions import PartitionKind
from evoruntime.eval import (
    EvalTask,
    InMemoryTaskSource,
    ScriptedAgent,
    ScriptedStep,
    SuiteFamily,
    TransferFamilyKind,
    TransferSuite,
    TransferSuiteResult,
    evaluated_transfer_scopes,
    run_transfer_suite,
)
from evoruntime.eval.errors import TaskSourceError
from evoruntime.selection import (
    CONDITION_TRANSFER_SCOPE,
    ConditionResult,
    PairedScores,
    PromotionEvidence,
    PromotionPolicyDocument,
    ResolvedRelease,
    evaluate_promotion,
)

N_PAIRS = 40
SEED = 20_260_827
ARM_IDS = ("incumbent", "retry", "one-shot")

FAMILIES = (
    SuiteFamily(
        name="cross-harness/alt-runner",
        kind=TransferFamilyKind.CROSS_HARNESS,
        experiment=three_arm_experiment(name="transfer-xharness", bootstrap_iterations=2_000),
        harness_id="alt-harness-v2",
        backend_id="model-a",
    ),
    SuiteFamily(
        name="cross-model/alt-llm",
        kind=TransferFamilyKind.CROSS_MODEL,
        experiment=three_arm_experiment(name="transfer-xmodel", bootstrap_iterations=2_000),
        harness_id="pytest-harness-v1",
        backend_id="model-b",
    ),
    SuiteFamily(
        name="adjacent-domain/infra",
        kind=TransferFamilyKind.ADJACENT_DOMAIN,
        experiment=three_arm_experiment(name="transfer-adjacent", bootstrap_iterations=2_000),
        harness_id="pytest-harness-v1",
        backend_id="model-a",
    ),
)

ALL_SCOPES = ("adjacent-domain/infra", "cross-harness/alt-runner", "cross-model/alt-llm")


class _FailingSource:
    """A task source that always fails — the stand-in for a broken dataset."""

    def load(self, dataset: str, partition: PartitionKind) -> tuple[EvalTask, ...]:
        raise TaskSourceError(f"dataset {dataset} unavailable")


def _run_suite(*, fail_families: tuple[str, ...] = ()) -> TransferSuiteResult:
    """Run the three-family suite, optionally breaking some families' sources."""
    suite = TransferSuite(name="transfer-2026-08", families=FAMILIES)
    backends: dict[str, Mapping[str, ScriptedAgent]] = {}
    sources: dict[str, object] = {}
    for family in FAMILIES:
        tasks = make_tasks()
        backends[family.name] = {
            arm_id: ScriptedAgent(
                {
                    task.id: (ScriptedStep(claimed_success=index < 8),)
                    for index, task in enumerate(tasks)
                }
            )
            for arm_id in ARM_IDS
        }
        if family.name in fail_families:
            sources[family.name] = _FailingSource()
        else:
            sources[family.name] = InMemoryTaskSource(tasks)
    return run_transfer_suite(
        suite,
        backends=backends,  # type: ignore[arg-type]
        task_sources=sources,  # type: ignore[arg-type]
        clock_factory=frozen_clock,
    )


def _heldout() -> PairedScores:
    """Deterministic paired scores: candidate = baseline + 0.15 per task."""
    baseline = tuple(0.5 + 0.01 * i for i in range(N_PAIRS))
    candidate = tuple(min(1.0, b + 0.15) for b in baseline)
    return PairedScores(
        task_ids=tuple(f"task-{i:03d}" for i in range(N_PAIRS)),
        baseline=baseline,
        candidate=candidate,
    )


def _evidence(**overrides: object) -> PromotionEvidence:
    """A candidate that passes every condition by default."""
    values: dict[str, object] = {
        "arm_id": "arm-candidate",
        "heldout": _heldout(),
        "success_gain": 0.15,
        "cost_reduction": 0.0,
        "p95_latency_regression": 0.02,
        "severity1_regressions": 0,
        "critical_failures": (),
        "budget_pass": True,
        "integrity_findings": (),
        "claimed_transfer_scope": (),
        "evaluated_transfer_scope": (),
        "bootstrap_iterations": 2_000,
        "bootstrap_seed": SEED,
    }
    values.update(overrides)
    return PromotionEvidence(**values)  # type: ignore[arg-type]


def _policy() -> PromotionPolicyDocument:
    return PromotionPolicyDocument(policy_id="mvp-gates-v1")


def _release() -> ResolvedRelease:
    return ResolvedRelease(artifact_classes=("prompt_bundle",))


def _condition(decision: object, name: str) -> ConditionResult:
    return next(c for c in decision.conditions if c.condition == name)  # type: ignore[attr-defined]


class TestTransferSuiteFeedsConditionSix:
    def test_evaluated_multi_family_results_satisfy_condition_six(self) -> None:
        """A candidate claiming all three scopes, with the suite's evaluated
        set as evidence, clears condition 6 — real multi-family data."""
        result = _run_suite()
        scopes = evaluated_transfer_scopes(result)
        assert scopes == ALL_SCOPES

        decision = evaluate_promotion(
            _policy(),
            _evidence(
                claimed_transfer_scope=scopes,
                evaluated_transfer_scope=scopes,
            ),
            release=_release(),
        )
        condition = _condition(decision, CONDITION_TRANSFER_SCOPE)
        assert condition.passed
        assert decision.eligible

    def test_claimed_but_unevaluated_scope_still_fails(self) -> None:
        """Phase 1 behavior preserved: a claimed scope no family evaluated
        fails condition 6 even when every other family ran."""
        result = _run_suite()
        scopes = evaluated_transfer_scopes(result)

        decision = evaluate_promotion(
            _policy(),
            _evidence(
                claimed_transfer_scope=(*scopes, "cross-model/untested-llm"),
                evaluated_transfer_scope=scopes,
            ),
            release=_release(),
        )
        condition = _condition(decision, CONDITION_TRANSFER_SCOPE)
        assert not condition.passed
        assert "cross-model/untested-llm" in condition.detail
        assert not decision.eligible

    def test_failed_family_scope_still_fails_condition_six(self) -> None:
        """A family that ran but failed contributes no scope: claiming its
        scope fails closed, exactly as in Phase 1."""
        result = _run_suite(fail_families=("cross-model/alt-llm",))
        scopes = evaluated_transfer_scopes(result)
        assert "cross-model/alt-llm" not in scopes

        decision = evaluate_promotion(
            _policy(),
            _evidence(
                claimed_transfer_scope=(*scopes, "cross-model/alt-llm"),
                evaluated_transfer_scope=scopes,
            ),
            release=_release(),
        )
        assert not _condition(decision, CONDITION_TRANSFER_SCOPE).passed
        assert not decision.eligible

    def test_all_families_failed_yields_no_coverage(self) -> None:
        """Every family failed: the evaluated set is empty and any claimed
        scope fails — the suite cannot manufacture coverage."""
        result = _run_suite(
            fail_families=(
                "cross-harness/alt-runner",
                "cross-model/alt-llm",
                "adjacent-domain/infra",
            )
        )
        assert evaluated_transfer_scopes(result) == ()

        decision = evaluate_promotion(
            _policy(),
            _evidence(
                claimed_transfer_scope=ALL_SCOPES,
                evaluated_transfer_scope=evaluated_transfer_scopes(result),
            ),
            release=_release(),
        )
        assert not _condition(decision, CONDITION_TRANSFER_SCOPE).passed
        assert not decision.eligible
