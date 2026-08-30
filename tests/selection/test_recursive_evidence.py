"""H11 evidence-assembly adapter tests: §12.6 evidence derived from *real*
paired ExperimentResults, not typed-in fixtures.

The adapter's contract is that the evidence a recursive claim cites is the
evidence the harness measured. These tests run actual scripted experiments
through `run_experiment` — the same path a campaign's evaluation round
takes — and assert the assembled evidence both matches what the runs
recorded and passes the real §12.6 gate when the runs support the claim.
"""

from __future__ import annotations

import pytest

from evoruntime.eval import (
    Arm,
    ArmKind,
    AttemptCost,
    EvalTask,
    Experiment,
    ExperimentResult,
    FrozenClock,
    InMemoryTaskSource,
    ScriptedAgent,
    ScriptedStep,
    run_experiment,
)
from evoruntime.eval.experiment import MIN_SEEDS
from evoruntime.selection import evaluate_recursive_claim
from evoruntime.selection.errors import EvidenceAssemblyError
from evoruntime.selection.recursive_evidence import (
    RecursiveClaimEvidenceAssembly,
    assemble_recursive_claim_evidence,
    canonical_evidence_dict,
    evidence_digest,
)

TASK_COUNT = 12
BOOTSTRAP_ITERATIONS = 200
"""Small enough to keep the suite fast, large enough for stable intervals."""

GEN1_PROMOTED = "sha256:" + "1" * 64
GEN2_PROMOTED = "sha256:" + "2" * 64


def _tasks() -> tuple[EvalTask, ...]:
    return tuple(
        EvalTask(
            id=f"tsk_{index:03d}",
            prompt=f"repair the failing test in module_{index}.py",
            metadata={"category": "localization" if index % 2 == 0 else "dependency_misuse"},
        )
        for index in range(TASK_COUNT)
    )


def _script(successes: int) -> dict[str, tuple[ScriptedStep, ...]]:
    """First `successes` tasks succeed, the rest fail — deterministic per task."""
    return {
        f"tsk_{index:03d}": (ScriptedStep(claimed_success=index < successes, cost=AttemptCost()),)
        for index in range(TASK_COUNT)
    }


def _generation1_result() -> ExperimentResult:
    """A simple three-arm generation-1 experiment result."""
    experiment = Experiment(
        name="gen1-campaign",
        dataset="ds_repo_repair_dev_v1",
        task_budget_profile="task-budget-v1",
        arms=[
            Arm(id="incumbent", kind=ArmKind.INCUMBENT),
            Arm(id="one-shot", kind=ArmKind.ONE_SHOT_CONTROL),
            Arm(id="strategy", kind=ArmKind.STRATEGY),
        ],
        seeds=MIN_SEEDS,
        bootstrap_iterations=BOOTSTRAP_ITERATIONS,
    )
    tasks = _tasks()
    return run_experiment(
        experiment,
        backends={
            "incumbent": ScriptedAgent(_script(5)),
            "one-shot": ScriptedAgent(_script(2)),
            "strategy": ScriptedAgent(_script(8)),
        },
        task_source=InMemoryTaskSource(tasks),
        clock_factory=FrozenClock,
    )


def _generation2_result() -> ExperimentResult:
    """The generation-2 experiment: strategy, one-shot, and fixed-editor arms.

    The strategy arm beats everything; the fixed-editor arm is the frozen
    optimizer the RI-3/RI-4 condition is judged against.
    """
    experiment = Experiment(
        name="gen2-campaign",
        dataset="ds_repo_repair_dev_v1",
        task_budget_profile="task-budget-v1",
        arms=[
            Arm(id="incumbent", kind=ArmKind.INCUMBENT),
            Arm(id="one-shot", kind=ArmKind.ONE_SHOT_CONTROL),
            Arm(id="strategy", kind=ArmKind.STRATEGY),
            Arm(
                id="fixed-editor",
                kind=ArmKind.FIXED_EDITOR,
                editor_ref="ghcr.io/evoruntime/strategist@sha256:" + "b" * 64,
            ),
        ],
        seeds=MIN_SEEDS,
        bootstrap_iterations=BOOTSTRAP_ITERATIONS,
    )
    tasks = _tasks()
    return run_experiment(
        experiment,
        backends={
            "incumbent": ScriptedAgent(_script(5)),
            "one-shot": ScriptedAgent(_script(2)),
            "strategy": ScriptedAgent(_script(11)),
            "fixed-editor": ScriptedAgent(_script(6)),
        },
        task_source=InMemoryTaskSource(tasks),
        clock_factory=FrozenClock,
    )


def _assemble(**overrides: object) -> RecursiveClaimEvidenceAssembly:
    kwargs: dict[str, object] = {
        "generation1_promoted_digest": GEN1_PROMOTED,
        "generation2_promoted_digest": GEN2_PROMOTED,
        "generation2_incumbent_digest": GEN1_PROMOTED,
        "fixed_editor_minimum_effect": 0.05,
    }
    kwargs.update(overrides)
    return assemble_recursive_claim_evidence(
        _generation1_result(),
        _generation2_result(),
        **kwargs,
    )


class TestAssemblyFromRealResults:
    def test_satisfied_evidence_passes_the_real_gate(self) -> None:
        """The acceptance shape: real runs -> assembled evidence -> gate pass."""
        assembly = _assemble()
        verdict = evaluate_recursive_claim(assembly.evidence)
        assert verdict.satisfied
        assert all(condition.passed for condition in verdict.conditions)

    def test_every_field_is_derived_not_asserted(self) -> None:
        assembly = _assemble()
        evidence = assembly.evidence
        assert evidence.successive_promoted_generations is True
        assert evidence.shared_error_budget is True
        assert evidence.causal_inheritance is True
        assert evidence.matched_compute_one_shot_advantage is True
        assert evidence.no_inheritance_control_arm is True
        assert evidence.fixed_editor_control_arm is True
        assert evidence.fixed_editor_advantage is not None
        assert evidence.fixed_editor_advantage > 0.05
        assert evidence.fixed_editor_holm_significant is True

    def test_causal_inheritance_requires_the_real_binding(self) -> None:
        """A generation-2 incumbent that is not the generation-1 promoted
        release breaks the inheritance link the claim rests on."""
        assembly = _assemble(generation2_incumbent_digest="sha256:" + "9" * 64)
        assert assembly.evidence.causal_inheritance is False
        assert not evaluate_recursive_claim(assembly.evidence).satisfied

    def test_repromoting_the_same_release_is_not_a_second_generation(self) -> None:
        assembly = _assemble(generation2_promoted_digest=GEN1_PROMOTED)
        assert assembly.evidence.successive_promoted_generations is False
        assert not evaluate_recursive_claim(assembly.evidence).satisfied

    def test_unpromoted_generation_fails_closed(self) -> None:
        assembly = _assemble(generation2_promoted_digest=None)
        assert assembly.evidence.successive_promoted_generations is False

    def test_unpinned_minimum_effect_defaults_to_failing(self) -> None:
        assembly = _assemble(fixed_editor_minimum_effect=None)
        assert assembly.evidence.fixed_editor_minimum_effect is None
        assert not evaluate_recursive_claim(assembly.evidence).satisfied

    def test_strategy_gain_provenance_rides_along(self) -> None:
        assembly = _assemble()
        assert assembly.strategy_gain.candidate_arm_id == "strategy"
        assert assembly.strategy_gain.baseline_arm_id == "incumbent"
        assert assembly.strategy_gain.is_improvement
        assert assembly.fixed_editor_comparison is not None
        assert assembly.fixed_editor_comparison.baseline_arm_id == "fixed-editor"
        assert assembly.one_shot_comparison is not None


class TestAssemblyFailClosed:
    def test_two_strategy_arms_are_refused(self) -> None:
        experiment = Experiment(
            name="ambiguous-strategy",
            dataset="ds_repo_repair_dev_v1",
            task_budget_profile="task-budget-v1",
            arms=[
                Arm(id="incumbent", kind=ArmKind.INCUMBENT),
                Arm(id="strategy-a", kind=ArmKind.STRATEGY),
                Arm(id="strategy-b", kind=ArmKind.STRATEGY),
            ],
            seeds=MIN_SEEDS,
            bootstrap_iterations=BOOTSTRAP_ITERATIONS,
        )
        tasks = _tasks()
        result = run_experiment(
            experiment,
            backends={
                "incumbent": ScriptedAgent(_script(5)),
                "strategy-a": ScriptedAgent(_script(8)),
                "strategy-b": ScriptedAgent(_script(9)),
            },
            task_source=InMemoryTaskSource(tasks),
            clock_factory=FrozenClock,
        )
        with pytest.raises(EvidenceAssemblyError, match="exactly one strategy arm"):
            assemble_recursive_claim_evidence(
                _generation1_result(),
                result,
                generation1_promoted_digest=GEN1_PROMOTED,
                generation2_promoted_digest=GEN2_PROMOTED,
                generation2_incumbent_digest=GEN1_PROMOTED,
                fixed_editor_minimum_effect=0.05,
            )

    def test_two_fixed_editor_arms_are_refused(self) -> None:
        """An ambiguous control fails closed — it does not get averaged."""
        experiment = Experiment(
            name="ambiguous-fixed-editor",
            dataset="ds_repo_repair_dev_v1",
            task_budget_profile="task-budget-v1",
            arms=[
                Arm(id="incumbent", kind=ArmKind.INCUMBENT),
                Arm(id="strategy", kind=ArmKind.STRATEGY),
                Arm(
                    id="fixed-editor-a",
                    kind=ArmKind.FIXED_EDITOR,
                    editor_ref="ghcr.io/evoruntime/strategist@sha256:" + "b" * 64,
                ),
                Arm(
                    id="fixed-editor-b",
                    kind=ArmKind.FIXED_EDITOR,
                    editor_ref="ghcr.io/evoruntime/strategist@sha256:" + "c" * 64,
                ),
            ],
            seeds=MIN_SEEDS,
            bootstrap_iterations=BOOTSTRAP_ITERATIONS,
        )
        tasks = _tasks()
        result = run_experiment(
            experiment,
            backends={
                "incumbent": ScriptedAgent(_script(5)),
                "strategy": ScriptedAgent(_script(11)),
                "fixed-editor-a": ScriptedAgent(_script(6)),
                "fixed-editor-b": ScriptedAgent(_script(4)),
            },
            task_source=InMemoryTaskSource(tasks),
            clock_factory=FrozenClock,
        )
        with pytest.raises(EvidenceAssemblyError, match="fixed-editor"):
            assemble_recursive_claim_evidence(
                _generation1_result(),
                result,
                generation1_promoted_digest=GEN1_PROMOTED,
                generation2_promoted_digest=GEN2_PROMOTED,
                generation2_incumbent_digest=GEN1_PROMOTED,
                fixed_editor_minimum_effect=0.05,
            )


class TestEvidenceCanonicalization:
    def test_digest_is_deterministic_and_discriminating(self) -> None:
        first = _assemble()
        second = _assemble()
        assert evidence_digest(first.evidence) == evidence_digest(second.evidence)
        assert evidence_digest(first.evidence).startswith("sha256:")

        broken = _assemble(generation2_incumbent_digest="sha256:" + "9" * 64)
        assert evidence_digest(first.evidence) != evidence_digest(broken.evidence)

    def test_canonical_dict_covers_every_gate_field(self) -> None:
        assembly = _assemble()
        canonical = canonical_evidence_dict(assembly.evidence)
        assert set(canonical) == {
            "successive_promoted_generations",
            "shared_error_budget",
            "causal_inheritance",
            "matched_compute_one_shot_advantage",
            "no_inheritance_control_arm",
            "fixed_editor_control_arm",
            "fixed_editor_advantage",
            "fixed_editor_minimum_effect",
            "fixed_editor_holm_significant",
        }

    def test_request_payload_carries_evidence_and_provenance(self) -> None:
        payload = _assemble().to_request_payload()
        assert set(payload) == {"evidence", "provenance"}
        assert payload["evidence"] == canonical_evidence_dict(_assemble().evidence)
        provenance = payload["provenance"]
        assert provenance["strategy_gain"]["candidate_arm_id"] == "strategy"
        assert provenance["fixed_editor_comparison"] is not None
        assert provenance["one_shot_comparison"] is not None
