"""Preregistration: what an experiment must fix before anything runs.

An experiment whose alpha, arms, or partition could be chosen after
seeing the deltas has no error rate to report. These tests hold the
construction-time refusals in place — including the one that matters most
for the trust boundary, that no experiment can name the sealed holdout.
"""

from __future__ import annotations

import pytest

from evoruntime.datasets.partitions import PartitionKind
from evoruntime.eval import (
    TASK_BUDGET_V1,
    Arm,
    ArmKind,
    Experiment,
    ExperimentDefinitionError,
    MultiplicityMethod,
    UnknownBudgetProfileError,
    derive_seed,
)
from evoruntime.eval.experiment import MIN_SEEDS
from tests.eval.conftest import three_arm_experiment


class TestFixedEditorArm:
    """G4: the fixed-editor arm — the incumbent scaffold evaluated under
    the frozen editor — with ABLATION-style editor_ref-only validation."""

    def test_fixed_editor_arm_constructs_with_an_editor_ref(self) -> None:
        arm = Arm.fixed_editor("fixed-editor", "evo-prompt-strategist@gen-0")
        assert arm.kind is ArmKind.FIXED_EDITOR
        assert arm.editor_reference == "evo-prompt-strategist@gen-0"

    def test_fixed_editor_arm_without_an_editor_ref_is_refused(self) -> None:
        with pytest.raises(ExperimentDefinitionError, match="editor_ref"):
            Arm(id="fixed-editor", kind=ArmKind.FIXED_EDITOR)

    def test_editor_ref_on_any_other_kind_is_refused(self) -> None:
        for kind in (
            ArmKind.INCUMBENT,
            ArmKind.RETRY_SELF_CONSISTENCY,
            ArmKind.ONE_SHOT_CONTROL,
            ArmKind.STRATEGY,
        ):
            with pytest.raises(ExperimentDefinitionError, match="editor_ref"):
                Arm(id="stray", kind=kind, editor_ref="evo-prompt-strategist@gen-0")
        # An ABLATION arm must satisfy its own component_id rule before the
        # editor_ref rule can fire, so it gets a valid component id here.
        with pytest.raises(ExperimentDefinitionError, match="editor_ref"):
            Arm(
                id="stray",
                kind=ArmKind.ABLATION,
                component_id="retriever",
                editor_ref="evo-prompt-strategist@gen-0",
            )

    def test_editor_reference_property_refuses_non_fixed_editor_arms(self) -> None:
        arm = Arm(id="incumbent", kind=ArmKind.INCUMBENT)
        with pytest.raises(ExperimentDefinitionError, match="fixed-editor"):
            _ = arm.editor_reference


def test_the_spec_sample_constructs() -> None:
    """The spec's Experiment sample is the contract; it must build as written."""
    exp = Experiment(
        name="python-repair-baseline-2026-08",
        dataset="ds_repo_repair_dev_v1",
        task_budget_profile="task-budget-v1",
        arms=[
            Arm(id="incumbent", kind=ArmKind.INCUMBENT),
            Arm(id="retry", kind=ArmKind.RETRY_SELF_CONSISTENCY, max_attempts=3),
            Arm(id="one-shot", kind=ArmKind.ONE_SHOT_CONTROL),
        ],
        seeds=3,
    )

    assert exp.incumbent.id == "incumbent"
    assert [arm.id for arm in exp.candidate_arms] == ["retry", "one-shot"]
    assert exp.budget is TASK_BUDGET_V1
    assert exp.partition is PartitionKind.DEV


def test_holdout_partition_is_refused_at_construction() -> None:
    """The trust boundary, enforced before a single task loads.

    Nothing downstream can leak holdout content if no experiment can name
    it: this is the first of the two refusals (the task source is the
    second), and it fires without touching storage at all.
    """
    with pytest.raises(ExperimentDefinitionError) as excinfo:
        three_arm_experiment(partition=PartitionKind.HOLDOUT)

    message = str(excinfo.value)
    assert "holdout" in message
    assert "dev" in message


@pytest.mark.parametrize(
    "kind",
    [
        PartitionKind.DISCOVERY,
        PartitionKind.DEV,
        PartitionKind.SELECTION,
        PartitionKind.ADVERSARIAL,
        PartitionKind.CANARY,
    ],
)
def test_unsealed_partitions_are_allowed(kind: PartitionKind) -> None:
    """Only sealed kinds are refused; adversarial fixtures stay runnable."""
    assert three_arm_experiment(partition=kind).partition is kind


def test_exactly_one_incumbent_is_required() -> None:
    """Paired statistics need a baseline; zero or two is not a comparison."""
    with pytest.raises(ExperimentDefinitionError, match="exactly one incumbent"):
        Experiment(
            name="no-baseline",
            dataset="ds",
            task_budget_profile="task-budget-v1",
            arms=[Arm(id="one-shot", kind=ArmKind.ONE_SHOT_CONTROL)],
        )

    with pytest.raises(ExperimentDefinitionError, match="exactly one incumbent"):
        Experiment(
            name="two-baselines",
            dataset="ds",
            task_budget_profile="task-budget-v1",
            arms=[
                Arm(id="a", kind=ArmKind.INCUMBENT),
                Arm(id="b", kind=ArmKind.INCUMBENT),
            ],
        )


def test_duplicate_arm_ids_are_rejected() -> None:
    """Two arms sharing an id would silently merge in every result mapping."""
    with pytest.raises(ExperimentDefinitionError, match="duplicate arm ids: dup"):
        Experiment(
            name="dupes",
            dataset="ds",
            task_budget_profile="task-budget-v1",
            arms=[
                Arm(id="dup", kind=ArmKind.INCUMBENT),
                Arm(id="dup", kind=ArmKind.ONE_SHOT_CONTROL),
            ],
        )


def test_seeds_below_the_prd_floor_are_rejected() -> None:
    """PRD §12.5 sets three replicates as the floor for reporting variance."""
    with pytest.raises(ExperimentDefinitionError, match="seeds must be at least 3"):
        three_arm_experiment(seeds=MIN_SEEDS - 1)

    assert three_arm_experiment(seeds=MIN_SEEDS).seeds == MIN_SEEDS


def test_unknown_budget_profile_fails_at_construction_not_at_run_time() -> None:
    """Finding out mid-campaign that the profile name was a typo is too late."""
    with pytest.raises(UnknownBudgetProfileError):
        three_arm_experiment(task_budget_profile="task-budget-v9")


@pytest.mark.parametrize("alpha", [0.0, 1.0, -0.1, 1.5])
def test_alpha_must_be_a_probability(alpha: float) -> None:
    """An alpha outside (0, 1) is not an error rate."""
    with pytest.raises(ExperimentDefinitionError, match="alpha"):
        three_arm_experiment(alpha=alpha)


def test_bootstrap_iterations_have_a_floor() -> None:
    """Too few resamples make the interval's endpoints noise."""
    with pytest.raises(ExperimentDefinitionError, match="bootstrap_iterations"):
        three_arm_experiment(bootstrap_iterations=10)


def test_only_a_retry_arm_may_retry() -> None:
    """`max_attempts` on a control arm would quietly redefine the control."""
    with pytest.raises(ExperimentDefinitionError, match="may retry"):
        Arm(id="one-shot", kind=ArmKind.ONE_SHOT_CONTROL, max_attempts=3)

    assert Arm.retry("retry").max_attempts == 3


def test_arm_ids_must_be_non_empty() -> None:
    """An unnamed arm cannot be reported, paired, or wired to a backend."""
    with pytest.raises(ExperimentDefinitionError, match="arm id"):
        Arm(id="", kind=ArmKind.INCUMBENT)


def test_experiment_defaults_match_the_prd_shape() -> None:
    """Defaults are part of the contract: dev partition, Bonferroni, seed floor."""
    exp = three_arm_experiment()

    assert exp.seeds == MIN_SEEDS
    assert exp.alpha == pytest.approx(0.05)
    assert exp.multiplicity is MultiplicityMethod.BONFERRONI
    assert exp.partition is PartitionKind.DEV


def test_arms_are_frozen_into_a_tuple() -> None:
    """A mutable arm list handed in by a caller could change mid-campaign."""
    arms = [Arm(id="incumbent", kind=ArmKind.INCUMBENT)]
    exp = Experiment(name="freeze", dataset="ds", task_budget_profile="task-budget-v1", arms=arms)
    arms.append(Arm(id="sneaky", kind=ArmKind.ONE_SHOT_CONTROL))

    assert isinstance(exp.arms, tuple)
    assert [arm.id for arm in exp.arms] == ["incumbent"]


class TestDeriveSeed:
    """Common random numbers: the seed depends on the cell, never on the arm."""

    def test_is_deterministic_across_calls(self) -> None:
        """A seed that changed between processes would not be a seed."""
        assert derive_seed("exp", "tsk_001", 0) == derive_seed("exp", "tsk_001", 0)

    def test_differs_by_task_and_by_seed_index(self) -> None:
        """Every cell gets its own stream, or replicates would be copies."""
        seeds = {
            derive_seed("exp", "tsk_001", 0),
            derive_seed("exp", "tsk_002", 0),
            derive_seed("exp", "tsk_001", 1),
            derive_seed("exp2", "tsk_001", 0),
        }

        assert len(seeds) == 4

    def test_takes_no_arm_argument(self) -> None:
        """The arm is deliberately not an input — that is what couples the arms.

        Two arms facing the same task and seed draw from the same stream,
        so an identical pair of arms produces an exactly zero difference
        instead of two independent coin flips.
        """
        assert derive_seed.__code__.co_varnames[:3] == (
            "experiment_name",
            "task_id",
            "seed_index",
        )
        assert derive_seed.__code__.co_argcount == 3
