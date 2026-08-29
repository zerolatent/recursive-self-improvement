"""Marginal ablations (Phase 2 F8, FR-101): each component's contribution.

The acceptance rows, each pinned by a test here:

*unregistered ablation rejected* — an ABLATION arm whose component is
outside the preregistered family (or named when no family exists) is a
construction error, at the harness level and again at the campaign-spec
level, because a family that could grow after seeing the deltas would not
be a preregistration.

*family-wide multiplicity control* — every ablation's paired bootstrap
runs under ONE Holm family: the per-comparison alpha splits across all
ablations, and the adjusted p-values come from one step-down pass over
the whole family.

*ablation of a real component shows a measurable contribution drop* — an
end-to-end run over scripted backends where removing a load-bearing
component produces a negative delta with a REGRESSION verdict, while
ablating an inert component does not.
"""

from __future__ import annotations

import hashlib
import json
from types import MappingProxyType

import pytest

from evoruntime.eval import (
    CONTRIBUTIONS_SCHEMA_ID,
    Arm,
    ArmKind,
    Experiment,
    ExperimentDefinitionError,
    MarginalContribution,
    MarginalContributionError,
    ScriptedAgent,
    Verdict,
    holm_adjusted_p_values,
    load_contributions,
    marginal_contributions,
    persist_contributions,
    run_arm,
    strategy_for,
    summarize_experiment,
)
from tests.campaign.conftest import make_spec_mapping
from tests.eval.conftest import frozen_clock, make_tasks, scripted_outcomes


def ablation_experiment(
    *,
    family: tuple[str, ...] = ("tool-loop",),
    arms: tuple[Arm, ...] | None = None,
    name: str = "ablation-study-2026-08",
) -> Experiment:
    """The relaxed ablation frame: exactly one incumbent + ablation arms."""
    if arms is None:
        arms = (
            Arm(id="incumbent", kind=ArmKind.INCUMBENT),
            Arm.ablation("no-tool-loop", "tool-loop"),
        )
    return Experiment(
        name=name,
        dataset="ds_repo_repair_dev_v1",
        task_budget_profile="task-budget-v1",
        arms=arms,
        ablation_family=family,
        bootstrap_iterations=200,
    )


def run_arms(exp: Experiment, backends: dict[str, ScriptedAgent], tasks: tuple) -> list:
    """Run every arm over the task set with a frozen clock."""
    runs = []
    for arm in exp.arms:
        runs.extend(
            run_arm(
                experiment=exp,
                arm=arm,
                backend=backends[arm.id],
                tasks=tasks,
                clock_factory=frozen_clock,
            )
        )
    return runs


class _MemoryStore:
    """Content-addressed store with fault injection, mirroring the
    campaign test double."""

    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}

    def store(self, data: bytes, *, schema_id: str) -> str:
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        self._blobs[digest] = data
        return digest

    def load(self, digest: str) -> bytes:
        return self._blobs[digest]

    def corrupt(self, digest: str, data: bytes) -> None:
        self._blobs[digest] = data


class TestUnregisteredAblationRejected:
    """The preregistration closure: the family is pinned at spec time."""

    def test_ablation_outside_the_family_is_refused(self) -> None:
        with pytest.raises(ExperimentDefinitionError) as excinfo:
            ablation_experiment(
                arms=(
                    Arm(id="incumbent", kind=ArmKind.INCUMBENT),
                    Arm.ablation("no-tool-loop", "tool-loop"),
                    Arm.ablation("no-memory", "memory"),
                ),
                family=("tool-loop",),
            )
        assert "memory" in str(excinfo.value)
        assert "preregistered" in str(excinfo.value)

    def test_ablation_without_any_family_is_refused(self) -> None:
        with pytest.raises(ExperimentDefinitionError, match="preregister"):
            ablation_experiment(family=())

    def test_campaign_spec_refuses_an_unregistered_ablation(self) -> None:
        from evoruntime.campaign.errors import InvalidCampaignSpecError
        from evoruntime.campaign.spec import CampaignSpec

        raw = make_spec_mapping()
        raw["schema_version"] = 2
        raw["mutable_artifacts"] = [raw.pop("mutable_artifact")]
        raw["arms"].append({"id": "no-tool-loop", "kind": "ablation", "component_id": "tool-loop"})
        # The family names a different component than the arm ablates.
        raw["statistics"]["ablation_family"] = ["retriever"]

        with pytest.raises(InvalidCampaignSpecError, match="preregistered ablation family"):
            CampaignSpec.from_mapping(raw)

    def test_campaign_spec_refuses_an_ablation_with_no_family_declared(self) -> None:
        from evoruntime.campaign.errors import InvalidCampaignSpecError
        from evoruntime.campaign.spec import CampaignSpec

        raw = make_spec_mapping()
        raw["schema_version"] = 2
        raw["mutable_artifacts"] = [raw.pop("mutable_artifact")]
        raw["arms"].append({"id": "no-tool-loop", "kind": "ablation", "component_id": "tool-loop"})
        with pytest.raises(InvalidCampaignSpecError, match="ablation_family"):
            CampaignSpec.from_mapping(raw)


class TestArmFrame:
    """The relaxed frame and the component-id discipline."""

    def test_incumbent_plus_ablations_constructs_without_control_arms(self) -> None:
        """The ablation frame is one incumbent + >=1 ablation — no retry,
        one-shot, or strategy arm is required."""
        exp = ablation_experiment()
        assert [arm.kind for arm in exp.arms].count(ArmKind.INCUMBENT) == 1
        assert [arm.id for arm in exp.ablation_arms] == ["no-tool-loop"]

    def test_component_id_is_required_for_an_ablation_arm(self) -> None:
        with pytest.raises(ExperimentDefinitionError, match="must name the component"):
            Arm(id="no-tool-loop", kind=ArmKind.ABLATION)

    def test_component_id_is_forbidden_on_other_kinds(self) -> None:
        with pytest.raises(ExperimentDefinitionError, match="only meaningful"):
            Arm(id="incumbent", kind=ArmKind.INCUMBENT, component_id="tool-loop")

    def test_two_arms_may_not_ablate_the_same_component(self) -> None:
        with pytest.raises(ExperimentDefinitionError, match="duplicate ablation"):
            ablation_experiment(
                arms=(
                    Arm(id="incumbent", kind=ArmKind.INCUMBENT),
                    Arm.ablation("no-tool-loop-a", "tool-loop"),
                    Arm.ablation("no-tool-loop-b", "tool-loop"),
                ),
            )

    def test_a_declared_family_without_ablation_arms_is_refused(self) -> None:
        """A family nobody ablates is a spec mistake, not a no-op."""
        with pytest.raises(ExperimentDefinitionError, match="preregistered but no arm"):
            ablation_experiment(
                arms=(Arm(id="incumbent", kind=ArmKind.INCUMBENT),),
                family=("tool-loop",),
            )

    def test_ablation_arm_spends_the_incumbent_envelope(self) -> None:
        """The only allowed delta is the removed component — the strategy
        mapping must not give the ablation arm a different envelope or
        verifier kind."""
        strategy = strategy_for(Arm.ablation("no-tool-loop", "tool-loop"))
        incumbent = strategy_for(Arm(id="incumbent", kind=ArmKind.INCUMBENT))
        assert strategy.max_attempts == incumbent.max_attempts
        assert strategy.allow_tools == incumbent.allow_tools
        assert type(strategy.verifier) is type(incumbent.verifier)


class TestFamilyWideMultiplicity:
    """One Holm family across every ablation in the run."""

    def two_ablation_fixture(self) -> tuple[Experiment, dict[str, ScriptedAgent], tuple]:
        tasks = make_tasks(count=12)
        arms = (
            Arm(id="incumbent", kind=ArmKind.INCUMBENT),
            Arm.ablation("no-tool-loop", "tool-loop"),
            Arm.ablation("no-memory", "memory"),
        )
        exp = ablation_experiment(family=("tool-loop", "memory"), arms=arms)
        backends = {
            "incumbent": ScriptedAgent(scripted_outcomes(tasks, 9)),
            "no-tool-loop": ScriptedAgent(scripted_outcomes(tasks, 5)),
            "no-memory": ScriptedAgent(scripted_outcomes(tasks, 4)),
        }
        return exp, backends, tasks

    def test_per_comparison_alpha_splits_across_the_whole_family(self) -> None:
        exp, backends, tasks = self.two_ablation_fixture()
        result = summarize_experiment(exp, run_arms(exp, backends, tasks))

        # Two ablations in the family: each interval is built at alpha/2.
        assert result.per_comparison_alpha == pytest.approx(exp.alpha / 2)
        assert set(result.delta) == {"no-tool-loop", "no-memory"}

    def test_holm_adjustment_covers_all_ablations_in_one_pass(self) -> None:
        exp, backends, tasks = self.two_ablation_fixture()
        result = summarize_experiment(exp, run_arms(exp, backends, tasks))

        raw = {arm_id: c.bootstrap.p_value for arm_id, c in result.delta.items()}
        expected = holm_adjusted_p_values(raw)
        assert {arm_id: c.adjusted_p_value for arm_id, c in result.delta.items()} == expected
        # Holm's step-down ordering: the larger raw p never ends up with
        # the smaller adjusted value.
        ordered = sorted(raw.items(), key=lambda item: item[1])
        assert expected[ordered[0][0]] <= expected[ordered[1][0]]


class TestRealComponentContribution:
    """End-to-end: ablating a real component costs measurable score."""

    def test_ablating_a_real_component_shows_a_contribution_drop(self) -> None:
        tasks = make_tasks(count=12)
        arms = (
            Arm(id="incumbent", kind=ArmKind.INCUMBENT),
            Arm.ablation("no-tool-loop", "tool-loop"),
            Arm.ablation("no-inert-flag", "inert-flag"),
        )
        exp = ablation_experiment(family=("tool-loop", "inert-flag"), arms=arms)
        backends = {
            "incumbent": ScriptedAgent(scripted_outcomes(tasks, 9)),
            # Removing the tool loop breaks most tasks...
            "no-tool-loop": ScriptedAgent(scripted_outcomes(tasks, 3)),
            # ...removing an inert component changes nothing.
            "no-inert-flag": ScriptedAgent(scripted_outcomes(tasks, 9)),
        }
        result = summarize_experiment(exp, run_arms(exp, backends, tasks))

        records = {r.component_id: r for r in marginal_contributions(result)}
        assert set(records) == {"tool-loop", "inert-flag"}

        real = records["tool-loop"]
        assert real.observed_delta == pytest.approx(3 / 12 - 9 / 12)
        assert real.verdict == Verdict.REGRESSION.value
        assert real.adjusted_p_value <= exp.alpha

        inert = records["inert-flag"]
        assert inert.observed_delta == pytest.approx(0.0)
        assert inert.verdict == Verdict.INCONCLUSIVE.value

    def test_records_carry_arm_ids_in_declaration_order(self) -> None:
        tasks = make_tasks(count=12)
        arms = (
            Arm(id="incumbent", kind=ArmKind.INCUMBENT),
            Arm.ablation("no-tool-loop", "tool-loop"),
        )
        exp = ablation_experiment(arms=arms)
        backends = {
            "incumbent": ScriptedAgent(scripted_outcomes(tasks, 9)),
            "no-tool-loop": ScriptedAgent(scripted_outcomes(tasks, 5)),
        }
        result = summarize_experiment(exp, run_arms(exp, backends, tasks))

        records = marginal_contributions(result)
        assert [r.arm_id for r in records] == ["no-tool-loop"]
        assert [r.component_id for r in records] == ["tool-loop"]

    def test_a_missing_comparison_is_refused_not_skipped(self) -> None:
        """A silently shorter record set would hide a run that never
        measured an ablation the preregistration is owed."""
        from evoruntime.eval import ExperimentResult

        tasks = make_tasks(count=12)
        arms = (
            Arm(id="incumbent", kind=ArmKind.INCUMBENT),
            Arm.ablation("no-tool-loop", "tool-loop"),
            Arm.ablation("no-memory", "memory"),
        )
        exp = ablation_experiment(family=("tool-loop", "memory"), arms=arms)
        backends = {
            "incumbent": ScriptedAgent(scripted_outcomes(tasks, 9)),
            "no-tool-loop": ScriptedAgent(scripted_outcomes(tasks, 5)),
            "no-memory": ScriptedAgent(scripted_outcomes(tasks, 4)),
        }
        result = summarize_experiment(exp, run_arms(exp, backends, tasks))
        stripped = ExperimentResult(
            experiment=result.experiment,
            task_ids=result.task_ids,
            primary=result.primary,
            delta=MappingProxyType({k: v for k, v in result.delta.items() if k != "no-memory"}),
            per_comparison_alpha=result.per_comparison_alpha,
        )

        with pytest.raises(MarginalContributionError, match="no comparison"):
            marginal_contributions(stripped)


class TestCheckpointPersistence:
    """The FR-005 pattern: content-addressed bytes, verified on load."""

    def roundtrip_fixture(self) -> tuple[tuple[MarginalContribution, ...], _MemoryStore, str]:
        tasks = make_tasks(count=12)
        arms = (
            Arm(id="incumbent", kind=ArmKind.INCUMBENT),
            Arm.ablation("no-tool-loop", "tool-loop"),
            Arm.ablation("no-memory", "memory"),
        )
        exp = ablation_experiment(family=("tool-loop", "memory"), arms=arms)
        backends = {
            "incumbent": ScriptedAgent(scripted_outcomes(tasks, 9)),
            "no-tool-loop": ScriptedAgent(scripted_outcomes(tasks, 5)),
            "no-memory": ScriptedAgent(scripted_outcomes(tasks, 4)),
        }
        result = summarize_experiment(exp, run_arms(exp, backends, tasks))
        records = marginal_contributions(result)
        store = _MemoryStore()
        digest = persist_contributions(records, store)
        return records, store, digest

    def test_roundtrip_preserves_the_records(self) -> None:
        records, store, digest = self.roundtrip_fixture()
        assert digest.startswith("sha256:")
        assert load_contributions(store, digest) == records

    def test_tampered_bytes_are_refused_on_load(self) -> None:
        records, store, digest = self.roundtrip_fixture()
        store.corrupt(digest, b'{"schema_id": "x", "contributions": []}')

        with pytest.raises(MarginalContributionError, match="content address"):
            load_contributions(store, digest)

    def test_a_foreign_schema_id_is_refused(self) -> None:
        store = _MemoryStore()
        data = json.dumps(
            {"schema_id": "evoruntime.eval.ablation.contributions/v2", "contributions": []}
        ).encode()
        digest = store.store(data, schema_id=CONTRIBUTIONS_SCHEMA_ID)

        with pytest.raises(MarginalContributionError, match="schema_id"):
            load_contributions(store, digest)

    def test_malformed_records_are_refused_after_verification(self) -> None:
        store = _MemoryStore()
        data = json.dumps(
            {"schema_id": CONTRIBUTIONS_SCHEMA_ID, "contributions": [{"arm_id": "a"}]}
        ).encode()
        digest = store.store(data, schema_id=CONTRIBUTIONS_SCHEMA_ID)

        with pytest.raises(MarginalContributionError, match="missing"):
            load_contributions(store, digest)
