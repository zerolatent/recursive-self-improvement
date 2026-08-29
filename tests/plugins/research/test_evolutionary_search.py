"""Behavior tests for the §16.5 evolutionary-artifact-search plugin.

Archive-diversity constraints, MAP-Elites admission, the cascaded
cheap-to-expensive verdict (F6 short-circuit semantics, plugin-side),
and the F6 stage/cost_class seam — over the real plugin subprocess for
the handler paths and in-process for the pure archive functions.
"""

from __future__ import annotations

import copy
import json
from types import SimpleNamespace

from tests.plugins.research.support import (
    assert_manifest_admits,
    load_plugin_module,
)

MODULE = "evolutionary_artifact_search"

PASSING_METRICS = {
    "stage:0:lint:passed": True,
    "stage:1:holdout:passed": True,
    "stage:1:holdout:score": 0.9,
    "descriptor:0": 0.6,
    "descriptor:1": 0.4,
}


def handler():
    return load_plugin_module(MODULE).EvolutionaryArtifactSearch()


def fresh_state() -> dict:
    context = {
        "campaign_id": "camp-f11",
        "artifact_type": "algorithm",
        "mutable_paths": ["algorithm/"],
        "runtime_version": "1.0.0",
    }
    return handler().initialize(context)


class TestArchiveDiversityConstraints:
    def test_parents_come_from_cells_at_least_min_distance_apart(self) -> None:
        from evoruntime.plugins.research.evolutionary_artifact_search import (
            MIN_PARENT_DISTANCE,
            sample_diverse_parents,
        )

        archive = {
            "0,0": {"candidate_id": "a", "descriptor": [0.05, 0.05], "score": 0.5},
            "0,1": {"candidate_id": "b", "descriptor": [0.1, 0.1], "score": 0.6},  # too close to a
            "3,3": {"candidate_id": "c", "descriptor": [0.95, 0.95], "score": 0.4},
        }
        parents = sample_diverse_parents(archive, k=2, min_distance=MIN_PARENT_DISTANCE)
        assert len(parents) == 2
        (first, second) = parents
        distance = (
            sum(
                (x - y) ** 2 for x, y in zip(first["descriptor"], second["descriptor"], strict=True)
            )
            ** 0.5
        )
        assert distance >= MIN_PARENT_DISTANCE

    def test_diversity_is_never_traded_for_headcount(self) -> None:
        from evoruntime.plugins.research.evolutionary_artifact_search import (
            sample_diverse_parents,
        )

        # Three elites clustered within the min distance: only one parent
        # can satisfy the constraint.
        archive = {
            "0,0": {"candidate_id": "a", "descriptor": [0.1, 0.1], "score": 0.9},
            "0,1": {"candidate_id": "b", "descriptor": [0.15, 0.1], "score": 0.8},
            "1,0": {"candidate_id": "c", "descriptor": [0.1, 0.15], "score": 0.7},
        }
        parents = sample_diverse_parents(archive, k=3, min_distance=1.0)
        assert len(parents) == 1
        assert parents[0]["candidate_id"] == "a"  # the best elite seeds the sample

    def test_empty_archive_yields_no_parents(self) -> None:
        from evoruntime.plugins.research.evolutionary_artifact_search import (
            sample_diverse_parents,
        )

        assert sample_diverse_parents({}, k=2, min_distance=1.0) == []


class TestMapElitesArchive:
    def test_a_cell_keeps_its_best_elite(self) -> None:
        from evoruntime.plugins.research.evolutionary_artifact_search import archive_insert

        archive = archive_insert({}, "1,1", {"candidate_id": "a", "score": 0.5})
        archive = archive_insert(archive, "1,1", {"candidate_id": "b", "score": 0.7})
        archive = archive_insert(archive, "1,1", {"candidate_id": "c", "score": 0.6})
        assert archive["1,1"]["candidate_id"] == "b"

    def test_insert_is_pure(self) -> None:
        from evoruntime.plugins.research.evolutionary_artifact_search import archive_insert

        original = {"1,1": {"candidate_id": "a", "score": 0.9}}
        frozen = copy.deepcopy(original)
        archive_insert(original, "1,1", {"candidate_id": "b", "score": 0.1})
        assert original == frozen

    def test_behavior_cell_quantizes_and_clamps(self) -> None:
        from evoruntime.plugins.research.evolutionary_artifact_search import (
            DESCRIPTOR_GRID,
            behavior_cell,
        )

        assert behavior_cell((0.0, 0.0)) == "0,0"
        assert behavior_cell((1.0, 1.0)) == f"{DESCRIPTOR_GRID - 1},{DESCRIPTOR_GRID - 1}"
        assert behavior_cell((-5.0, 42.0)) == f"0,{DESCRIPTOR_GRID - 1}"


class TestCascadedVerdict:
    def plan(self, *stages: tuple[int, str, bool]) -> tuple[dict, ...]:
        return tuple(
            {
                "name": name,
                "stage": stage,
                "cost_class": "cheap" if stage == 0 else "expensive",
                "short_circuit": short,
            }
            for stage, name, short in stages
        )

    def test_cheap_stage_failure_short_circuits_despite_expensive_metrics(self) -> None:
        from evoruntime.plugins.research.evolutionary_artifact_search import cascaded_verdict

        metrics = {
            "stage:0:lint:passed": False,
            # Expensive-stage metrics present — the cascade must NOT
            # credit them past the failed cheap stage.
            "stage:1:holdout:passed": True,
            "stage:1:holdout:score": 0.99,
        }
        verdict = cascaded_verdict(metrics, self.plan((0, "lint", True), (1, "holdout", True)))
        assert verdict["passed"] is False
        assert verdict["short_circuited"] is True
        assert verdict["resolved_stage"] == 0
        assert verdict["score"] is None

    def test_all_stages_passed_credits_the_expensive_stage_score(self) -> None:
        from evoruntime.plugins.research.evolutionary_artifact_search import cascaded_verdict

        verdict = cascaded_verdict(
            PASSING_METRICS, self.plan((0, "lint", True), (1, "holdout", True))
        )
        assert verdict["passed"] is True
        assert verdict["score"] == 0.9
        assert verdict["short_circuited"] is False

    def test_an_unrun_stage_resolves_the_candidate_as_failed(self) -> None:
        from evoruntime.plugins.research.evolutionary_artifact_search import cascaded_verdict

        # Stage 1 never reported — the cascade exited early upstream.
        metrics = {"stage:0:lint:passed": True}
        verdict = cascaded_verdict(metrics, self.plan((0, "lint", True), (1, "holdout", True)))
        assert verdict["passed"] is False
        assert verdict["resolved_stage"] == 1

    def test_empty_plan_fails_closed(self) -> None:
        from evoruntime.plugins.research.evolutionary_artifact_search import cascaded_verdict

        assert cascaded_verdict(PASSING_METRICS, ())["passed"] is False


class TestF6StagePlanSeam:
    def test_bindings_project_into_an_ascending_stage_plan(self) -> None:
        from evoruntime.plugins.research.evolutionary_artifact_search import (
            stage_plan_from_bindings,
        )

        # F6's EvaluatorBinding field names, as objects…
        bindings = [
            SimpleNamespace(name="holdout", stage=1, cost_class="expensive", short_circuit=True),
            SimpleNamespace(name="lint", stage=0, cost_class="cheap", short_circuit=True),
        ]
        plan = stage_plan_from_bindings(bindings)
        assert [stage["name"] for stage in plan] == ["lint", "holdout"]
        assert [stage["stage"] for stage in plan] == [0, 1]
        assert plan[0]["cost_class"] == "cheap"

    def test_state_payload_mappings_project_identically(self) -> None:
        from evoruntime.plugins.research.evolutionary_artifact_search import (
            stage_plan_from_bindings,
        )

        as_objects = stage_plan_from_bindings(
            [SimpleNamespace(name="lint", stage=0, cost_class="cheap", short_circuit=True)]
        )
        as_mappings = stage_plan_from_bindings(
            [{"name": "lint", "stage": 0, "cost_class": "cheap", "short_circuit": True}]
        )
        assert as_objects == as_mappings

    def test_infer_stage_plan_falls_back_to_metric_keys(self) -> None:
        from evoruntime.plugins.research.evolutionary_artifact_search import infer_stage_plan

        plan = infer_stage_plan(PASSING_METRICS)
        assert [stage["stage"] for stage in plan] == [0, 1]
        assert [stage["name"] for stage in plan] == ["lint", "holdout"]
        assert all(stage["short_circuit"] for stage in plan)


class TestEvolutionLoop:
    def test_a_fully_passing_candidate_enters_the_archive(self) -> None:
        h = handler()
        state = fresh_state()
        proposal = h.propose(state, [], None, {"proposals_remaining": 1})
        observed = h.observe(
            state,
            {
                "result_id": proposal["proposals"][0]["proposal_id"],
                "passed": True,
                "metrics": PASSING_METRICS,
            },
        )
        archives = [island["archive"] for island in observed["data"]["islands"]]
        assert any(archive for archive in archives)

    def test_a_short_circuited_candidate_never_enters_the_archive(self) -> None:
        h = handler()
        state = fresh_state()
        failed = dict(PASSING_METRICS, **{"stage:0:lint:passed": False})
        observed = h.observe(
            state,
            {
                "result_id": "evo-fail",
                "passed": False,
                "metrics": failed,
            },
        )
        assert all(not island["archive"] for island in observed["data"]["islands"])
        assert observed["data"]["last_verdict"]["short_circuited"] is True

    def test_after_archiving_the_next_proposal_samples_diverse_parents(self) -> None:
        h = handler()
        state = fresh_state()
        first = h.propose(state, [], None, {"proposals_remaining": 1})
        archived = h.observe(
            state,
            {
                "result_id": first["proposals"][0]["proposal_id"],
                "passed": True,
                "metrics": PASSING_METRICS,
            },
        )
        second = h.propose(archived, [], None, {"proposals_remaining": 1})
        (proposal,) = second["proposals"]
        patch = proposal["members"][0]["patch"]
        assert patch["base"] == first["proposals"][0]["proposal_id"]
        from evoruntime.plugins.research.evolutionary_artifact_search import behavior_cell

        assert patch["cell"] == behavior_cell(tuple(patch["descriptor"]))

    def test_determinism_same_state_same_proposal(self) -> None:
        h = handler()
        state = fresh_state()
        first = h.propose(copy.deepcopy(state), [], None, {"proposals_remaining": 3})
        second = h.propose(copy.deepcopy(state), [], None, {"proposals_remaining": 3})
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)

    def test_zero_budget_yields_no_proposals(self) -> None:
        h = handler()
        result = h.propose(fresh_state(), [], None, {"proposals_remaining": 0})
        assert result["proposals"] == []


class TestManifest:
    def test_manifest_declares_algorithm_outputs_at_tier_three(self) -> None:
        manifest = assert_manifest_admits(MODULE)
        assert {t.value for t in manifest.artifact_types} == {"algorithm", "tool_spec"}
        assert manifest.execution_requirements is not None
        assert manifest.execution_requirements.executables == ("algorithm_runner",)
        assert manifest.execution_requirements.minimum_tier >= 3
        assert manifest.plugin_id == "evolutionary-artifact-search"
