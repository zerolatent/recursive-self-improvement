"""Behavior tests for the AFlow-inspired workflow-graph search plugin.

Drives the real plugin subprocess through the E2 clients: composite
proposals, experience-driven refinement across iterations, and
determinism under the manifest's seed.
"""

from __future__ import annotations

import copy
import json

from tests.plugins.research.support import (
    assert_manifest_admits,
    load_plugin_module,
    make_budget,
    sample_evidence,
    strategy_client,
)

MODULE = "workflow_graph_search"


def fresh_state() -> dict:
    module = load_plugin_module(MODULE)
    context = {
        "campaign_id": "camp-f11",
        "artifact_type": "workflow_graph",
        "mutable_paths": ["workflow/"],
        "runtime_version": "1.0.0",
    }
    return module.WorkflowGraphSearch().initialize(context)


def handler():
    return load_plugin_module(MODULE).WorkflowGraphSearch()


class TestCompositeProposals:
    def test_first_proposal_is_a_composite_workflow_graph_candidate(self) -> None:
        h = handler()
        state = fresh_state()
        result = h.propose(state, [], None, {"proposals_remaining": 5})
        (proposal,) = result["proposals"]
        members = proposal["members"]
        assert members[0]["artifact_type"] == "workflow_graph"
        assert members[0]["declared_executables"] == ("graph_runner",)
        patch = members[0]["patch"]
        assert patch["nodes"] and patch["edges"]
        # The seed pipeline is generate -> verify: two LLM-operator nodes.
        assert [node["operator"] for node in patch["nodes"]] == ["generate", "verify"]

    def test_expansion_with_a_tool_backed_operator_emits_two_members(self) -> None:
        h = handler()
        state = fresh_state()
        first = h.propose(state, [], None, {"proposals_remaining": 1})
        observed = h.observe(
            state,
            {
                "result_id": first["proposals"][0]["proposal_id"],
                "passed": True,
                "metrics": {"node:op-1": 0.8, "node:op-2": 0.7},
            },
        )
        second = h.propose(observed, [], None, {"proposals_remaining": 1})
        (proposal,) = second["proposals"]
        types = [member["artifact_type"] for member in proposal["members"]]
        # counter=1 rotates to the verify operator, which needs a tool:
        # the composite carries the tool_spec member atomically (F4).
        assert types == ["workflow_graph", "tool_spec"]
        assert proposal["members"][1]["patch"]["op"] == "declare_tool"


class TestExperienceDrivenRefinement:
    def test_low_scoring_node_is_pruned_once_the_graph_has_room(self) -> None:
        h = handler()
        state = fresh_state()
        # First candidate: the seed pipeline, shipped unchanged.
        seed = h.propose(state, [], None, {"proposals_remaining": 1})
        assert seed["proposals"][0]["members"][0]["patch"]["op"] == "refine_graph:seed"
        # Evaluate it, then grow the graph to three nodes.
        grown_state = h.observe(
            state,
            {
                "result_id": seed["proposals"][0]["proposal_id"],
                "passed": True,
                "metrics": {"node:op-1": 0.9, "node:op-2": 0.8},
            },
        )
        grown = h.propose(grown_state, [], None, {"proposals_remaining": 1})
        grown_state = h.observe(
            grown_state,
            {
                "result_id": grown["proposals"][0]["proposal_id"],
                "passed": True,
                "metrics": {"node:op-1": 0.9, "node:op-2": 0.8},
            },
        )
        # Then score the weakest node below the prune threshold.
        scored = h.observe(
            grown_state,
            {
                "result_id": "probe",
                "passed": False,
                "metrics": {"node:op-1": 0.1, "node:op-2": 0.9, "node:op-3": 0.9},
            },
        )
        pruned = h.propose(scored, [], None, {"proposals_remaining": 1})
        (proposal,) = pruned["proposals"]
        patch = proposal["members"][0]["patch"]
        assert patch["op"] == "refine_graph:prune"
        assert all(node["id"] != "op-1" for node in patch["nodes"])

    def test_scores_from_observe_drive_the_next_refinement(self) -> None:
        h = handler()
        state = fresh_state()
        proposal = h.propose(state, [], None, {"proposals_remaining": 1})
        observed = h.observe(
            state,
            {
                "result_id": proposal["proposals"][0]["proposal_id"],
                "passed": True,
                "metrics": {"node:op-1": 0.9, "node:op-2": 0.4},
            },
        )
        scores = {node["id"]: node["score"] for node in observed["data"]["nodes"]}
        assert scores == {"op-1": 0.9, "op-2": 0.4}
        # The experience pool records the operator that just ran.
        assert observed["data"]["experience"][-1]["passed"] is True


class TestDeterminism:
    def test_same_state_yields_the_same_proposal(self) -> None:
        h = handler()
        state = fresh_state()
        first = h.propose(copy.deepcopy(state), [], None, {"proposals_remaining": 3})
        second = h.propose(copy.deepcopy(state), [], None, {"proposals_remaining": 3})
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


class TestBudget:
    def test_zero_budget_yields_no_proposals(self) -> None:
        h = handler()
        result = h.propose(fresh_state(), [], None, {"proposals_remaining": 0})
        assert result["proposals"] == []


class TestManifest:
    def test_manifest_declares_workflow_graph_and_tool_spec(self) -> None:
        manifest = assert_manifest_admits(MODULE)
        types = {t.value for t in manifest.artifact_types}
        assert types == {"workflow_graph", "tool_spec"}
        assert manifest.plugin_id == "workflow-graph-search"


def test_client_round_trip_proposes_composite_over_the_wire() -> None:
    """End-to-end over stdio JSON-RPC: the composite members survive the
    wire round-trip as typed ProposalMember tuples."""
    from tests.plugins.research.support import (
        plugin_context,
    )

    client, _ = strategy_client(MODULE)
    try:
        state = client.initialize(plugin_context("workflow_graph", ("workflow/",)))
        proposals = client.propose(state, [], sample_evidence(MODULE), make_budget())
        (proposal,) = proposals
        assert proposal.is_composite
        assert proposal.members[0].artifact_type == "workflow_graph"
    finally:
        client.close()
