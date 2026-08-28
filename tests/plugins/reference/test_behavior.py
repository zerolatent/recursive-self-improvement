"""Per-plugin behavior tests — each PRD §16.1–16.4 defining behavior,
proven through the real plugin subprocess with ScriptedAgent feedback.
"""

from __future__ import annotations

import pytest

from evoruntime.plugins.protocol import PluginMethodError, StdioJsonRpcTransport
from tests.plugins.reference.support import (
    make_budget,
    plugin_command,
    plugin_context,
    plugin_env,
    sample_evidence,
    scripted_dev_result,
    strategy_client,
)

# ---------------------------------------------------------------------------
# §16.1 experience-distiller
# ---------------------------------------------------------------------------


class TestExperienceDistiller:
    def init(self):
        client, _ = strategy_client("experience_distiller")
        return client, client.initialize(plugin_context("memory_entry", ("memory/",)))

    def test_distills_both_success_and_failure_traces(self) -> None:
        client, state = self.init()
        try:
            proposals = client.propose(
                state, [], sample_evidence("experience_distiller"), make_budget()
            )
            outcomes = {p.patch["entry"]["outcome"] for p in proposals}
            assert outcomes == {"success", "failure"}
            assert all(p.artifact_type == "memory_entry" for p in proposals)
        finally:
            client.close()

    def test_proposals_are_delta_edits_with_scoped_routing(self) -> None:
        client, state = self.init()
        try:
            proposals = client.propose(
                state, [], sample_evidence("experience_distiller"), make_budget()
            )
            for proposal in proposals:
                assert proposal.patch["op"] in ("add_entry", "amend_entry")
                scope = proposal.patch["entry"]["scope"]
                assert scope["task_type"] == "coding"
                assert scope["environment"] == "ci"
                assert scope["model_id"] == "model-a" or scope["model_id"] is None
                assert scope["harness_id"] in (None, "harness-a")
        finally:
            client.close()

    def test_every_proposal_declares_paired_persistence_evaluation(self) -> None:
        client, state = self.init()
        try:
            proposals = client.propose(
                state, [], sample_evidence("experience_distiller"), make_budget()
            )
            for proposal in proposals:
                required = proposal.patch["required_evaluation"]
                assert required["design"] == "paired"
                assert set(required["arms"]) == {"persistence-on", "persistence-off"}
                assert "non-inferiority" in required["gates"]
                assert "negative-transfer" in required["gates"]
        finally:
            client.close()

    def test_traces_without_a_persistence_pair_are_not_distilled(self) -> None:
        from evoruntime.plugins.reference.experience_distiller import distill_proposals

        item = {
            "trace_id": "t-unpaired",
            "outcome": "success",
            "route": {"environment": "ci", "task_type": "coding"},
            "strategy_text": "unpaired evidence",
        }
        proposals, skipped = distill_proposals((item,), max_proposals=5)
        assert proposals == []
        assert skipped[0]["reason"] == "requires paired persistence-on/off evaluation"

    def test_whole_memory_rewrites_are_never_proposed(self) -> None:
        from evoruntime.plugins.reference.experience_distiller import distill_proposals

        item = {
            "trace_id": "t-rewrite",
            "outcome": "success",
            "persistence_pair": {"on": {}, "off": {}},
            "requested_op": "replace_memory",
            "route": {"environment": "ci", "task_type": "coding"},
            "strategy_text": "rewrite everything",
        }
        proposals, skipped = distill_proposals((item,), max_proposals=5)
        assert proposals == []
        assert "delta edits only" in skipped[0]["reason"]

    def test_executable_content_is_never_auto_promoted(self) -> None:
        from evoruntime.plugins.reference.experience_distiller import distill_proposals

        item = {
            "trace_id": "t-exec",
            "outcome": "success",
            "persistence_pair": {"on": {}, "off": {}},
            "content_kind": "executable",
            "route": {"environment": "ci", "task_type": "coding"},
            "strategy_text": "run this binary",
        }
        proposals, skipped = distill_proposals((item,), max_proposals=5)
        assert proposals == []
        assert "executable" in skipped[0]["reason"]

    def test_malformed_bundle_is_a_structured_error(self) -> None:
        transport = StdioJsonRpcTransport(plugin_command("experience_distiller"), env=plugin_env())
        try:
            transport.request(
                "strategy/initialize",
                {"context": plugin_context("memory_entry", ("memory/",)).model_dump(mode="json")},
                timeout_s=10.0,
            )
            with pytest.raises(PluginMethodError, match="malformed evidence"):
                transport.request(
                    "strategy/propose",
                    {
                        "state": {"data": {}},
                        "parents": [],
                        "evidence": {"redacted_items": 42},
                        "budget": make_budget().model_dump(mode="json"),
                    },
                    timeout_s=10.0,
                )
        finally:
            transport.close()


# ---------------------------------------------------------------------------
# §16.2 bootstrap-demonstration-compiler
# ---------------------------------------------------------------------------


class TestBootstrapDemonstrationCompiler:
    def init(self):
        client, _ = strategy_client("bootstrap_demonstration_compiler")
        return client, client.initialize(
            plugin_context("demonstration_set", ("demonstration_set/",))
        )

    def test_stores_only_externally_metric_approved_traces(self) -> None:
        from evoruntime.plugins.reference.bootstrap_demonstration_compiler import (
            compile_demonstrations,
        )

        items = (
            {
                "trace_id": "t-approved",
                "metric_approved": True,
                "teacher_model": "teacher-x",
                "labels": ["golden"],
                "tokens": 100,
            },
            {"trace_id": "t-self-reported", "metric_approved": False, "tokens": 100},
        )
        proposals, skipped = compile_demonstrations(items, max_proposals=5)
        compiled = proposals[0]["patch"]["demonstrations"]
        assert [demo["source_trace"] for demo in compiled] == ["t-approved"]
        assert skipped[0]["reason"] == "not externally metric-approved"

    def test_records_source_teacher_labels_ordering_and_token_budget(self) -> None:
        client, state = self.init()
        try:
            proposals = client.propose(
                state, [], sample_evidence("bootstrap_demonstration_compiler"), make_budget()
            )
            set_proposal = next(p for p in proposals if p.artifact_type == "demonstration_set")
            demos = set_proposal.patch["demonstrations"]
            assert [demo["order"] for demo in demos] == [0, 1]
            assert demos[0]["source_trace"] == "t-approved-1"
            assert demos[0]["teacher_model"] == "teacher-x"
            assert demos[0]["labels"] == ["golden", "coding"]
            assert set_proposal.patch["token_budget"] == 200
        finally:
            client.close()

    def test_supplies_the_equal_budget_control(self) -> None:
        client, state = self.init()
        try:
            proposals = client.propose(
                state, [], sample_evidence("bootstrap_demonstration_compiler"), make_budget()
            )
            control = next(p for p in proposals if p.artifact_type == "compiled_prompt_program")
            set_proposal = next(p for p in proposals if p.artifact_type == "demonstration_set")
            assert control.patch["role"] == "equal-budget-control"
            assert control.patch["token_budget"] == set_proposal.patch["token_budget"]
            assert control.patch["shots"] == 1
        finally:
            client.close()

    def test_budget_of_one_ships_the_set_and_defers_the_control(self) -> None:
        client, state = self.init()
        try:
            proposals = client.propose(
                state,
                [],
                sample_evidence("bootstrap_demonstration_compiler"),
                make_budget(proposals_remaining=1),
            )
            assert [p.artifact_type for p in proposals] == ["demonstration_set"]
        finally:
            client.close()

    def test_no_approved_traces_yields_no_proposals(self) -> None:
        from evoruntime.plugins.reference.bootstrap_demonstration_compiler import (
            compile_demonstrations,
        )

        proposals, _skipped = compile_demonstrations(
            ({"trace_id": "t", "metric_approved": False},), max_proposals=5
        )
        assert proposals == []


# ---------------------------------------------------------------------------
# §16.3 gepa-prompt-optimizer
# ---------------------------------------------------------------------------


class TestGepaPromptOptimizer:
    def init(self):
        client, _ = strategy_client("gepa_prompt_optimizer")
        return client, client.initialize(
            plugin_context("prompt_bundle", ("prompt_bundle/system.md", "prompt_bundle/tools.md"))
        )

    def test_edits_exactly_one_declared_module_per_mutation(self) -> None:
        client, state = self.init()
        try:
            proposals = client.propose(state, [], None, make_budget())
            assert len(proposals) == 1
            patch = proposals[0].patch
            assert patch["op"] == "amend_module"
            assert patch["module"] in ("prompt_bundle/system.md", "prompt_bundle/tools.md")
        finally:
            client.close()

    def test_pareto_state_is_instance_wise(self) -> None:
        from evoruntime.plugins.reference.gepa_prompt_optimizer import update_pareto_state

        pareto = update_pareto_state({}, {"inst-a": 0.6, "inst-b": 0.4})
        pareto = update_pareto_state(pareto, {"inst-a": 0.4, "inst-b": 0.9})
        assert pareto == {"inst-a": 0.6, "inst-b": 0.9}

    def test_minibatch_failure_is_rejected_before_full_evaluation(self) -> None:
        """ScriptedAgent-driven: a candidate that fails the working
        minibatch never joins the frontier and never becomes a parent."""
        client, state = self.init()
        try:
            proposals = client.propose(state, [], None, make_budget())
            candidate_id = proposals[0].proposal_id
            failed = scripted_dev_result(
                candidate_id,
                claimed_success=False,
                metrics={"instance:prompt_bundle/system.md:1": 0.2},
            )
            state = client.observe(state, failed)
            assert state.data["rejected"] == [failed.result_id]
            assert state.data["frontier"] == []
            # The next mutation does not descend from the rejected candidate.
            proposals = client.propose(state, [], None, make_budget())
            assert candidate_id not in proposals[0].rationale
            assert proposals[0].proposal_id != candidate_id
        finally:
            client.close()

    def test_minibatch_pass_joins_the_frontier_and_updates_pareto(self) -> None:
        client, state = self.init()
        try:
            proposals = client.propose(state, [], None, make_budget())
            candidate_id = proposals[0].proposal_id
            passed = scripted_dev_result(
                candidate_id,
                claimed_success=True,
                metrics={"instance:prompt_bundle/system.md:1": 0.8},
            )
            state = client.observe(state, passed)
            assert state.data["frontier"] == [passed.result_id]
            assert state.data["pareto"]["prompt_bundle/system.md:1"] == 0.8
            assert state.data["lineage"][passed.result_id]["minibatch_passed"] is True
        finally:
            client.close()

    def test_requires_at_least_one_declared_module(self) -> None:
        client, _ = strategy_client("gepa_prompt_optimizer")
        try:
            with pytest.raises(PluginMethodError, match="declared module"):
                client.initialize(plugin_context("prompt_bundle", ()))
        finally:
            client.close()


# ---------------------------------------------------------------------------
# §16.4 skillopt-text-skill-optimizer
# ---------------------------------------------------------------------------


class TestSkilloptTextSkillOptimizer:
    def init(self):
        client, _ = strategy_client("skillopt_text_skill_optimizer")
        return client, client.initialize(plugin_context("skill_package", ("skill_package/",)))

    def test_bounded_edits_cap_the_proposal(self) -> None:
        from evoruntime.plugins.reference.skillopt_text_skill_optimizer import (
            MAX_EDITS_PER_PROPOSAL,
            plan_edits,
        )

        edits = [
            {"action": "add", "section": f"s{i}", "text": f"text {i}"}
            for i in range(MAX_EDITS_PER_PROPOSAL + 2)
        ]
        proposals, rejected = plan_edits(({"skill_edits": edits},), max_proposals=5)
        assert len(proposals) == 1
        assert len(proposals[0]["patch"]["edits"]) == MAX_EDITS_PER_PROPOSAL
        deferred = [r for r in rejected if "bounded" in r["reason"]]
        assert len(deferred) == 2

    def test_edit_vocabulary_is_add_delete_replace_only(self) -> None:
        from evoruntime.plugins.reference.skillopt_text_skill_optimizer import plan_edits

        edits = [
            {"action": "rewrite", "section": "s", "text": "not a bounded edit"},
            {"action": "add", "section": "s", "text": "valid"},
        ]
        proposals, rejected = plan_edits(({"skill_edits": edits},), max_proposals=5)
        assert len(proposals[0]["patch"]["edits"]) == 1
        assert "vocabulary" in rejected[0]["reason"]

    def test_text_only_non_string_and_executable_edits_are_refused(self) -> None:
        from evoruntime.plugins.reference.skillopt_text_skill_optimizer import plan_edits

        edits = [
            {"action": "add", "section": "s", "text": 12345},
            {"action": "add", "section": "s", "text": "code", "executable": True},
            {"action": "add", "section": "s", "text": "valid"},
        ]
        proposals, rejected = plan_edits(({"skill_edits": edits},), max_proposals=5)
        assert len(proposals[0]["patch"]["edits"]) == 1
        reasons = [r["reason"] for r in rejected]
        assert any("text-only" in reason for reason in reasons)
        assert any("executable" in reason for reason in reasons)

    def test_reject_buffer_retains_failed_candidates(self) -> None:
        client, state = self.init()
        try:
            failed = scripted_dev_result("skill-cand-1", claimed_success=False)
            state = client.observe(state, failed)
            assert state.data["reject_buffer"][0]["candidate_id"] == "skill-cand-1-1"
            # The evidence survives checkpointing — it is not discarded.
            ref = client.checkpoint(state)
            assert ref.size_bytes > 0
        finally:
            client.close()

    def test_repairs_and_regressions_are_reported_separately(self) -> None:
        client, state = self.init()
        try:
            first = scripted_dev_result(
                "skill-cand-a",
                claimed_success=True,
                metrics={"repairs": 3, "regressions": 1},
            )
            state = client.observe(state, first)
            second = scripted_dev_result(
                "skill-cand-b",
                claimed_success=True,
                metrics={"repairs": 0, "regressions": 2},
            )
            state = client.observe(state, second)
            assert state.data["repairs"] == 3
            assert state.data["regressions"] == 3
        finally:
            client.close()
