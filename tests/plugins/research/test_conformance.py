"""Per-plugin FR-004 conformance — the E2 suites run against each of the
two F11 research plugins over real subprocesses.

The same suite families the E7 reference plugins answer: protocol (§10.2
strategy contract), compatibility (§10.4 manifest admission, extended
with the F2 execution-requirements checks executable classes demand),
budget (proposal ceilings), malformed-output (structured JSON-RPC
errors, never a dead process), and declared-artifact-types-only.
"""

from __future__ import annotations

import hashlib
from typing import Any

import pytest

from evoruntime.plugins.manifest import EXECUTABLE_ARTIFACT_TYPES, PluginArtifactType
from evoruntime.plugins.protocol import (
    PluginMethodError,
    StdioJsonRpcTransport,
)
from tests.plugins.research.support import (
    RESEARCH_MODULE_NAMES,
    RESEARCH_PLUGIN_PARAMS,
    assert_manifest_admits,
    make_budget,
    plugin_command,
    plugin_context,
    plugin_env,
    sample_evidence,
    strategy_client,
)
from tests.plugins.support import RUNTIME_VERSION


def context_for(module_name: str):
    artifact_type, mutable_paths = next(
        (t, paths) for name, t, paths in RESEARCH_PLUGIN_PARAMS if name == module_name
    )
    return plugin_context(artifact_type, mutable_paths)


class TestProtocolConformance:
    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_initialize_returns_search_state(self, module_name: str) -> None:
        client, _ = strategy_client(module_name)
        try:
            state = client.initialize(context_for(module_name))
            artifact_type = next(t for name, t, _ in RESEARCH_PLUGIN_PARAMS if name == module_name)
            assert state.data["artifact_type"] == artifact_type
        finally:
            client.close()

    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_propose_returns_validated_proposals_within_budget(self, module_name: str) -> None:
        client, _ = strategy_client(module_name)
        try:
            state = client.initialize(context_for(module_name))
            proposals = client.propose(
                state, [], sample_evidence(module_name), make_budget(proposals_remaining=5)
            )
            assert 0 < len(proposals) <= 5
            for proposal in proposals:
                assert proposal.proposal_id
                assert proposal.patch or proposal.members
        finally:
            client.close()

    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_propose_emits_composite_proposals(self, module_name: str) -> None:
        """F11 requires composite multi-artifact proposals from both
        plugins: every proposal carries an ordered member set whose
        primary member matches the singular artifact_type."""
        client, _ = strategy_client(module_name)
        try:
            state = client.initialize(context_for(module_name))
            proposals = client.propose(state, [], sample_evidence(module_name), make_budget())
            for proposal in proposals:
                assert proposal.is_composite
                assert proposal.members[0].artifact_type == proposal.artifact_type
        finally:
            client.close()

    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_observe_returns_updated_state(self, module_name: str) -> None:
        client, _ = strategy_client(module_name)
        try:
            state = client.initialize(context_for(module_name))
            result = scripted_pass(module_name)
            updated = client.observe(state, result)
            assert updated.data.get("last_evaluation") == result.result_id
        finally:
            client.close()

    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_checkpoint_bytes_stored_opaquely_content_addressed(self, module_name: str) -> None:
        client, store = strategy_client(module_name)
        try:
            state = client.initialize(context_for(module_name))
            ref = client.checkpoint(state)
            raw = store.load(ref.digest)
            assert ref.digest == f"sha256:{hashlib.sha256(raw).hexdigest()}"
            assert ref.schema_id.endswith("/v1")
            assert ref.size_bytes == len(raw)
        finally:
            client.close()


def scripted_pass(module_name: str):
    """A passing dev-evaluation with plugin-shaped stage/node metrics."""
    from evoruntime.plugins.protocol import DevEvaluationResult

    metrics: dict[str, float] = (
        {"node:op-1": 0.8, "node:op-2": 0.7}
        if module_name == "workflow_graph_search"
        else {
            "stage:0:lint:passed": 1.0,
            "stage:1:holdout:passed": 1.0,
            "stage:1:holdout:score": 0.9,
            "descriptor:0": 0.6,
            "descriptor:1": 0.4,
        }
    )
    return DevEvaluationResult(result_id=f"task-{module_name}-1", passed=True, metrics=metrics)


class TestCompatibilityConformance:
    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_manifest_admits_against_runtime_version(self, module_name: str) -> None:
        assert_manifest_admits(module_name)

    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_manifest_entrypoint_matches_the_served_module(self, module_name: str) -> None:
        manifest = assert_manifest_admits(module_name)
        assert manifest.entrypoint.transport == "stdio-jsonrpc"
        assert manifest.entrypoint.command == ("python", "-m", plugin_command(module_name)[2])

    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_manifest_requests_no_direct_network(self, module_name: str) -> None:
        """The egress broker is the sole network path; a research plugin
        never requests direct network access."""
        manifest = assert_manifest_admits(module_name)
        assert manifest.permissions.network.value == "none"

    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_manifest_model_access_is_brokered_with_explicit_hosts(self, module_name: str) -> None:
        """Model access is the §16.6 posture: either none at all, or
        brokered with an explicit exact-host allowlist the broker
        matches — never a blanket request."""
        manifest = assert_manifest_admits(module_name)
        if not manifest.permissions.model_access:
            assert manifest.permissions.model_hosts == ()
            return
        assert manifest.permissions.model_hosts
        assert all(host and "/" not in host for host in manifest.permissions.model_hosts)

    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_manifest_is_deterministic_with_seed(self, module_name: str) -> None:
        manifest = assert_manifest_admits(module_name)
        assert manifest.reproducibility.deterministic is True
        assert manifest.reproducibility.seed is not None
        assert "@sha256:" in manifest.reproducibility.pinned_image

    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_manifest_declares_execution_requirements_for_executable_outputs(
        self, module_name: str
    ) -> None:
        """Both plugins declare executable outputs at the required tier:
        every declared class is executable, and the manifest carries the
        F2 execution requirements (executables + minimum isolation tier)."""
        manifest = assert_manifest_admits(module_name)
        declared = {PluginArtifactType(t) for t in manifest.artifact_types}
        assert declared <= EXECUTABLE_ARTIFACT_TYPES
        assert manifest.execution_requirements is not None
        assert manifest.execution_requirements.executables
        assert manifest.execution_requirements.minimum_tier >= 3


class TestBudgetConformance:
    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_propose_respects_a_budget_of_one(self, module_name: str) -> None:
        client, _ = strategy_client(module_name)
        try:
            state = client.initialize(context_for(module_name))
            proposals = client.propose(
                state, [], sample_evidence(module_name), make_budget(proposals_remaining=1)
            )
            assert len(proposals) <= 1
        finally:
            client.close()

    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_zero_budget_yields_no_proposals(self, module_name: str) -> None:
        client, _ = strategy_client(module_name)
        try:
            state = client.initialize(context_for(module_name))
            proposals = client.propose(
                state, [], sample_evidence(module_name), make_budget(proposals_remaining=0)
            )
            assert proposals == []
        finally:
            client.close()


def raw_propose(
    transport: StdioJsonRpcTransport,
    state_data: dict[str, Any],
    evidence_payload: Any,
) -> Any:
    """Call strategy/propose over the wire with an unvalidated payload —
    the injection point for malformed-output conformance."""
    return transport.request(
        "strategy/propose",
        {
            "state": state_data,
            "parents": [],
            "evidence": evidence_payload,
            "budget": make_budget().model_dump(mode="json"),
        },
        timeout_s=10.0,
    )


class TestMalformedOutputConformance:
    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_malformed_evidence_is_a_jsonrpc_error_and_the_process_survives(
        self, module_name: str
    ) -> None:
        transport = StdioJsonRpcTransport(plugin_command(module_name), env=plugin_env())
        try:
            state = transport.request(
                "strategy/initialize",
                {"context": context_for(module_name).model_dump(mode="json")},
                timeout_s=10.0,
            )
            bad_bundle = {"bundle_id": "bad", "redacted_items": "not-a-list"}
            with pytest.raises(PluginMethodError, match="malformed evidence"):
                raw_propose(transport, state, bad_bundle)
            # The plugin answered with a structured error, not a crash —
            # the same process still serves a well-formed request.
            result = raw_propose(
                transport, state, sample_evidence(module_name).model_dump(mode="json")
            )
            assert isinstance(result["proposals"], list)
        finally:
            transport.close()

    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_malformed_state_is_a_jsonrpc_error(self, module_name: str) -> None:
        transport = StdioJsonRpcTransport(plugin_command(module_name), env=plugin_env())
        try:
            transport.request(
                "strategy/initialize",
                {"context": context_for(module_name).model_dump(mode="json")},
                timeout_s=10.0,
            )
            with pytest.raises(PluginMethodError, match="malformed state"):
                raw_propose(transport, {"data": "not-an-object"}, None)
        finally:
            transport.close()


class TestDeclaredArtifactTypesOnly:
    @pytest.mark.parametrize("module_name", RESEARCH_MODULE_NAMES)
    def test_every_proposal_member_uses_a_declared_artifact_type(self, module_name: str) -> None:
        """A plugin proposes only artifact types its manifest declares —
        checked per composite member, over the sample evidence and a
        no-evidence call."""
        manifest = assert_manifest_admits(module_name)
        declared = {t.value for t in manifest.artifact_types}
        client, _ = strategy_client(module_name)
        try:
            state = client.initialize(context_for(module_name))
            for evidence in (sample_evidence(module_name), None):
                proposals = client.propose(state, [], evidence, make_budget())
                for proposal in proposals:
                    assert proposal.artifact_type in declared
                    for member in proposal.typed_members():
                        assert member.artifact_type in declared
        finally:
            client.close()


def test_runtime_version_is_pinned() -> None:
    """The research plugins conformance-test against the same runtime
    version the shared support module pins."""
    assert RUNTIME_VERSION == "1.0.0"
