"""FR-004 protocol conformance — strategy + adapter contracts over real subprocesses."""

from __future__ import annotations

import base64
import hashlib

from evoruntime.plugins.protocol import (
    AdapterPluginClient,
    DevEvaluationResult,
    InMemoryCheckpointStore,
    StdioJsonRpcTransport,
    StrategyPluginClient,
)
from tests.plugins.support import (
    make_budget,
    make_candidate,
    make_canonical,
    make_context,
    reference_command,
    reference_env,
)


def strategy_client(mode: str = "conform") -> tuple[StrategyPluginClient, InMemoryCheckpointStore]:
    transport = StdioJsonRpcTransport(reference_command(), env=reference_env(mode))
    store = InMemoryCheckpointStore()
    return StrategyPluginClient(transport, checkpoint_store=store), store


def adapter_client(mode: str = "conform") -> AdapterPluginClient:
    transport = StdioJsonRpcTransport(reference_command(), env=reference_env(mode))
    return AdapterPluginClient(transport)


class TestStrategyContract:
    def test_initialize_returns_search_state(self) -> None:
        client, _ = strategy_client()
        try:
            state = client.initialize(make_context())
            assert state.data["initialized"] is True
            assert state.data["artifact_type"] == "prompt_bundle"
        finally:
            client.close()

    def test_propose_returns_validated_proposals(self) -> None:
        client, _ = strategy_client()
        try:
            state = client.initialize(make_context())
            proposals = client.propose(state, [], None, make_budget())
            assert len(proposals) == 1
            assert proposals[0].artifact_type == "prompt_bundle"
            assert proposals[0].patch["path"] == "prompt_bundle/system.md"
        finally:
            client.close()

    def test_observe_returns_updated_state(self) -> None:
        client, _ = strategy_client()
        try:
            state = client.initialize(make_context())
            result = DevEvaluationResult(result_id="res-1", passed=True, metrics={"score": 0.9})
            updated = client.observe(state, result)
            assert updated.data["observed"] == "res-1"
        finally:
            client.close()

    def test_checkpoint_bytes_stored_opaquely_never_deserialized(self) -> None:
        """The runtime hashes and stores plugin-native bytes; it never parses them."""
        client, store = strategy_client()
        try:
            state = client.initialize(make_context())
            ref = client.checkpoint(state)
            raw = store.load(ref.digest)
            # These bytes are not valid JSON in any schema — proof the runtime
            # round-tripped them verbatim instead of deserializing.
            assert raw == b"\x00\x01plugin-native-checkpoint\x00\xff"
            assert ref.schema_id == "reference-plugin/v1"
            assert ref.size_bytes == len(raw)
        finally:
            client.close()

    def test_checkpoint_digest_is_content_addressed(self) -> None:
        client, store = strategy_client()
        try:
            state = client.initialize(make_context())
            ref = client.checkpoint(state)
            expected = f"sha256:{hashlib.sha256(store.load(ref.digest)).hexdigest()}"
            assert ref.digest == expected
        finally:
            client.close()


class TestAdapterContract:
    def test_validate_accepts_clean_candidate(self) -> None:
        client = adapter_client()
        try:
            report = client.validate(make_candidate())
            assert report.accepted is True
            assert report.violations == ()
        finally:
            client.close()

    def test_render_returns_canonical_bytes_with_digest(self) -> None:
        client = adapter_client()
        try:
            rendered = client.render(make_canonical(), {"op": "replace"})
            content = base64.b64decode(rendered.data_b64)
            assert content.endswith(b"# rendered\n")
            assert rendered.digest.startswith("sha256:")
        finally:
            client.close()

    def test_semantic_diff_and_fingerprint(self) -> None:
        client = adapter_client()
        try:
            diff = client.semantic_diff(make_canonical(), make_canonical(b"new body"))
            assert "base" in diff.unified and "candidate" in diff.unified
            digest = client.fingerprint(make_canonical(b"deterministic body"))
            assert digest.value.startswith("sha256:")
        finally:
            client.close()
