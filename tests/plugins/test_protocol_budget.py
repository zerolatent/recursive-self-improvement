"""FR-004 budget enforcement and malformed-plugin-output handling."""

from __future__ import annotations

import pytest

from evoruntime.plugins.protocol import (
    BudgetExceededError,
    InMemoryCheckpointStore,
    PluginProcessDiedError,
    PluginProtocolViolationError,
    PluginRequestTimeoutError,
    StdioJsonRpcTransport,
    StrategyPluginClient,
    _dispatch_line,
    clean_plugin_env,
)
from tests.plugins.support import (
    make_budget,
    make_context,
    reference_command,
    reference_env,
)


def client_for(mode: str, timeout_s: float = 10.0) -> StrategyPluginClient:
    transport = StdioJsonRpcTransport(reference_command(), env=reference_env(mode))
    return StrategyPluginClient(
        transport, checkpoint_store=InMemoryCheckpointStore(), request_timeout_s=timeout_s
    )


class TestBudgetEnforcement:
    def test_plugin_returning_over_budget_proposals_is_rejected(self) -> None:
        client = client_for("over_budget")
        try:
            state = client.initialize(make_context())
            with pytest.raises(BudgetExceededError, match="only 1 remain"):
                client.propose(state, [], None, make_budget(proposals_remaining=1))
        finally:
            client.close()

    def test_exact_budget_is_accepted(self) -> None:
        client = client_for("exact")
        try:
            state = client.initialize(make_context())
            # exact returns exactly proposals_remaining proposals; a budget of 2 admits them.
            proposals = client.propose(state, [], None, make_budget(proposals_remaining=2))
            assert len(proposals) == 2
        finally:
            client.close()


class TestWallClockEnforcement:
    def test_hung_plugin_hits_the_request_deadline(self) -> None:
        client = client_for("hang", timeout_s=0.5)
        with pytest.raises(PluginRequestTimeoutError):
            client.initialize(make_context())
        # The transport must not leave the hung process attached.
        client.close()

    def test_dead_process_raises_process_died(self) -> None:
        client = client_for("die")
        with pytest.raises(PluginProcessDiedError):
            client.initialize(make_context())


class TestMalformedPluginOutput:
    def test_non_json_output_is_a_protocol_violation(self) -> None:
        client = client_for("bad_json")
        with pytest.raises(PluginProtocolViolationError):
            client.initialize(make_context())

    def test_unknown_method_returns_method_not_found(self) -> None:
        """The plugin-side dispatcher answers unknown methods with -32601."""

        class Noop:
            pass

        response = _dispatch_line(
            b'{"jsonrpc":"2.0","id":1,"method":"strategy/teleport","params":{}}', Noop()
        )
        assert response["error"]["code"] == -32601


class TestCleanEnvironment:
    def test_clean_plugin_env_scrubs_secrets(self) -> None:
        env = clean_plugin_env()
        assert "EVORUNTIME_EVALUATOR_SIGNING_KEY" not in env
        assert "EVORUNTIME_DATABASE_URL" not in env
        # Only a minimal allowlist survives.
        assert set(env) <= {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR"}

    def test_plugin_process_never_sees_host_secrets(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """End-to-end: a secret in the runtime's env never reaches the plugin."""
        monkeypatch.setenv("EVORUNTIME_EVALUATOR_SIGNING_KEY", "test-secret-value")
        monkeypatch.setenv("EVORUNTIME_DATABASE_URL", "postgres://secret")
        client = client_for("env_probe")
        try:
            state = client.initialize(make_context())
            seen = set(state.data["env_var_names"])
            assert "EVORUNTIME_EVALUATOR_SIGNING_KEY" not in seen
            assert "EVORUNTIME_DATABASE_URL" not in seen
            # The plugin still gets what it needs to run.
            assert "PATH" in seen
            assert "EVORUNTIME_PLUGIN_MODE" in seen
        finally:
            client.close()
