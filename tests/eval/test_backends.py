"""Agent backends: deterministic scripts for CI, and the live path's rules.

The ScriptedAgent tests pin determinism — the property that makes every
other harness assertion a statement about the harness. The
OpenAI-compatible backend tests pin the two rules that matter for a live
run: credentials resolve from the secrets store at attempt time and
never fall back, and budget accounting is reserve-then-reconcile so a
ceiling holds against a provider that reports usage after the fact.
"""

from __future__ import annotations

import pytest

from evoruntime.eval import (
    AgentRequest,
    AttemptCost,
    BackendCredentialError,
    BackendRequestError,
    BudgetExceededError,
    BudgetMeter,
    BudgetUsage,
    ChatRequest,
    ChatResponse,
    EnvSecretsProvider,
    EvalTask,
    OpenAICompatibleBackend,
    ScriptedAgent,
    ScriptedAgentError,
    ScriptedStep,
    TaskBudget,
    estimate_input_tokens,
    resolve_credential,
)
from evoruntime.eval.backends import (
    CHARS_PER_TOKEN_ESTIMATE,
    DEFAULT_MODEL_API_KEY_SECRET,
    parse_chat_response,
)
from tests.eval.conftest import frozen_clock

SMALL_BUDGET = TaskBudget(
    max_input_tokens=10_000, max_output_tokens=2_000, max_tool_calls=10, max_wall_clock_s=120.0
)


class _MutableSecrets:
    """A SecretsProvider whose values a test can rotate between attempts."""

    def __init__(self, values: dict[str, str | None]) -> None:
        self._values = dict(values)

    def rotate(self, name: str, value: str) -> None:
        self._values[name] = value

    def get(self, name: str) -> str | None:
        return self._values.get(name)


class _FakeClient:
    """A ChatCompletionClient that records its requests and returns a canned reply."""

    def __init__(self, text: str, input_tokens: int, output_tokens: int) -> None:
        self._reply = ChatResponse(
            text=text, input_tokens=input_tokens, output_tokens=output_tokens
        )
        self.requests: list[ChatRequest] = []
        self.api_keys: list[str] = []

    def complete(self, request: ChatRequest, *, api_key: str) -> ChatResponse:
        self.requests.append(request)
        self.api_keys.append(api_key)
        return self._reply


def _meter() -> BudgetMeter:
    return BudgetMeter(SMALL_BUDGET, clock=frozen_clock())


def make_request(
    task_id: str = "tsk_001", *, attempt: int = 1, allow_tools: bool = True
) -> AgentRequest:
    return AgentRequest(
        task=EvalTask(id=task_id, prompt="fix it"),
        attempt=attempt,
        seed=42,
        remaining=BudgetUsage(
            input_tokens=SMALL_BUDGET.max_input_tokens,
            output_tokens=SMALL_BUDGET.max_output_tokens,
            tool_calls=SMALL_BUDGET.max_tool_calls,
            wall_clock_s=SMALL_BUDGET.max_wall_clock_s,
        ),
        allow_tools=allow_tools,
    )


class TestScriptedAgent:
    """The backend CI runs on — determinism is its contract."""

    def test_same_script_same_outcome(self) -> None:
        """Two agents built from one script must agree on every attempt."""
        script = {"tsk_001": (ScriptedStep(claimed_success=True),)}

        first = ScriptedAgent(script).run(make_request(), _meter())
        second = ScriptedAgent(script).run(make_request(), _meter())

        assert first.claimed_success == second.claimed_success
        assert first.input_tokens == second.input_tokens

    def test_attempt_i_uses_step_i(self) -> None:
        """A two-step script describes: fails, then succeeds."""
        script = {
            "tsk_001": (
                ScriptedStep(claimed_success=False),
                ScriptedStep(claimed_success=True),
            )
        }
        agent = ScriptedAgent(script)

        first = agent.run(make_request(attempt=1), _meter())
        second = agent.run(make_request(attempt=2), _meter())

        assert first.claimed_success is False
        assert second.claimed_success is True

    def test_short_script_repeats_its_last_step(self) -> None:
        """Fails, then succeeds, and stays succeeded — no IndexError at attempt 3."""
        script = {
            "tsk_001": (
                ScriptedStep(claimed_success=False),
                ScriptedStep(claimed_success=True),
            )
        }
        agent = ScriptedAgent(script)

        third = agent.run(make_request(attempt=3), _meter())

        assert third.claimed_success is True

    def test_missing_task_without_default_is_a_loud_error(self) -> None:
        """A script gap must surface, not silently score as a failure."""
        agent = ScriptedAgent({})

        with pytest.raises(ScriptedAgentError, match="tsk_001"):
            agent.run(make_request(), _meter())

    def test_default_step_covers_unscripted_tasks(self) -> None:
        agent = ScriptedAgent({}, default=ScriptedStep(claimed_success=True))

        assert agent.run(make_request(), _meter()).claimed_success is True

    def test_charges_the_scripted_cost(self) -> None:
        """The meter, not the response, is the ledger — and it must see the cost."""
        cost = AttemptCost(input_tokens=500, output_tokens=100, tool_calls=2, wall_clock_s=3.0)
        meter = _meter()

        ScriptedAgent({"tsk_001": (ScriptedStep(True, cost=cost),)}).run(make_request(), meter)

        assert meter.usage.input_tokens == 500
        assert meter.usage.output_tokens == 100
        assert meter.usage.tool_calls == 2

    def test_no_tool_loop_no_tool_charge(self) -> None:
        """A one-shot control is not billed for scaffolding it never ran."""
        meter = _meter()

        ScriptedAgent(
            {"tsk_001": (ScriptedStep(True, cost=AttemptCost(tool_calls=3)),)}
        ).run(make_request(allow_tools=False), meter)

        assert meter.usage.tool_calls == 0


class TestCredentialResolution:
    """Credentials come from the secrets store at run time — never code."""

    def test_missing_credential_is_a_typed_error_with_no_fallback(self) -> None:
        """An absent key must stop the run, not degrade to an unauthenticated call."""
        with pytest.raises(BackendCredentialError, match="never falls back"):
            resolve_credential(_MutableSecrets({}), "EVORUNTIME_MODEL_API_KEY")

    def test_empty_credential_is_treated_as_missing(self) -> None:
        with pytest.raises(BackendCredentialError):
            resolve_credential(_MutableSecrets({"K": "   "}), "K")

    def test_env_provider_reads_the_bare_name(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EVORUNTIME_MODEL_API_KEY", "sk-live-123")

        assert EnvSecretsProvider().get("EVORUNTIME_MODEL_API_KEY") == "sk-live-123"

    def test_env_provider_reads_the_secret_prefixed_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The platform's secrets store injects as SECRET_<NAME>."""
        monkeypatch.setenv("SECRET_EVORUNTIME_MODEL_API_KEY", "sk-injected")

        assert EnvSecretsProvider().get("EVORUNTIME_MODEL_API_KEY") == "sk-injected"

    def test_default_secret_name_is_pinned(self) -> None:
        """A silent rename would leave every deployment's credential unset."""
        assert DEFAULT_MODEL_API_KEY_SECRET == "EVORUNTIME_MODEL_API_KEY"


class TestOpenAICompatibleBackend:
    """The live path: reserve-then-reconcile inside the arm's envelope."""

    def _backend(
        self, client: _FakeClient, secrets: _MutableSecrets | None = None
    ) -> OpenAICompatibleBackend:
        return OpenAICompatibleBackend(
            model="gpt-test",
            client=client,
            secrets=secrets
            if secrets is not None
            else _MutableSecrets({DEFAULT_MODEL_API_KEY_SECRET: "sk-test"}),
        )

    def test_usage_is_reconciled_to_the_provider_report(self) -> None:
        """Reserved output the model did not generate is refunded; the
        input estimate is trued up to the provider's count."""
        client = _FakeClient("TASK_COMPLETE done", input_tokens=120, output_tokens=40)
        meter = _meter()

        response = self._backend(client).run(make_request(), meter)

        assert response.claimed_success is True
        assert meter.usage.input_tokens == 120
        assert meter.usage.output_tokens == 40

    def test_success_marker_decides_the_claimed_outcome(self) -> None:
        """The marker is the contract between fixture prompts and the backend."""
        client = _FakeClient("partial progress, no marker", input_tokens=10, output_tokens=5)

        response = self._backend(client).run(make_request(), _meter())

        assert response.claimed_success is False

    def test_missing_credential_fails_before_any_request_is_made(self) -> None:
        """No key, no network call — the failure is local and typed."""
        client = _FakeClient("x", input_tokens=1, output_tokens=1)
        backend = OpenAICompatibleBackend(
            model="gpt-test", client=client, secrets=_MutableSecrets({})
        )

        with pytest.raises(BackendCredentialError):
            backend.run(make_request(), _meter())

        assert client.requests == []

    def test_credential_is_resolved_per_attempt_not_cached(self) -> None:
        """A credential held on the object outlives the rotation meant to retire it."""
        client = _FakeClient("TASK_COMPLETE", input_tokens=10, output_tokens=5)
        secrets = _MutableSecrets({DEFAULT_MODEL_API_KEY_SECRET: "sk-first"})
        backend = OpenAICompatibleBackend(model="gpt-test", client=client, secrets=secrets)

        backend.run(make_request(), _meter())
        secrets.rotate(DEFAULT_MODEL_API_KEY_SECRET, "sk-rotated")
        backend.run(make_request(), _meter())

        assert client.api_keys == ["sk-first", "sk-rotated"]

    def test_request_carries_the_task_prompt_and_seed(self) -> None:
        """The provider call must be reproducible: same task, same seed."""
        client = _FakeClient("ok", input_tokens=10, output_tokens=5)
        request = make_request()

        self._backend(client).run(request, _meter())

        assert client.requests[0].model == "gpt-test"
        assert client.requests[0].prompt == request.task.prompt
        assert client.requests[0].seed == request.seed

    def test_a_reconciliation_that_crosses_the_ceiling_raises(self) -> None:
        """The tokens are spent either way, but an over-budget result never
        enters the comparison — the error propagates as budget exhaustion."""
        client = _FakeClient(
            "TASK_COMPLETE",
            input_tokens=SMALL_BUDGET.max_input_tokens + 5,
            output_tokens=1,
        )

        with pytest.raises(BudgetExceededError):
            self._backend(client).run(make_request(), _meter())


class TestParseChatResponse:
    """Pure parsing: a shape the provider changed must fail loudly here."""

    def test_extracts_text_and_usage(self) -> None:
        body = {
            "choices": [{"message": {"role": "assistant", "content": "patch applied"}}],
            "usage": {"prompt_tokens": 111, "completion_tokens": 22},
        }

        parsed = parse_chat_response(body)

        assert parsed.text == "patch applied"
        assert parsed.input_tokens == 111
        assert parsed.output_tokens == 22

    @pytest.mark.parametrize(
        "body",
        [
            "not a dict",
            {"choices": []},
            {"choices": [{"message": {}}]},
            {"choices": [{"message": {"content": "x"}}]},
            {"choices": [{"message": {"content": "x"}}], "usage": {}},
            {"choices": [{"message": {"content": "x"}}], "usage": {"prompt_tokens": "abc"}},
        ],
    )
    def test_unreadable_shapes_raise_a_typed_error(self, body: object) -> None:
        """A run with zero recorded cost is worse than a failed run."""
        with pytest.raises(BackendRequestError):
            parse_chat_response(body)


class TestTokenEstimate:
    """The pre-flight reservation."""

    def test_estimate_is_pessimistic(self) -> None:
        """Erring high costs headroom; erring low costs the comparison its validity."""
        assert estimate_input_tokens("x" * 300) == 100

    def test_estimate_never_returns_zero(self) -> None:
        """An empty prompt still reserves something: one token minimum."""
        assert estimate_input_tokens("") == 1

    def test_chars_per_token_constant_is_pinned(self) -> None:
        assert CHARS_PER_TOKEN_ESTIMATE == 3.0
