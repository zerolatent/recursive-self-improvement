"""Brokered model access (H10): the §13.2 direct-dial bypass, closed.

The contract under test: a harness backend dials a model provider only
through the egress broker's model_hosts allowlist, and a host not on it
fails closed — typed refusal, no credential read, no byte moved. The
refusal tests assert on the recording client's request log, not just the
exception type, because "fails closed" means the dial never happened.
"""

from __future__ import annotations

import pytest

from evoruntime.eval import (
    AgentRequest,
    BudgetMeter,
    BudgetUsage,
    ChatRequest,
    ChatResponse,
    EvalTask,
    OpenAICompatibleBackend,
    TaskBudget,
)
from evoruntime.eval.backends import (
    DEFAULT_MODEL_HOSTS,
    DEFAULT_OPENAI_BASE_URL,
    BrokeredChatCompletionClient,
    ChatCompletionClient,
    brokered_model_client,
)
from evoruntime.eval.errors import BrokeredEgressDeniedError
from tests.eval.conftest import frozen_clock

SMALL_BUDGET = TaskBudget(
    max_input_tokens=10_000, max_output_tokens=2_000, max_tool_calls=10, max_wall_clock_s=120.0
)

REMAINING = BudgetUsage(
    input_tokens=SMALL_BUDGET.max_input_tokens,
    output_tokens=SMALL_BUDGET.max_output_tokens,
    tool_calls=SMALL_BUDGET.max_tool_calls,
    wall_clock_s=SMALL_BUDGET.max_wall_clock_s,
)


class _RecordingClient:
    """A ChatCompletionClient that logs every dial — the refusal test's witness."""

    def __init__(self, text: str = "TASK_COMPLETE done") -> None:
        self._reply = ChatResponse(text=text, input_tokens=10, output_tokens=5)
        self.requests: list[ChatRequest] = []

    def complete(self, request: ChatRequest, *, api_key: str) -> ChatResponse:
        self.requests.append(request)
        return self._reply


class _MutableSecrets:
    def __init__(self, values: dict[str, str]) -> None:
        self._values = dict(values)

    def get(self, name: str) -> str | None:
        return self._values.get(name)


def _secrets() -> _MutableSecrets:
    return _MutableSecrets({"EVORUNTIME_MODEL_API_KEY": "sk-test"})


def _meter() -> BudgetMeter:
    return BudgetMeter(SMALL_BUDGET, clock=frozen_clock())


def _request() -> AgentRequest:
    return AgentRequest(
        task=EvalTask(id="tsk_001", prompt="fix it"),
        attempt=1,
        seed=42,
        remaining=REMAINING,
        allow_tools=False,
    )


class TestOpenAICompatibleBackendBroker:
    """The live backend authorizes every dial before anything else happens."""

    def test_direct_dial_to_unallowlisted_host_fails_closed(self) -> None:
        """A backend pointed off the allowlist refuses before the client is touched."""
        client = _RecordingClient()
        backend = OpenAICompatibleBackend(
            model="gpt-test",
            client=client,  # type: ignore[arg-type]
            secrets=_secrets(),
            model_endpoint="https://malicious.example.com/v1",
        )

        with pytest.raises(BrokeredEgressDeniedError, match="malicious.example.com"):
            backend.run(_request(), _meter())

        assert client.requests == []

    def test_refusal_does_not_touch_the_secrets_store(self) -> None:
        """The broker check runs before credential resolution."""
        client = _RecordingClient()
        secrets = _MutableSecrets({})  # no key at all — must not matter
        backend = OpenAICompatibleBackend(
            model="gpt-test",
            client=client,  # type: ignore[arg-type]
            secrets=secrets,
            model_endpoint="https://malicious.example.com/v1",
        )

        with pytest.raises(BrokeredEgressDeniedError):
            backend.run(_request(), _meter())

    def test_allowlisted_endpoint_dials_normally(self) -> None:
        """The sanctioned path is unchanged: default host, default allowlist."""
        client = _RecordingClient()
        backend = OpenAICompatibleBackend(
            model="gpt-test",
            client=client,
            secrets=_secrets(),  # type: ignore[arg-type]
        )

        response = backend.run(_request(), _meter())

        assert response.claimed_success is True
        assert len(client.requests) == 1

    def test_explicit_allowlist_names_the_endpoint(self) -> None:
        """A non-default endpoint works only when its host is allowlisted."""
        client = _RecordingClient()
        backend = OpenAICompatibleBackend(
            model="gpt-test",
            client=client,  # type: ignore[arg-type]
            secrets=_secrets(),
            model_endpoint="https://gateway.internal.corp/v1",
            model_hosts=("gateway.internal.corp",),
        )

        response = backend.run(_request(), _meter())

        assert response.claimed_success is True

    def test_allowlist_matching_is_case_insensitive(self) -> None:
        """Host matching follows EgressPolicy's case-insensitive exact rule."""
        client = _RecordingClient()
        backend = OpenAICompatibleBackend(
            model="gpt-test",
            client=client,  # type: ignore[arg-type]
            secrets=_secrets(),
            model_endpoint="https://API.OPENAI.COM/v1",
        )

        response = backend.run(_request(), _meter())

        assert response.claimed_success is True

    def test_empty_allowlist_is_refused_at_construction(self) -> None:
        """An empty allowlist is a misconfiguration, refused loudly up front."""
        with pytest.raises(ValueError, match="at least one host"):
            OpenAICompatibleBackend(
                model="gpt-test",
                client=_RecordingClient(),  # type: ignore[arg-type]
                secrets=_secrets(),
                model_hosts=(),
            )

    def test_default_allowlist_is_the_sanctioned_host(self) -> None:
        """The default posture: deny-by-default with one sanctioned host."""
        assert DEFAULT_MODEL_HOSTS == ("api.openai.com",)


class TestBrokeredChatCompletionClient:
    """The wrapper authorizes before the wrapped transport is touched."""

    def test_denied_destination_never_reaches_the_inner_client(self) -> None:
        """The §13.2 direct-dial bypass has no path through this class."""
        inner = _RecordingClient()
        client = BrokeredChatCompletionClient(
            inner,  # type: ignore[arg-type]
            model_endpoint="https://evil.example.net/v1",
        )

        with pytest.raises(BrokeredEgressDeniedError, match="evil.example.net"):
            client.complete(
                ChatRequest(model="m", prompt="p", max_output_tokens=8, temperature=0.0, seed=1),
                api_key="sk-test",
            )

        assert inner.requests == []

    def test_allowed_destination_delegates(self) -> None:
        """An allowlisted endpoint passes straight through to the transport."""
        inner = _RecordingClient()
        client = BrokeredChatCompletionClient(inner)  # type: ignore[arg-type]

        response = client.complete(
            ChatRequest(model="m", prompt="p", max_output_tokens=8, temperature=0.0, seed=1),
            api_key="sk-test",
        )

        assert response.text == "TASK_COMPLETE done"
        assert len(inner.requests) == 1

    def test_empty_allowlist_is_refused_at_construction(self) -> None:
        """Same construction-time refusal as the backend."""
        with pytest.raises(ValueError, match="at least one host"):
            BrokeredChatCompletionClient(_RecordingClient(), model_hosts=())  # type: ignore[arg-type]


class TestBrokeredModelClientFactory:
    """The sanctioned live-model dial path."""

    def test_factory_returns_a_brokered_client(self) -> None:
        """The factory pairs the HTTP transport with the broker policy."""
        client = brokered_model_client()

        assert isinstance(client, BrokeredChatCompletionClient)

    def test_factory_refuses_an_empty_allowlist(self) -> None:
        """Fail closed at construction, before any dial is possible."""
        with pytest.raises(ValueError, match="at least one host"):
            brokered_model_client(model_hosts=())

    def test_factory_is_assignable_to_the_client_protocol(self) -> None:
        """The wrapper satisfies ChatCompletionClient structurally."""
        client: ChatCompletionClient = brokered_model_client()

        assert callable(client.complete)
        assert DEFAULT_OPENAI_BASE_URL.startswith("https://api.openai.com")
