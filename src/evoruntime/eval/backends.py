"""Agent backends: what actually attempts a task.

Two backends ship in Phase 0 and they exist for different reasons. The
scripted ones make the harness testable — a deterministic agent turns
"did the statistics work?" into a question with a known answer, which is
the only way to validate an estimator. The OpenAI-compatible one makes
the harness real, and its whole job is to charge the budget honestly
against a provider that bills for tokens whether or not the harness was
paying attention.

The budget contract every backend obeys: **charge before you spend.** A
backend receives the `BudgetMeter` and must charge a resource before
consuming it, so a ceiling is enforced at the moment of the decision
rather than discovered in an audit. `BudgetExceededError` propagates to
the runner, which records the attempt as budget-exhausted. Authoritative
usage is always read from the meter, never from a backend's self-report —
a backend that under-reports its costs cannot thereby buy itself more
room than its peers.

Credentials never appear in code, fixtures, or an experiment definition.
The live backend resolves its key from the secrets store at call time
through `SecretsProvider`, and a missing key raises rather than silently
falling back to an unauthenticated request that would attribute results
to the wrong model.
"""

from __future__ import annotations

import json
import math
import os
import random
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from evoruntime.eval.budgets import BudgetMeter, BudgetUsage
from evoruntime.eval.errors import (
    BackendCredentialError,
    BackendRequestError,
    BrokeredEgressDeniedError,
    ScriptedAgentError,
)
from evoruntime.eval.tasks import EvalTask
from evoruntime.security.egress import EgressBroker, EgressDeniedError, EgressPolicy

DEFAULT_MODEL_API_KEY_SECRET = "EVORUNTIME_MODEL_API_KEY"
"""Secret name holding the API key for the OpenAI-compatible backend."""

DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
"""Overridable per client — any OpenAI-compatible gateway works."""

DEFAULT_MODEL_HOSTS = ("api.openai.com",)
"""The default model_hosts allowlist (H10).

Deny-by-default with one sanctioned host: a backend pointed at any other
endpoint must name that host explicitly, so a misconfigured campaign
cannot dial a provider nobody allowlisted. Mirrors the harness mutator's
MODEL_HOSTS convention (G9).
"""

CHARS_PER_TOKEN_ESTIMATE = 3.0
"""Deliberately pessimistic (real English is closer to 4).

The pre-flight input charge is an estimate, and an estimate that runs low
would let a request through that the ceiling should have stopped. Erring
high costs an arm a little headroom; erring low costs the comparison its
validity.
"""


@dataclass(frozen=True, slots=True)
class AgentRequest:
    """Everything a backend needs to make one attempt at one task."""

    task: EvalTask
    attempt: int
    seed: int
    remaining: BudgetUsage
    allow_tools: bool = True


@dataclass(frozen=True, slots=True)
class AgentResponse:
    """What a backend did, for the attempt record.

    Costs here are descriptive. The meter, not this object, is the ledger.
    """

    claimed_success: bool
    input_tokens: int = 0
    output_tokens: int = 0
    tool_calls: int = 0
    wall_clock_s: float = 0.0
    output: str = ""


class AgentBackend(Protocol):
    """A thing that attempts tasks under a budget."""

    def run(self, request: AgentRequest, meter: BudgetMeter) -> AgentResponse:
        """Attempt the task, charging `meter` before each resource is spent.

        Raises:
            BudgetExceededError: the attempt could not proceed inside the
                envelope. Expected control flow, not a fault.
        """
        ...


@dataclass(frozen=True, slots=True)
class AttemptCost:
    """The resources one scripted attempt declares."""

    input_tokens: int = 1_000
    output_tokens: int = 200
    tool_calls: int = 2
    wall_clock_s: float = 5.0


@dataclass(frozen=True, slots=True)
class ScriptedStep:
    """One scripted attempt: its claimed outcome and what it cost."""

    claimed_success: bool
    cost: AttemptCost = field(default_factory=AttemptCost)
    output: str = ""


class ScriptedAgent:
    """A deterministic backend driven by a per-task script.

    The backend CI runs on. Given the same script it produces the same
    outcomes, the same costs, and the same budget exhaustion points on
    every machine, which is what makes an assertion about the harness an
    assertion about the harness rather than about a model's mood.

    Attempt *i* uses step *i*; a script shorter than the attempt count
    repeats its last step, so a two-step script describes "fails, then
    succeeds, and stays succeeded".
    """

    def __init__(
        self,
        script: Mapping[str, Sequence[ScriptedStep]],
        *,
        default: ScriptedStep | None = None,
    ) -> None:
        self._script = {task_id: tuple(steps) for task_id, steps in script.items()}
        self._default = default

    def run(self, request: AgentRequest, meter: BudgetMeter) -> AgentResponse:
        """Charge the scripted cost, then return the scripted outcome."""
        step = self._step_for(request.task.id, request.attempt)
        # A one-shot control has no tool loop, so it is not charged for one.
        tool_calls = step.cost.tool_calls if request.allow_tools else 0
        meter.charge(
            input_tokens=step.cost.input_tokens,
            output_tokens=step.cost.output_tokens,
            tool_calls=tool_calls,
            wall_clock_s=step.cost.wall_clock_s,
        )
        return AgentResponse(
            claimed_success=step.claimed_success,
            input_tokens=step.cost.input_tokens,
            output_tokens=step.cost.output_tokens,
            tool_calls=tool_calls,
            wall_clock_s=step.cost.wall_clock_s,
            output=step.output,
        )

    def _step_for(self, task_id: str, attempt: int) -> ScriptedStep:
        steps = self._script.get(task_id)
        if steps is None or not steps:
            if self._default is None:
                raise ScriptedAgentError(
                    f"no scripted steps for task {task_id!r} and no default step"
                )
            return self._default
        return steps[min(attempt - 1, len(steps) - 1)]


class BernoulliScriptedAgent:
    """A deterministic backend whose success rate is a known parameter.

    This is the instrument the statistics are calibrated against: set the
    incumbent to 0.45 and a candidate to 0.70 and the true effect is
    exactly 0.25, so a bootstrap interval either recovers it or is wrong.

    The draw is seeded from the cell's seed and the attempt number and
    nothing else — not the arm id. Two arms therefore see the *same*
    uniform draw for the same task and attempt, which couples them:
    a candidate with a higher success probability succeeds on a strict
    superset of the incumbent's tasks. That is common random numbers, and
    it is what lets a paired design detect a real effect on twenty tasks
    instead of two hundred.
    """

    def __init__(
        self,
        *,
        success_probability: float | Mapping[str, float],
        cost: AttemptCost | None = None,
        default_probability: float = 0.0,
    ) -> None:
        self._probability = success_probability
        self._cost = cost if cost is not None else AttemptCost()
        self._default_probability = default_probability

    def run(self, request: AgentRequest, meter: BudgetMeter) -> AgentResponse:
        """Charge the fixed cost, then draw the outcome for this cell."""
        tool_calls = self._cost.tool_calls if request.allow_tools else 0
        meter.charge(
            input_tokens=self._cost.input_tokens,
            output_tokens=self._cost.output_tokens,
            tool_calls=tool_calls,
            wall_clock_s=self._cost.wall_clock_s,
        )
        draw = random.Random(f"{request.seed}:{request.attempt}").random()
        return AgentResponse(
            claimed_success=draw < self._probability_for(request.task.id),
            input_tokens=self._cost.input_tokens,
            output_tokens=self._cost.output_tokens,
            tool_calls=tool_calls,
            wall_clock_s=self._cost.wall_clock_s,
        )

    def _probability_for(self, task_id: str) -> float:
        if isinstance(self._probability, float | int):
            return float(self._probability)
        return self._probability.get(task_id, self._default_probability)


class SecretsProvider(Protocol):
    """Read-only access to named credentials."""

    def get(self, name: str) -> str | None:
        """Return the secret's value, or None when it is not configured."""
        ...


class EnvSecretsProvider:
    """Secrets from the process environment.

    Checks the bare name and the `SECRET_`-prefixed form, because the
    platform's secrets store injects configured secrets as
    `SECRET_<NAME>`. Nothing is cached: a rotated credential takes effect
    on the next attempt rather than at the next process restart.
    """

    def get(self, name: str) -> str | None:
        """Return the first non-empty match, or None."""
        for candidate in (name, f"SECRET_{name}"):
            value = os.environ.get(candidate, "").strip()
            if value:
                return value
        return None


def resolve_credential(provider: SecretsProvider, name: str) -> str:
    """Fetch a required credential.

    Raises:
        BackendCredentialError: the secret is absent or empty.
    """
    value = (provider.get(name) or "").strip()
    if not value:
        raise BackendCredentialError(
            f"model credential {name!r} is not configured; the OpenAI-compatible backend "
            "reads its key from the secrets store at run time and never falls back"
        )
    return value


@dataclass(frozen=True, slots=True)
class ChatRequest:
    """One chat-completion call, provider-agnostic."""

    model: str
    prompt: str
    max_output_tokens: int
    temperature: float
    seed: int


@dataclass(frozen=True, slots=True)
class ChatResponse:
    """A completion plus the provider's authoritative token usage."""

    text: str
    input_tokens: int
    output_tokens: int


class ChatCompletionClient(Protocol):
    """Transport for an OpenAI-compatible `/chat/completions` endpoint."""

    def complete(self, request: ChatRequest, *, api_key: str) -> ChatResponse:
        """Perform the call and return the completion with its usage."""
        ...


class HttpChatCompletionClient:
    """Minimal `/chat/completions` client over the standard library.

    `urllib` rather than a client library because the runtime package has
    no HTTP dependency and Phase 0 should not acquire one for a smoke
    path: this issues one JSON POST and reads three fields back. A
    production deployment can inject any client satisfying
    `ChatCompletionClient` without touching the backend.
    """

    def __init__(self, *, base_url: str = DEFAULT_OPENAI_BASE_URL, timeout_s: float = 60.0) -> None:
        self._base_url = base_url.rstrip("/")
        self._timeout_s = timeout_s

    def complete(self, request: ChatRequest, *, api_key: str) -> ChatResponse:
        """POST the completion request and parse the response.

        Raises:
            BackendRequestError: transport failure, non-2xx status, or a
                response whose shape the parser does not recognize.
        """
        payload = json.dumps(
            {
                "model": request.model,
                "messages": [{"role": "user", "content": request.prompt}],
                "max_tokens": request.max_output_tokens,
                "temperature": request.temperature,
                "seed": request.seed,
            }
        ).encode()
        http_request = urllib.request.Request(
            url=f"{self._base_url}/chat/completions",
            data=payload,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(http_request, timeout=self._timeout_s) as response:
                body = json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            raise BackendRequestError(
                f"chat completion failed with HTTP {exc.code}: {exc.reason}"
            ) from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise BackendRequestError(f"chat completion request failed: {exc}") from exc
        return parse_chat_response(body)


def _model_broker(model_hosts: Sequence[str]) -> EgressBroker:
    """Build the egress broker for a model_hosts allowlist (H10).

    Hosts are normalized here once; the broker matches case-insensitively
    and exactly — no wildcards, per EgressPolicy's bypass rules.

    Raises:
        ValueError: the allowlist is empty or contains blank hosts. An
            empty allowlist on a model backend is a misconfiguration, not
            a posture — refuse it at construction, fail closed at runtime.
    """
    hosts = tuple(model_hosts)
    if not hosts or any(not host.strip() for host in hosts):
        raise ValueError(
            "model_hosts must name at least one host — an empty allowlist "
            "denies every model dial; configure the allowlist explicitly"
        )
    return EgressBroker(
        EgressPolicy(allowed_hosts=frozenset(host.strip().lower() for host in hosts))
    )


class BrokeredChatCompletionClient:
    """ChatCompletionClient wrapper that authorizes every dial through the broker.

    The sanctioned construction path for live model access (H10): the
    policy check runs before the wrapped transport is touched, so a client
    pointed anywhere off the model_hosts allowlist fails closed — the
    §13.2 direct-dial bypass has no path through this class. Satisfies the
    `ChatCompletionClient` protocol, so it composes anywhere a client is
    expected, including behind the fixture agent's harness backend.
    """

    def __init__(
        self,
        inner: ChatCompletionClient,
        *,
        model_endpoint: str = DEFAULT_OPENAI_BASE_URL,
        model_hosts: Sequence[str] = DEFAULT_MODEL_HOSTS,
    ) -> None:
        self._inner = inner
        self._broker = _model_broker(model_hosts)
        self._model_endpoint = model_endpoint

    def complete(self, request: ChatRequest, *, api_key: str) -> ChatResponse:
        """Authorize the destination, then delegate to the wrapped transport."""
        try:
            self._broker.authorize(self._model_endpoint)
        except EgressDeniedError as exc:
            raise BrokeredEgressDeniedError(str(exc)) from exc
        return self._inner.complete(request, api_key=api_key)


def brokered_model_client(
    *,
    base_url: str = DEFAULT_OPENAI_BASE_URL,
    model_hosts: Sequence[str] = DEFAULT_MODEL_HOSTS,
    timeout_s: float = 60.0,
) -> ChatCompletionClient:
    """The sanctioned live-model dial path: HTTP transport behind the broker.

    Every harness model dial should be built through this factory (or the
    backend's own broker check) — a bare `HttpChatCompletionClient` handed
    to a backend is a direct-dial path the §13.2 closure exists to prevent.
    """
    return BrokeredChatCompletionClient(
        HttpChatCompletionClient(base_url=base_url, timeout_s=timeout_s),
        model_endpoint=base_url,
        model_hosts=model_hosts,
    )


def parse_chat_response(body: Any) -> ChatResponse:
    """Extract the completion text and usage from a provider response.

    Kept a pure function so the parsing is testable without a network and
    so a shape the provider changed under us fails loudly here rather than
    producing a run with zero recorded cost.
    """
    if not isinstance(body, dict):
        raise BackendRequestError(f"chat completion response was not an object: {type(body)}")

    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        raise BackendRequestError("chat completion response contained no choices")
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str):
        raise BackendRequestError("chat completion choice had no string content")

    usage = body.get("usage")
    if not isinstance(usage, dict):
        raise BackendRequestError("chat completion response reported no token usage")
    try:
        input_tokens = int(usage["prompt_tokens"])
        output_tokens = int(usage["completion_tokens"])
    except (KeyError, TypeError, ValueError) as exc:
        raise BackendRequestError(f"chat completion usage was unreadable: {usage!r}") from exc

    return ChatResponse(text=content, input_tokens=input_tokens, output_tokens=output_tokens)


def estimate_input_tokens(prompt: str) -> int:
    """Pre-flight estimate of a prompt's input tokens.

    Replaced by the provider's reported count as soon as the response
    arrives; this only has to be safe enough to reserve against.
    """
    return max(1, math.ceil(len(prompt) / CHARS_PER_TOKEN_ESTIMATE))


class OpenAICompatibleBackend:
    """Live backend for any OpenAI-compatible chat-completions endpoint.

    Budget accounting is reserve-then-reconcile, which is the only order
    that respects a ceiling against a provider that reports usage after
    the fact: reserve the estimated input and the full `max_tokens` output
    before the call, refund the output the model did not generate, then
    charge any input tokens the estimate missed. If that reconciliation
    crosses a ceiling the error propagates and the attempt is recorded as
    budget-exhausted — the tokens are spent either way, but an over-budget
    result never enters the comparison.
    """

    def __init__(
        self,
        *,
        model: str,
        client: ChatCompletionClient,
        secret_name: str = DEFAULT_MODEL_API_KEY_SECRET,
        secrets: SecretsProvider | None = None,
        max_output_tokens: int = 2_048,
        temperature: float = 0.0,
        success_marker: str = "TASK_COMPLETE",
        model_endpoint: str = DEFAULT_OPENAI_BASE_URL,
        model_hosts: Sequence[str] = DEFAULT_MODEL_HOSTS,
    ) -> None:
        self._model = model
        self._client = client
        self._secret_name = secret_name
        self._secrets = secrets if secrets is not None else EnvSecretsProvider()
        self._max_output_tokens = max_output_tokens
        self._temperature = temperature
        self._success_marker = success_marker
        # H10: every dial is authorized against the model_hosts allowlist
        # before anything else happens — no credential is read and no byte
        # moves to a host the broker has not sanctioned.
        self._broker = _model_broker(model_hosts)
        self._model_endpoint = model_endpoint

    def run(self, request: AgentRequest, meter: BudgetMeter) -> AgentResponse:
        """Make one live completion call inside the arm's remaining budget."""
        # Broker first, credential second: the refusal must not depend on
        # the secrets store, and the secrets store must not be touched for
        # a host the policy denies.
        try:
            self._broker.authorize(self._model_endpoint)
        except EgressDeniedError as exc:
            raise BrokeredEgressDeniedError(str(exc)) from exc

        # Resolved per attempt, never at construction: a credential held in
        # an object outlives the rotation that was supposed to retire it.
        api_key = resolve_credential(self._secrets, self._secret_name)

        prompt = request.task.prompt
        reserved_input = estimate_input_tokens(prompt)
        reserved_output = min(self._max_output_tokens, request.remaining.output_tokens)
        meter.charge(input_tokens=reserved_input, output_tokens=reserved_output)

        started_at = meter.elapsed_s
        response = self._client.complete(
            ChatRequest(
                model=self._model,
                prompt=prompt,
                max_output_tokens=reserved_output,
                temperature=self._temperature,
                seed=request.seed,
            ),
            api_key=api_key,
        )
        meter.refund_output_tokens(max(0, reserved_output - response.output_tokens))
        meter.charge(input_tokens=max(0, response.input_tokens - reserved_input))

        return AgentResponse(
            claimed_success=self._success_marker in response.text,
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            tool_calls=0,
            wall_clock_s=meter.elapsed_s - started_at,
            output=response.text,
        )


__all__ = [
    "CHARS_PER_TOKEN_ESTIMATE",
    "DEFAULT_MODEL_API_KEY_SECRET",
    "DEFAULT_MODEL_HOSTS",
    "DEFAULT_OPENAI_BASE_URL",
    "AgentBackend",
    "AgentRequest",
    "AgentResponse",
    "AttemptCost",
    "BernoulliScriptedAgent",
    "BrokeredChatCompletionClient",
    "ChatCompletionClient",
    "ChatRequest",
    "ChatResponse",
    "EnvSecretsProvider",
    "HttpChatCompletionClient",
    "OpenAICompatibleBackend",
    "brokered_model_client",
    "ScriptedAgent",
    "ScriptedStep",
    "SecretsProvider",
    "estimate_input_tokens",
    "parse_chat_response",
    "resolve_credential",
]
