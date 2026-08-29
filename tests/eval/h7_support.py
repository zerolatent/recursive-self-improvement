"""H7 transfer doubles: a second harness and a second model family.

Harness #1 is the H1 fixture agent (ScriptedAgent stands in for its
deterministic step loop in tests). These stubs give `TransferSuite`
families something genuinely different to point at, with no network and
no provider dependency: the provider behind `ChatCompletionClient` is an
implementation detail, and a deterministic stub is the honest choice for
CI — same input, same completion, every run.
"""

from __future__ import annotations

from evoruntime.eval.backends import (
    AgentRequest,
    AgentResponse,
    AttemptCost,
    ChatRequest,
    ChatResponse,
)
from evoruntime.eval.budgets import BudgetMeter

SUCCESS_MARKER = "TASK_COMPLETE"


class StaticSecretsProvider:
    """In-memory `SecretsProvider` — the stub credential store for tests."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = dict(values)

    def get(self, name: str) -> str | None:
        return self._values.get(name)


class DeterministicHarness:
    """Harness #2: succeeds exactly on tasks whose difficulty it can solve.

    Deliberately unlike ScriptedAgent (per-task script): this harness
    reads the task's slice annotation and succeeds on a declared
    difficulty set, so a CROSS_HARNESS family compares two harnesses with
    different competence profiles over the same fixture corpus.
    """

    def __init__(
        self,
        *,
        solved_difficulties: tuple[str, ...] = ("easy",),
        cost: AttemptCost | None = None,
    ) -> None:
        self._solved = frozenset(solved_difficulties)
        self._cost = cost if cost is not None else AttemptCost()

    def run(self, request: AgentRequest, meter: BudgetMeter) -> AgentResponse:
        """Charge the fixed cost, then succeed iff the task is in the solved set."""
        tool_calls = self._cost.tool_calls if request.allow_tools else 0
        meter.charge(
            input_tokens=self._cost.input_tokens,
            output_tokens=self._cost.output_tokens,
            tool_calls=tool_calls,
            wall_clock_s=self._cost.wall_clock_s,
        )
        difficulty = request.task.metadata.get("difficulty", "")
        return AgentResponse(
            claimed_success=difficulty in self._solved,
            input_tokens=self._cost.input_tokens,
            output_tokens=self._cost.output_tokens,
            tool_calls=tool_calls,
            wall_clock_s=self._cost.wall_clock_s,
            output=SUCCESS_MARKER if difficulty in self._solved else "task not solved",
        )


class StubChatCompletionClient:
    """A deterministic `ChatCompletionClient` for one model family.

    `succeeds_up_to_chars` models a family with a shorter effective
    context: prompts beyond the limit fail, everything else completes.
    Token usage is derived from the prompt deterministically, so the
    budget reconciliation in `OpenAICompatibleBackend` sees stable numbers.
    """

    def __init__(self, *, family: str, succeeds_up_to_chars: int | None = None) -> None:
        self._family = family
        self._succeeds_up_to_chars = succeeds_up_to_chars

    def complete(self, request: ChatRequest, *, api_key: str) -> ChatResponse:
        """Return the family's deterministic completion for this prompt."""
        del api_key  # the stub never authenticates anywhere
        succeeds = (
            self._succeeds_up_to_chars is None or len(request.prompt) <= self._succeeds_up_to_chars
        )
        text = SUCCESS_MARKER if succeeds else f"[{self._family}] could not complete the task"
        return ChatResponse(
            text=text,
            input_tokens=max(1, len(request.prompt) // 3),
            output_tokens=24,
        )
