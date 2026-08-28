"""Typed harness errors.

Collected in one module, like `evoruntime.datasets.errors`, so the set of
failures a caller must handle is auditable in one place rather than
discovered one traceback at a time.

Two of these are control flow rather than faults. `BudgetExceededError`
is how an arm learns it has spent its envelope — an expected terminal
condition the runner records as a result, not a crash. `SealedPartitionError`
is the trust boundary refusing to be crossed; it is always a bug in the
caller, never a recoverable condition.
"""

from __future__ import annotations

from evoruntime.datasets.partitions import PartitionKind


class EvalError(Exception):
    """Base class for evaluation-harness failures."""


class CascadeDefinitionError(EvalError):
    """A cascade was declared in a way the runner cannot execute.

    Raised before any stage runs: an empty stage set or two stages sharing
    a stage number has no defensible execution order, and running one
    anyway would make the short-circuit semantics depend on sort stability.
    """


class ExperimentDefinitionError(EvalError):
    """An experiment or arm was declared in a way the harness cannot run.

    Raised at construction time, not run time: an experiment that cannot
    produce a defensible comparison should fail before it burns a single
    token, not after an hour of task execution.
    """


class UnknownBudgetProfileError(EvalError):
    """The named task-budget profile is not registered.

    Budget profiles are named and versioned (`task-budget-v1`) precisely
    so an experiment's resource envelope is a citable constant rather than
    a number someone typed twice. An unknown name is a typo, and a typo
    here silently invalidates every comparison in the run.
    """

    def __init__(self, name: str, known: tuple[str, ...]) -> None:
        self.name = name
        self.known = known
        super().__init__(f"unknown task budget profile {name!r} (known: {', '.join(known)})")


class BudgetExceededError(EvalError):
    """A charge would have pushed an arm past one of its ceilings.

    Carries the dimension that was hit so the runner can record *why* an
    attempt stopped: an arm that ran out of tool calls and one that ran
    out of wall clock are different findings about the same budget.
    """

    def __init__(self, dimension: str, limit: float, attempted: float) -> None:
        self.dimension = dimension
        self.limit = limit
        self.attempted = attempted
        super().__init__(
            f"task budget exhausted on {dimension}: attempted {attempted:g}, ceiling {limit:g}"
        )


class TaskSourceError(EvalError):
    """A dataset partition could not be turned into runnable tasks."""


class SealedPartitionError(TaskSourceError):
    """The harness was asked to source tasks from a sealed partition.

    Holdout content reaches exactly one caller in this system: an
    evaluator-role principal calling `HoldoutService.resolve`, which
    ledgers the read and spends alpha. The harness is not that caller and
    has no code path that becomes it, so a sealed partition is refused
    here regardless of who is asking — including an evaluator, whose role
    would otherwise permit the read. Refusing by role alone would leave
    the boundary one permission grant away from being crossed.
    """

    def __init__(self, partition_id: str, kind: PartitionKind) -> None:
        self.partition_id = partition_id
        self.kind = kind
        super().__init__(
            f"partition {partition_id} is sealed ({kind.value}); the evaluation harness "
            "never reads sealed content — run baselines against the dev partition"
        )


class ScriptedAgentError(EvalError):
    """A scripted backend was asked for a task it has no script for.

    Always a fixture bug. Substituting a default outcome would let a test
    pass while silently measuring a task nobody wrote a script for.
    """


class BackendRequestError(EvalError):
    """A model provider call failed or returned a shape we cannot read.

    Distinct from `BackendCredentialError` because the operator response
    differs: one is a configuration fix, the other is a provider incident
    or an API change.
    """


class BackendCredentialError(EvalError):
    """A model backend was invoked without a credential from the secrets store.

    Deliberately raised rather than defaulted: a backend that silently
    falls back to an unauthenticated or differently-credentialed request
    produces results attributed to the wrong model, which is worse than no
    results.
    """


class StatisticsError(EvalError):
    """A statistical routine was handed data it cannot draw a conclusion from."""


__all__ = [
    "BackendCredentialError",
    "CascadeDefinitionError",
    "BackendRequestError",
    "BudgetExceededError",
    "EvalError",
    "ExperimentDefinitionError",
    "ScriptedAgentError",
    "SealedPartitionError",
    "StatisticsError",
    "TaskSourceError",
    "UnknownBudgetProfileError",
]
