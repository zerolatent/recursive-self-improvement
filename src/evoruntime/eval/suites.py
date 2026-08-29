"""Transfer suites (Phase 2 F7, FR-103): a suite of suites above the experiment.

Phase 1's transfer check was a vocabulary check: whatever a candidate
*claimed* to transfer had to appear in the set of scopes the evaluation
*covered*, and a claim the evaluation never touched failed promotion
condition 6 (`_transfer_scope_condition`). What that check could not do
was produce the covered set from real multi-family evidence — there was
no object above a single `Experiment` that could hold "the candidate was
also evaluated against a different harness, a different model, and an
adjacent task domain".

A transfer suite is that object. It is a user-defined family of
experiments — cross-harness, cross-model, adjacent-domain — where each
family pins its own harness and backend, runs its own preregistered
`Experiment`, and produces its own paired result with the D6 machinery
(`summarize_experiment`): the same paired bootstrap, the same
multiplicity discipline, no new statistics. What F7 adds is the frame:

*Per-family pinning.* Each family names the harness and backend it runs
under, so a family cannot silently drift onto another harness or model
between the suite's declaration and its execution — the drift that would
make a "cross-harness" result measure the same harness twice.

*A scope ledger.* The set of transfer scopes the suite actually
evaluated, derived from the families that produced a valid paired
result. That tuple is what feeds promotion condition 6 as data: the
campaign passes `evaluated_transfer_scopes(result)` into
`PromotionEvidence.evaluated_transfer_scope`, and the existing condition
does the rest, unchanged.

Fail-closed carries over from Phase 1. A family whose evaluation fails
(a backend error, a statistics error) is recorded as failed with its
error message preserved, and its scope is *absent* from the evaluated
set — so a candidate claiming that scope still fails condition 6, even
though the suite ran. The suite widens what can satisfy the condition;
it does not loosen the condition.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from evoruntime.eval.backends import AgentBackend
from evoruntime.eval.budgets import MonotonicClock
from evoruntime.eval.errors import EvalError, SuiteDefinitionError
from evoruntime.eval.experiment import Experiment
from evoruntime.eval.results import ExperimentResult
from evoruntime.eval.runner import ClockFactory, run_experiment
from evoruntime.eval.sources import TaskSource


class TransferFamilyKind(StrEnum):
    """The three user-defined transfer families (PRD §14.2, FR-103)."""

    CROSS_HARNESS = "cross-harness"
    """The same candidate against a different evaluation harness."""

    CROSS_MODEL = "cross-model"
    """The same candidate against a different model backend."""

    ADJACENT_DOMAIN = "adjacent-domain"
    """The candidate against tasks from an adjacent, non-identical domain."""


@dataclass(frozen=True, slots=True)
class SuiteFamily:
    """One family of a transfer suite, pinned to its harness and backend.

    `harness_id` and `backend_id` are the family's pins: the identity of
    the harness and the model backend this family's experiment must run
    under. They are declared here, next to the experiment they govern,
    so the suite's declaration is the one place a reviewer can read what
    "cross-harness" or "cross-model" concretely meant for this campaign.

    `scope` is the transfer-scope name this family evaluates — the token
    that must appear in a candidate's claimed scopes for condition 6 to
    credit the family. It defaults to the family name so a suite whose
    families are named after their scopes needs no extra vocabulary.
    """

    name: str
    kind: TransferFamilyKind
    experiment: Experiment
    harness_id: str
    backend_id: str
    scope: str = ""

    def __post_init__(self) -> None:
        if not self.name:
            raise SuiteDefinitionError("suite family name must be non-empty")
        if not self.harness_id:
            raise SuiteDefinitionError(
                f"family {self.name!r}: harness_id must be non-empty — an unpinned "
                "family cannot defend a cross-harness or cross-model claim"
            )
        if not self.backend_id:
            raise SuiteDefinitionError(
                f"family {self.name!r}: backend_id must be non-empty — an unpinned "
                "family cannot attribute its results to a model"
            )
        if not self.scope:
            object.__setattr__(self, "scope", self.name)


@dataclass(frozen=True, slots=True)
class TransferSuite:
    """A user-defined suite of transfer families, declared before it runs.

    The suite-of-suites object above `Experiment`: it fixes which
    families make up the transfer evaluation before any of them execute,
    so the evaluated scope set is a fact about the preregistration
    rather than about which runs happened to succeed.
    """

    name: str
    families: Sequence[SuiteFamily]

    def __post_init__(self) -> None:
        object.__setattr__(self, "families", tuple(self.families))

        if not self.name:
            raise SuiteDefinitionError("transfer suite name must be non-empty")
        if not self.families:
            raise SuiteDefinitionError(
                "a transfer suite needs at least one family — an empty suite "
                "evaluates nothing and would report an empty scope set"
            )

        names = [family.name for family in self.families]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            raise SuiteDefinitionError(f"duplicate suite family name(s): {', '.join(duplicates)}")

        scopes = [family.scope for family in self.families]
        duplicate_scopes = sorted({scope for scope in scopes if scopes.count(scope) > 1})
        if duplicate_scopes:
            raise SuiteDefinitionError(
                "duplicate suite family scope(s): "
                f"{', '.join(duplicate_scopes)} — two families claiming one scope "
                "would let a single family's failure look like partial coverage"
            )

    @property
    def families_by_name(self) -> dict[str, SuiteFamily]:
        """The declared families keyed by name — the completeness check's map."""
        return {family.name: family for family in self.families}

    @property
    def scopes(self) -> tuple[str, ...]:
        """Every scope the suite declares, sorted — the coverage ceiling."""
        return tuple(sorted(family.scope for family in self.families))


@dataclass(frozen=True, slots=True)
class FamilyOutcome:
    """One family's terminal record: either a paired result or its error.

    Exactly one of `result` / `error` is set. A family that failed keeps
    its error message — the record a reviewer reads to learn *why* a
    claimed scope went unevaluated — and its scope stays out of the
    evaluated set.
    """

    family: SuiteFamily
    result: ExperimentResult | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        if (self.result is None) == (self.error is None):
            raise SuiteDefinitionError(
                f"family {self.family.name!r}: an outcome records exactly one of "
                "a paired result or an error"
            )

    @property
    def evaluated(self) -> bool:
        """True when the family produced a valid paired result."""
        return self.error is None and self.result is not None


@dataclass(frozen=True, slots=True)
class TransferSuiteResult:
    """The suite's full record: every family's outcome, run or failed."""

    suite: TransferSuite
    outcomes: Mapping[str, FamilyOutcome]
    """Keyed by family name; every declared family appears exactly once."""

    def __post_init__(self) -> None:
        object.__setattr__(self, "outcomes", MappingProxyType(dict(self.outcomes)))

    @property
    def evaluated_families(self) -> tuple[FamilyOutcome, ...]:
        """Families that produced a valid paired result, in declaration order."""
        return tuple(o for o in self.outcomes.values() if o.evaluated)

    @property
    def failed_families(self) -> tuple[FamilyOutcome, ...]:
        """Families that failed, with their preserved error messages."""
        return tuple(o for o in self.outcomes.values() if not o.evaluated)


def evaluated_transfer_scopes(result: TransferSuiteResult) -> tuple[str, ...]:
    """The transfer scopes the suite actually evaluated, sorted.

    This is the bridge to promotion condition 6: pass the returned tuple
    as `PromotionEvidence.evaluated_transfer_scope` and the existing
    claimed-vs-evaluated check runs on real multi-family data. Scopes of
    failed families are absent — a claim resting on them fails, which is
    the Phase 1 behavior preserved under multi-family evidence.

    Raises:
        SuiteDefinitionError: the result does not record an outcome for
            every declared family — a silently missing family would
            understate the evaluated set and fail promotions that real
            evidence supports.
    """
    missing = sorted(set(result.suite.families_by_name) - set(result.outcomes))
    if missing:
        raise SuiteDefinitionError(
            f"suite result is missing outcome(s) for family(ies): {', '.join(missing)}"
        )
    return tuple(sorted(outcome.family.scope for outcome in result.evaluated_families))


def run_transfer_suite(
    suite: TransferSuite,
    *,
    backends: Mapping[str, Mapping[str, AgentBackend]],
    task_sources: Mapping[str, TaskSource],
    clock_factory: ClockFactory | None = None,
) -> TransferSuiteResult:
    """Run every family of a transfer suite and record each outcome.

    Args:
        suite: the declared suite. Validated at construction.
        backends: family name -> arm id -> the backend that arm runs,
            mirroring `run_experiment`'s arm wiring one level up.
        task_sources: family name -> where that family's tasks come from.
        clock_factory: builds each run's clock, passed through to every
            family's experiment run.

    Returns:
        A result with one outcome per declared family. A family whose
        run raises a harness-taxonomy error (`EvalError`) is recorded as
        failed with the error message preserved and the remaining
        families still run — the suite reports what it evaluated and
        what it could not, and the promotion gate fails closed on the
        gap. Anything outside the taxonomy propagates: a `TypeError` in
        a backend is a bug, not a family finding.

    Raises:
        SuiteDefinitionError: any family lacks backends or a task
            source, or an arm/backend wiring is wrong — all detected
            before the first family runs, so a wiring typo cannot burn
            compute on the families it happens to precede.
    """
    _validate_wiring(suite, backends, task_sources)

    factory = clock_factory if clock_factory is not None else MonotonicClock
    outcomes: dict[str, FamilyOutcome] = {}
    for family in suite.families:
        try:
            result = run_experiment(
                family.experiment,
                backends=backends[family.name],
                task_source=task_sources[family.name],
                clock_factory=factory,
            )
            outcomes[family.name] = FamilyOutcome(family=family, result=result)
        except EvalError as exc:
            outcomes[family.name] = FamilyOutcome(
                family=family, error=f"{type(exc).__name__}: {exc}"
            )

    return TransferSuiteResult(suite=suite, outcomes=outcomes)


def _validate_wiring(
    suite: TransferSuite,
    backends: Mapping[str, Mapping[str, AgentBackend]],
    task_sources: Mapping[str, TaskSource],
) -> None:
    """Fail before any family runs when the suite's wiring is wrong.

    Mirrors `run_experiment`'s arm/backend check one level up, so a
    missing task source on the last family cannot hide behind the
    compute spent on the first three.
    """
    problems: list[str] = []
    for family in suite.families:
        if family.name not in backends:
            problems.append(f"family {family.name!r}: no backends supplied")
        else:
            supplied = backends[family.name]
            declared = {arm.id for arm in family.experiment.arms}
            missing = sorted(declared - set(supplied))
            unexpected = sorted(set(supplied) - declared)
            if missing:
                problems.append(
                    f"family {family.name!r}: no backend for arm(s): {', '.join(missing)}"
                )
            if unexpected:
                problems.append(
                    f"family {family.name!r}: backend(s) for undeclared arm(s): "
                    f"{', '.join(unexpected)}"
                )
        if family.name not in task_sources:
            problems.append(f"family {family.name!r}: no task source supplied")

    if problems:
        raise SuiteDefinitionError("; ".join(problems))


__all__ = [
    "FamilyOutcome",
    "SuiteFamily",
    "TransferFamilyKind",
    "TransferSuite",
    "TransferSuiteResult",
    "evaluated_transfer_scopes",
    "run_transfer_suite",
]
