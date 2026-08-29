"""Self-edit conformance as a pinned stage-0 cascade evaluator (Phase 3, G2).

Scaffold mutation lets a candidate rewrite the code that evaluates it. The
counterweight is a stage-0 gate that runs the scaffold's own conformance
suite against the *mutated* scaffold, in-sandbox, before any more expensive
stage is allowed to spend its budget on the candidate. Three properties are
load-bearing, and each is pinned here rather than configured:

**Stage 0, short-circuiting.** The evaluator always projects a
:class:`~evoruntime.eval.cascade.CascadeStage` at stage 0 with
``short_circuit=True`` — the cheapest tier, first in the cascade, and a
failure here stops the cascade outright. A candidate that breaks the
scaffold's own conformance suite has already failed; later stages would
be measuring a broken runtime.

**Zero regressions required.** The scaffold ships with a green conformance
suite — that is the invariant that makes "regression" well-defined. Every
failing test against the mutated scaffold is therefore a regression the
candidate introduced, and one regression is enough to fail the stage.
There is no tolerance knob: a mutation campaign that needs one should not
be running.

**Early exit is a measured failure, not a skip.** A suite that cannot run
— sandbox error, timeout, crash before the summary line, output that
cannot be parsed — fails the stage, because "the conformance suite could
not prove zero regressions" and "there are no regressions" are different
claims, and only the first one is honest. This matches the cascade's
scoring contract: a short-circuited cascade scores the candidate arm as a
measured failure on every task (:meth:`~evoruntime.eval.cascade.
CascadeResult.candidate_scores`), never as a shorter sample.

The evaluator is pure with respect to execution: it owns pinning, command
construction, output interpretation, and the zero-regression rule, while
the actual in-sandbox run is delegated to a :class:`ConformanceSuiteRunner`
the caller wires (the sandbox executor stages the mutated scaffold; the
evaluator only ever sees the run's result). That split is what makes the
regression-rejection semantics unit-testable without a sandbox.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Protocol

from evoruntime.eval.cascade import CascadeStage, EvaluatorCostClass, StageOutcome
from evoruntime.eval.errors import CascadeDefinitionError

CONFORMANCE_STAGE_NUMBER = 0
"""The pinned cascade position: conformance is always the cheapest tier."""

CONFORMANCE_STAGE_NAME = "self_edit_conformance"
"""The pinned stage name — attestation metrics and ledger purposes key on it."""

#: pytest's terminal summary line, e.g. ``5 failed, 118 passed in 2.31s``.
_PYTEST_SUMMARY = re.compile(r"(?:(\d+) failed)?[^0-9]*(?:(\d+) passed)?")


class ConformanceSuiteRunner(Protocol):
    """What executes the conformance suite against the mutated scaffold.

    Implementations run in-sandbox: the contract is that ``command`` is
    executed against the *mutated* scaffold working copy, with the
    suite's own exit code, streams, and timeout status returned intact.
    A runner that cannot run the suite returns ``timed_out=True`` or a
    ``returncode`` of None — the evaluator scores both as measured
    failures, never as passes.
    """

    def run(self, command: tuple[str, ...]) -> SuiteRunResult: ...


@dataclass(frozen=True, slots=True)
class SuiteRunResult:
    """The raw outcome of one in-sandbox suite run."""

    returncode: int | None
    """The suite process's exit code; None when it never exited cleanly."""

    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    """True when the sandbox killed the run for exceeding its time limit."""


def parse_pytest_summary(stdout: str) -> tuple[int, int] | None:
    """Extract ``(failed, passed)`` counts from a pytest summary line.

    Returns None when the output carries no parseable summary — the
    evaluator treats that as "could not prove zero regressions" and fails
    closed, rather than guessing from an exit code alone.
    """
    failed: int | None = None
    passed: int | None = None
    for line in stdout.splitlines():
        match = _PYTEST_SUMMARY.search(line)
        if match and (match.group(1) or match.group(2)):
            failed = int(match.group(1) or 0)
            passed = int(match.group(2) or 0)
    if failed is None and passed is None:
        return None
    # A summary that names only one side is still a summary: pytest prints
    # "3 failed in 1.0s" when nothing passed, and the missing side is zero.
    return failed or 0, passed or 0


class SelfEditConformanceEvaluator:
    """The pinned stage-0 evaluator: the scaffold's suite vs the mutation.

    Constructed with the suite command and the in-sandbox runner, both
    pinned for the evaluator's lifetime — a conformance gate whose suite
    could be swapped mid-campaign would be a gate that could be talked
    out of gating. :meth:`evaluate` satisfies the cascade's
    ``StageEvaluator`` protocol but refuses any stage other than its own
    pinned stage-0 identity: the stage this evaluator runs is part of the
    pin, not a per-call choice.
    """

    def __init__(
        self,
        *,
        suite_command: tuple[str, ...],
        runner: ConformanceSuiteRunner,
        name: str = CONFORMANCE_STAGE_NAME,
    ) -> None:
        if not suite_command:
            raise CascadeDefinitionError(
                "a conformance evaluator needs a non-empty suite command — "
                "an empty command runs nothing and proves nothing"
            )
        self.suite_command = suite_command
        self.runner = runner
        self.stage = CascadeStage(
            name=name,
            stage=CONFORMANCE_STAGE_NUMBER,
            cost_class=EvaluatorCostClass.CHEAP,
            short_circuit=True,
        )

    def evaluate(self, stage: CascadeStage) -> StageOutcome:
        """Run the pinned suite against the mutated scaffold; zero regressions pass.

        Raises:
            CascadeDefinitionError: ``stage`` is not this evaluator's pinned
                stage — a conformance verdict must never be attributed to a
                stage position it was not pinned to.
        """
        if stage.stage != self.stage.stage or stage.name != self.stage.name:
            raise CascadeDefinitionError(
                f"conformance evaluator is pinned to stage "
                f"{self.stage.stage} ({self.stage.name!r}), was asked to evaluate "
                f"stage {stage.stage} ({stage.name!r})"
            )
        run = self.runner.run(self.suite_command)
        return self._interpret(run)

    def _interpret(self, run: SuiteRunResult) -> StageOutcome:
        """Turn one suite run into a stage outcome — fail closed throughout.

        Every not-proven-safe path (timeout, no exit, nonzero exit,
        unparseable summary, zero tests collected) is a measured failure
        with the reason in the metrics, so an early exit is attributable
        from the attestation alone.
        """
        summary = parse_pytest_summary(run.stdout)
        failed = summary[0] if summary is not None else -1
        passed = summary[1] if summary is not None else -1
        metrics: dict[str, float] = {
            "suite_timed_out": 1.0 if run.timed_out else 0.0,
            "suite_exit_code": float(run.returncode) if run.returncode is not None else -1.0,
            "suite_summary_parsed": 1.0 if summary is not None else 0.0,
            "tests_failed": float(failed),
            "tests_passed": float(passed),
            "regressions": float(max(failed, 0)),
        }
        if run.timed_out:
            return StageOutcome(False, {**metrics, "failure_reason": 1.0})  # suite timeout
        if run.returncode is None:
            return StageOutcome(False, {**metrics, "failure_reason": 2.0})  # no exit recorded
        if "no tests ran" in run.stdout:
            # pytest's exit code 5: the suite collected nothing. Nothing ran,
            # so nothing was proven — a measured failure, not a pass.
            return StageOutcome(False, {**metrics, "failure_reason": 5.0})
        if summary is None:
            return StageOutcome(False, {**metrics, "failure_reason": 3.0})  # unparseable output
        if failed > 0:
            return StageOutcome(False, {**metrics, "failure_reason": 4.0})  # regressions
        if passed < 1:
            return StageOutcome(False, {**metrics, "failure_reason": 5.0})  # no tests ran
        if run.returncode != 0:
            return StageOutcome(False, {**metrics, "failure_reason": 6.0})  # exit/summary disagree
        return StageOutcome(True, metrics)


def run_self_edit_conformance(
    evaluator: SelfEditConformanceEvaluator,
) -> tuple[CascadeStage, StageOutcome]:
    """Run the pinned conformance stage on its own — the single-stage cascade.

    Convenience for callers that want the conformance verdict without
    composing a full cascade: the stage and its outcome are exactly what
    :func:`evoruntime.eval.cascade.run_cascade` would produce for a
    one-stage cascade, so early exits carry the same measured-failure
    semantics either way.
    """
    return evaluator.stage, evaluator.evaluate(evaluator.stage)


__all__ = [
    "CONFORMANCE_STAGE_NAME",
    "CONFORMANCE_STAGE_NUMBER",
    "ConformanceSuiteRunner",
    "SelfEditConformanceEvaluator",
    "SuiteRunResult",
    "parse_pytest_summary",
    "run_self_edit_conformance",
]
