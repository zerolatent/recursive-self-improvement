"""The H4 holdout-evaluation composition: frozen candidate vs. resolved holdout.

The pieces existed — :class:`HoldoutService` (the only ledgered route to
sealed content) and :func:`run_experiment` (the matched-budget harness) —
but nothing wired them. These tests pin the seam's discipline:

* the resolution happens **first** and is ledgered before any task runs;
* a non-evaluator principal is denied (and the denial ledgered) before any
  task runs;
* the paired scores come back aligned per task, in the experiment's
  canonical order — the pairing the promotion bootstrap resamples.
"""

from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal

import pytest

from evoruntime.core.principal import Principal
from evoruntime.datasets.errors import HoldoutAccessDeniedError
from evoruntime.datasets.service import HoldoutService
from evoruntime.eval import (
    EvalTask,
    FrozenClock,
    InMemoryTaskSource,
    ScriptedAgent,
)
from evoruntime.execution.holdout import (
    HoldoutEvaluation,
    evaluate_frozen_candidate,
    paired_scores_from_result,
)
from tests.eval.conftest import make_tasks, scripted_outcomes, three_arm_experiment

pytestmark = pytest.mark.usefixtures("session_factory")

CANDIDATE_ARM = "retry"  # the three-arm experiment's first candidate arm


def _backends(
    tasks: tuple[EvalTask, ...], *, incumbent_successes: int, candidate_successes: int
) -> Mapping[str, ScriptedAgent]:
    """One scripted backend per declared arm; candidate and incumbent differ."""
    return {
        "incumbent": ScriptedAgent(scripted_outcomes(tasks, incumbent_successes)),
        CANDIDATE_ARM: ScriptedAgent(scripted_outcomes(tasks, candidate_successes)),
        "one-shot": ScriptedAgent(scripted_outcomes(tasks, incumbent_successes)),
    }


def _evaluate(
    holdout_service: HoldoutService,
    principal: Principal,
    handle_uri: str,
    purpose: str,
    tasks: tuple[EvalTask, ...],
) -> HoldoutEvaluation:
    return evaluate_frozen_candidate(
        holdout_service=holdout_service,
        principal=principal,
        handle_uri=handle_uri,
        purpose=purpose,
        experiment=three_arm_experiment(name="h4-holdout-composition"),
        backends=_backends(tasks, incumbent_successes=6, candidate_successes=9),
        task_source=InMemoryTaskSource(tasks),
        clock_factory=lambda: FrozenClock(),
    )


def test_resolution_is_ledgered_before_the_harness_runs(
    holdout_service: HoldoutService,
    evaluator: Principal,
    issued_handle: object,
) -> None:
    """The ledgered resolution is the gate: exactly one grant row for the run."""
    tasks = make_tasks()
    evaluation = _evaluate(
        holdout_service, evaluator, issued_handle.handle_uri, "h4 frozen-candidate scoring", tasks
    )

    ledger = holdout_service.read_ledger(evaluator, evaluation.handle_uri)
    assert len(ledger) == 1
    assert ledger[0].purpose == "h4 frozen-candidate scoring"
    assert ledger[0].alpha_spent == Decimal("0.01")


def test_non_evaluator_is_denied_before_any_task_runs(
    holdout_service: HoldoutService,
    evaluator: Principal,
    candidate_runner: Principal,
    issued_handle: object,
) -> None:
    """A candidate-runner principal never reaches the harness (D5 IAM)."""
    tasks = make_tasks()
    with pytest.raises(HoldoutAccessDeniedError):
        _evaluate(
            holdout_service,
            candidate_runner,
            issued_handle.handle_uri,
            "should never happen",
            tasks,
        )

    # The denial is evidence, not silence: one ledger row, no alpha spent.
    ledger = holdout_service.read_ledger(evaluator, issued_handle.handle_uri)
    assert len(ledger) == 1
    assert ledger[0].denial_reason is not None
    report = holdout_service.budget_report(evaluator, issued_handle.handle_uri)
    assert report.spent == Decimal("0")


def test_paired_scores_are_aligned_in_canonical_order(
    holdout_service: HoldoutService,
    evaluator: Principal,
    issued_handle: object,
) -> None:
    """The pairing the bootstrap resamples: per-task, incumbent vs. candidate."""
    tasks = make_tasks()
    evaluation = _evaluate(
        holdout_service, evaluator, issued_handle.handle_uri, "paired scoring", tasks
    )

    paired = evaluation.paired
    assert paired.task_ids == evaluation.result.task_ids
    assert len(paired.baseline) == len(paired.candidate) == len(paired.task_ids)
    # The scripts make the direction a property of the data: the candidate
    # arm succeeds on strictly more tasks than the incumbent.
    assert sum(paired.candidate) > sum(paired.baseline)


def test_paired_scores_helper_matches_evaluation_order(
    holdout_service: HoldoutService,
    evaluator: Principal,
    issued_handle: object,
) -> None:
    """aligned_scores fills the experiment's canonical task order, not run order."""
    tasks = make_tasks()
    evaluation = _evaluate(
        holdout_service, evaluator, issued_handle.handle_uri, "order check", tasks
    )

    rebuilt = paired_scores_from_result(
        evaluation.result,
        incumbent_arm_id="incumbent",
        candidate_arm_id=CANDIDATE_ARM,
    )
    assert rebuilt.task_ids == evaluation.paired.task_ids
    assert rebuilt.baseline == evaluation.paired.baseline
    assert rebuilt.candidate == evaluation.paired.candidate


def test_one_resolution_spends_exactly_one_query_of_alpha(
    holdout_service: HoldoutService,
    evaluator: Principal,
    issued_handle: object,
) -> None:
    """A whole frozen-candidate evaluation costs one resolution's alpha."""
    tasks = make_tasks()
    _evaluate(holdout_service, evaluator, issued_handle.handle_uri, "budget check", tasks)

    report = holdout_service.budget_report(evaluator, issued_handle.handle_uri)
    assert report.spent == Decimal("0.01")
    assert report.remaining == Decimal("0.03")
