"""Sealed-holdout evaluation (H4): the frozen candidate vs. the resolved holdout.

§17.1 step 7's composition. The pieces already existed —
:class:`evoruntime.datasets.service.HoldoutService` (the only ledgered route
to sealed content) and :func:`evoruntime.eval.runner.run_experiment` (the
matched-budget harness) — but nothing wired them together: the holdout plane
had no harness call site, and the harness refused sealed partitions by
construction. This module is the seam between them, and the discipline it
enforces is the point:

* **Resolve first, always.** The holdout is resolved through
  :meth:`HoldoutService.resolve` *before* any task runs — the resolution is
  the ledgered, alpha-spending, evaluator-only gate, and an evaluation that
  never resolved has no business having run. Non-evaluator roles are denied
  by the service itself and the denial is ledgered; this module adds
  nothing on top.

* **Paired results, aligned per task.** The output is a
  :class:`~evoruntime.selection.policy.PairedScores` over the incumbent and
  the first candidate arm, in the experiment's canonical task order — the
  same pairing the promotion policy's bootstrap resamples. A holdout run
  that produced unpaired numbers would not be usable evidence, so the
  pairing is built here, once, from the arm summaries the harness already
  computed.

Recording the paired results is the caller's explicit act (a signed
evaluation attestation via the control plane) — this module returns the
evidence; it does not silently write verdicts.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from evoruntime.core.principal import Principal
from evoruntime.datasets.schemas import HoldoutContentRef
from evoruntime.datasets.service import HoldoutService
from evoruntime.eval.backends import AgentBackend
from evoruntime.eval.experiment import Experiment
from evoruntime.eval.results import ExperimentResult, aligned_scores
from evoruntime.eval.runner import ClockFactory, run_experiment
from evoruntime.eval.sources import TaskSource
from evoruntime.selection.policy import PairedScores


@dataclass(frozen=True, slots=True)
class HoldoutEvaluation:
    """One frozen-candidate run against one resolved sealed holdout."""

    handle_uri: str
    content_ref: HoldoutContentRef
    result: ExperimentResult
    paired: PairedScores


def paired_scores_from_result(
    result: ExperimentResult,
    *,
    incumbent_arm_id: str,
    candidate_arm_id: str,
) -> PairedScores:
    """Build the paired per-task scores one promotion comparison needs.

    Task order is the experiment's canonical order (the incumbent's
    first-seen sequence), and both score vectors are aligned to it — the
    pairing the bootstrap's validity depends on.
    """
    baseline = aligned_scores(result.primary[incumbent_arm_id], result.task_ids)
    candidate = aligned_scores(result.primary[candidate_arm_id], result.task_ids)
    return PairedScores(task_ids=result.task_ids, baseline=baseline, candidate=candidate)


def evaluate_frozen_candidate(
    *,
    holdout_service: HoldoutService,
    principal: Principal,
    handle_uri: str,
    purpose: str,
    experiment: Experiment,
    backends: Mapping[str, AgentBackend],
    task_source: TaskSource,
    clock_factory: ClockFactory | None = None,
) -> HoldoutEvaluation:
    """Run a frozen candidate against a resolved sealed holdout.

    The resolution happens first and is ledgered; only then does the
    harness run the experiment over the holdout's tasks. ``backends`` is a
    mapping of arm id to backend (passed through to the runner, which
    refuses unmatched arms); ``task_source`` is any
    :class:`~evoruntime.eval.sources.TaskSource` — loading sealed content
    is the caller's composed responsibility, reached only through the
    resolution above.

    Raises:
        HoldoutAccessDeniedError: the caller is not an evaluator-role
            principal in the handle's tenant (denied and ledgered by the
            service, before any task runs).
    """
    # The gate: ledgered, alpha-spending, evaluator-only. Everything after
    # this line only runs because the resolution succeeded.
    content_ref = holdout_service.resolve(principal, handle_uri, purpose=purpose)

    result = run_experiment(
        experiment,
        backends=backends,
        task_source=task_source,
        clock_factory=clock_factory,
    )
    candidate_arms = experiment.candidate_arms
    if not candidate_arms:
        raise ValueError(
            f"experiment {experiment.name!r} declares no candidate arm; "
            "a holdout evaluation compares a frozen candidate to the incumbent"
        )
    paired = paired_scores_from_result(
        result,
        incumbent_arm_id=experiment.incumbent.id,
        candidate_arm_id=candidate_arms[0].id,
    )
    return HoldoutEvaluation(
        handle_uri=handle_uri,
        content_ref=content_ref,
        result=result,
        paired=paired,
    )
