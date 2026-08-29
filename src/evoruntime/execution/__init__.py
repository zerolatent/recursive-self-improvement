"""The service-side execution layer (H4): the operator plane that makes the
sandbox load-bearing.

Two modules:

* :mod:`evoruntime.execution.worker` — the dev-evaluate worker. It resolves
  its isolation backend once at construction through the H9 selection seam
  (:func:`evoruntime.sandbox.selection.resolve_isolation_backend`), stages
  candidate bytes into its own scratch root, and drives every run through the
  sandbox while handling the operational failure modes a long-lived process
  actually hits: workspaces abandoned by crashed runs, egress-proxy
  lifecycle, and partial capture failure.

* :mod:`evoruntime.execution.holdout` — the sealed-holdout evaluation
  composition: a frozen candidate is run against a *resolved* holdout (the
  resolution is the ledgered, evaluator-only gate) and the paired per-task
  results are returned for recording.

Before this package existed, ``SubprocessIsolationBackend`` was constructed
only in tests (survey §5) — no production path executed a candidate through
the sandbox. The worker is that path.
"""

from __future__ import annotations

from evoruntime.execution.holdout import (
    HoldoutEvaluation,
    evaluate_frozen_candidate,
    paired_scores_from_result,
)
from evoruntime.execution.worker import (
    DevEvaluateWorker,
    WorkerOutcome,
    WorkerRunReport,
    dev_evaluate_verdict,
    sweep_stale_workspaces,
)

__all__ = [
    "DevEvaluateWorker",
    "HoldoutEvaluation",
    "WorkerOutcome",
    "WorkerRunReport",
    "dev_evaluate_verdict",
    "evaluate_frozen_candidate",
    "paired_scores_from_result",
    "sweep_stale_workspaces",
]
