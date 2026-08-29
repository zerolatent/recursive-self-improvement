"""Evaluation-metric vocabularies shared across planes.

`COST_METRIC_KEYS` is the closed vocabulary of metric keys the runtime
treats as *costs* — quantities where lower is better. It was previously
defined in the campaign API service; FR-102 (productivity-aware lineage
selection) needs the same vocabulary in the selection plane, and a
vocabulary two planes must agree on cannot live in either of them. The
frozenset here is the single source of truth; the API module re-exports it.

The vocabulary is closed at spec time: a new cost metric is a code change
to this tuple, reviewed as a spec change — never a runtime value a caller
can inject.
"""

from __future__ import annotations

#: Metric keys the runtime reports as *costs* rather than gains or
#: regressions: spending more tokens, dollars, or wall clock than the
#: parent is a regression, spending less is a gain. Everything else is
#: compared against the parent and split by the sign of its delta.
COST_METRIC_KEYS = frozenset(
    {"tokens", "total_tokens", "mean_total_tokens", "cost_usd", "wall_clock_s"}
)

__all__ = ["COST_METRIC_KEYS"]
