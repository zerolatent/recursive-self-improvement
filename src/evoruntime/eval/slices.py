"""Cost/latency slice reporting over attested metrics (H10 → H5).

The H5 archive groups candidates by task attributes; this module is the
runtime-side half of that contract. The closed slice-key vocabulary lives
here (the fixture library re-exports it, so the corpus annotations and
the runtime aggregation cannot drift apart), and the aggregation is a
pure function from `TaskRun` records plus `EvalTask` metadata to
per-slice cost/latency summaries.

The reported costs are the attested vocabulary: `mean_total_tokens` is
itself a member of `COST_METRIC_KEYS` (`evoruntime.core.metrics`), and
`wall_clock_s` is the attested key whose per-run mean the aggregate
carries — plus the success rate that gives the slices their outcome
reading. A slice summary is therefore built from the same numbers the
campaign's statistics consume — no side channel, no unattested metric.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from statistics import mean

from evoruntime.eval.results import ArmSummary, ExperimentResult
from evoruntime.eval.tasks import EvalTask, TaskRun

SLICE_TASK_TYPE = "task_type"
SLICE_DIFFICULTY = "difficulty"
SLICE_LANGUAGE = "language"
SLICE_FAILURE_CATEGORY = "failure_category"
SLICE_FIXTURE_ID = "fixture_id"

SLICE_KEYS = (
    SLICE_TASK_TYPE,
    SLICE_DIFFICULTY,
    SLICE_LANGUAGE,
    SLICE_FAILURE_CATEGORY,
    SLICE_FIXTURE_ID,
)
"""The closed slice-key vocabulary the H5 slices consume.

A task contributes to a slice only for keys it declares in its metadata;
a key a task does not carry groups nothing for that task. New keys are a
code change here (reviewed as a spec change), never runtime values.
"""

SLICE_COST_METRICS = ("mean_total_tokens", "wall_clock_s")
"""The COST_METRIC_KEYS every slice aggregate is built from.

`mean_total_tokens` is attested verbatim; `wall_clock_s` is the attested
key whose per-run mean the aggregate reports as `mean_wall_clock_s`.
"""


@dataclass(frozen=True, slots=True)
class SliceAggregate:
    """One (slice key, value) bucket's cost/latency summary."""

    slice_key: str
    slice_value: str
    runs: int
    success_rate: float
    mean_input_tokens: float
    mean_output_tokens: float
    mean_tool_calls: float
    mean_wall_clock_s: float

    @property
    def mean_total_tokens(self) -> float:
        """Input plus output, per run — the attested headline cost."""
        return self.mean_input_tokens + self.mean_output_tokens


def task_slice_index(
    tasks: Iterable[EvalTask], *, keys: Sequence[str] = SLICE_KEYS
) -> dict[str, dict[str, str]]:
    """task_id → {slice_key: value} for the keys each task declares.

    Tasks with no declared keys map to an empty dict and contribute to no
    slice — an unannotated task is not silently lumped into an
    "everything else" bucket that would blur the slice's meaning.
    """
    index: dict[str, dict[str, str]] = {}
    for task in tasks:
        index[task.id] = {key: task.metadata[key] for key in keys if key in task.metadata}
    return index


def slice_aggregates(
    runs: Sequence[TaskRun],
    task_slices: Mapping[str, Mapping[str, str]],
    *,
    keys: Sequence[str] = SLICE_KEYS,
) -> tuple[SliceAggregate, ...]:
    """Aggregate runs into per-slice cost/latency summaries.

    A run contributes to a (key, value) bucket when its task declares that
    key with that value; a run whose task lacks the key is simply absent
    from that key's slices. The result is sorted by the key order given
    and then by value, so the same runs always render the same report.

    Raises:
        KeyError: a run's task_id is absent from `task_slices` — the
            caller passed runs from a different task set.
    """
    if not runs:
        return ()

    buckets: dict[tuple[str, str], list[TaskRun]] = {}
    for run in runs:
        slices = task_slices[run.task_id]
        for key in keys:
            if key in slices:
                buckets.setdefault((key, slices[key]), []).append(run)

    order = {key: position for position, key in enumerate(keys)}
    return tuple(
        _aggregate(slice_key, slice_value, bucket)
        for (slice_key, slice_value), bucket in sorted(
            buckets.items(), key=lambda item: (order[item[0][0]], item[0][1])
        )
    )


def arm_slice_report(
    arm: ArmSummary,
    tasks: Iterable[EvalTask],
    *,
    keys: Sequence[str] = SLICE_KEYS,
) -> tuple[SliceAggregate, ...]:
    """One arm's runs, sliced by task attributes."""
    return slice_aggregates(arm.runs, task_slice_index(tasks, keys=keys), keys=keys)


def experiment_slice_report(
    result: ExperimentResult,
    tasks: Iterable[EvalTask],
    *,
    keys: Sequence[str] = SLICE_KEYS,
) -> dict[str, tuple[SliceAggregate, ...]]:
    """Every arm's slice report, keyed by arm id — the H5 archive's input."""
    return {
        arm_id: arm_slice_report(arm, tasks, keys=keys)
        for arm_id, arm in sorted(result.primary.items())
    }


def render_slice_report(report: Mapping[str, Sequence[SliceAggregate]]) -> str:
    """Deterministic text rendering, one line per slice, arms in id order."""
    lines: list[str] = []
    for arm_id, aggregates in report.items():
        lines.append(f"arm {arm_id}:")
        for aggregate in aggregates:
            lines.append(
                f"  {aggregate.slice_key}={aggregate.slice_value}: "
                f"runs={aggregate.runs} "
                f"success={aggregate.success_rate:.3f} "
                f"tokens={aggregate.mean_total_tokens:.1f} "
                f"wall={aggregate.mean_wall_clock_s:.2f}s"
            )
    return "\n".join(lines)


def _aggregate(slice_key: str, slice_value: str, bucket: list[TaskRun]) -> SliceAggregate:
    """One bucket's runs → its summary. The bucket is never empty."""
    return SliceAggregate(
        slice_key=slice_key,
        slice_value=slice_value,
        runs=len(bucket),
        success_rate=mean([run.score for run in bucket]),
        mean_input_tokens=mean([float(run.usage.input_tokens) for run in bucket]),
        mean_output_tokens=mean([float(run.usage.output_tokens) for run in bucket]),
        mean_tool_calls=mean([float(run.usage.tool_calls) for run in bucket]),
        mean_wall_clock_s=mean([run.usage.wall_clock_s for run in bucket]),
    )


__all__ = [
    "SLICE_COST_METRICS",
    "SLICE_DIFFICULTY",
    "SLICE_FAILURE_CATEGORY",
    "SLICE_FIXTURE_ID",
    "SLICE_KEYS",
    "SLICE_LANGUAGE",
    "SLICE_TASK_TYPE",
    "SliceAggregate",
    "arm_slice_report",
    "experiment_slice_report",
    "render_slice_report",
    "slice_aggregates",
    "task_slice_index",
]
