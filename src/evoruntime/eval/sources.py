"""Where the harness gets its tasks — and where it refuses to.

The trust boundary shows up in this module as a plain refusal. D5 already
withholds a sealed partition's locator from every role, so the harness
*cannot* accidentally read holdout content through `list_partitions`. This
module adds the second half: it will not even look. A sealed partition
raises before any storage is touched, whoever is asking, because the only
sanctioned route to holdout content is a ledgered
`HoldoutService.resolve` that spends alpha — and the harness is not that
caller and has no code path that becomes it.

Dev-partition content, by contrast, is disclosed by design: a baseline you
cannot execute is not a baseline. `PartitionTaskSource` therefore goes
through `DatasetService`, which scopes every lookup to the caller's tenant
and hands back a locator only for unsealed kinds.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Protocol

from evoruntime.core.principal import Principal
from evoruntime.datasets.partitions import PartitionKind, is_sealed
from evoruntime.datasets.schemas import PartitionSummary
from evoruntime.datasets.service import DatasetService
from evoruntime.eval.errors import SealedPartitionError, TaskSourceError
from evoruntime.eval.tasks import EvalTask

FILE_LOCATOR_SCHEME = "file://"
"""The one locator scheme Phase 0's default loader understands."""


class TaskSource(Protocol):
    """Supplies the ordered task set an experiment runs over."""

    def load(self, dataset: str, partition: PartitionKind) -> tuple[EvalTask, ...]:
        """Return the tasks for this dataset partition, in a stable order.

        Order is part of the contract: paired statistics compare arms
        task-by-task, so a source that reordered between arms would pair
        unrelated results and produce a confident number about nothing.
        """
        ...


def ensure_unsealed(partition_id: str, kind: PartitionKind) -> None:
    """Refuse a sealed partition before any content is touched.

    Raises:
        SealedPartitionError: the partition is sealed.
    """
    if is_sealed(kind):
        raise SealedPartitionError(partition_id, kind)


def validate_task_set(tasks: Iterable[EvalTask]) -> tuple[EvalTask, ...]:
    """Freeze an ordered task set, rejecting emptiness and duplicate ids.

    Duplicate ids are fatal rather than deduplicated: a task appearing
    twice would be silently double-weighted in every arm's mean and would
    break the by-task pairing the bootstrap resamples over.
    """
    ordered = tuple(tasks)
    if not ordered:
        raise TaskSourceError("task set is empty; an experiment needs at least one task")

    seen: set[str] = set()
    duplicates: set[str] = set()
    for task in ordered:
        if task.id in seen:
            duplicates.add(task.id)
        seen.add(task.id)
    if duplicates:
        raise TaskSourceError(f"duplicate task ids in task set: {', '.join(sorted(duplicates))}")
    return ordered


class InMemoryTaskSource:
    """Tasks supplied directly — the source CI and fixtures use.

    Still enforces the seal refusal. The check costs nothing and means the
    boundary holds for every source in the system rather than for the one
    that happens to talk to a database.
    """

    def __init__(self, tasks: Sequence[EvalTask]) -> None:
        self._tasks = validate_task_set(tasks)

    def load(self, dataset: str, partition: PartitionKind) -> tuple[EvalTask, ...]:
        """Return the fixed task set after refusing sealed partitions."""
        ensure_unsealed(f"{dataset}/{partition.value}", partition)
        return self._tasks


TaskLoader = Callable[[str], tuple[EvalTask, ...]]
"""Turns a partition's content locator into tasks."""


def load_jsonl_tasks(locator: str) -> tuple[EvalTask, ...]:
    """Read tasks from a JSONL file locator (`file://` or a bare path).

    One JSON object per line with `id` and `prompt`, plus optional string
    `metadata`. Object-storage locators (`object://`, as D5 records for
    evaluation-plane content) raise rather than silently returning
    nothing: Phase 0 ships no object-store client, and a task source that
    answered "no tasks" for a partition full of them would turn a missing
    capability into a quietly empty experiment.
    """
    if "://" in locator and not locator.startswith(FILE_LOCATOR_SCHEME):
        scheme = locator.split("://", 1)[0]
        raise TaskSourceError(
            f"unsupported task locator scheme {scheme!r}: the Phase 0 loader reads "
            f"{FILE_LOCATOR_SCHEME} locators; inject a TaskLoader for anything else"
        )
    path = Path(locator.removeprefix(FILE_LOCATOR_SCHEME))
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise TaskSourceError(f"could not read task file {path}: {exc}") from exc

    tasks: list[EvalTask] = []
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        tasks.append(_parse_task_line(stripped, path, number))
    return validate_task_set(tasks)


def _parse_task_line(line: str, path: Path, number: int) -> EvalTask:
    """Parse one JSONL record into a task, naming the file and line on failure."""
    try:
        record = json.loads(line)
    except json.JSONDecodeError as exc:
        raise TaskSourceError(f"{path}:{number}: not valid JSON: {exc}") from exc
    if not isinstance(record, dict):
        raise TaskSourceError(f"{path}:{number}: expected a JSON object")

    task_id = record.get("id")
    prompt = record.get("prompt")
    if not isinstance(task_id, str) or not isinstance(prompt, str):
        raise TaskSourceError(f"{path}:{number}: task records need string 'id' and 'prompt'")

    raw_metadata = record.get("metadata", {})
    if not isinstance(raw_metadata, dict):
        raise TaskSourceError(f"{path}:{number}: 'metadata' must be an object")
    metadata = {str(key): str(value) for key, value in raw_metadata.items()}
    return EvalTask(id=task_id, prompt=prompt, metadata=metadata)


class PartitionTaskSource:
    """Tasks from a governed dataset partition, via D5's access rules.

    Every lookup carries a `Principal`, so partition resolution is
    tenant-scoped by the same code path the dataset API uses — the harness
    gets no privileged read of its own. A sealed partition is refused
    twice over: D5 withholds its locator, and `ensure_unsealed` raises
    before the locator is consulted.
    """

    def __init__(
        self,
        dataset_service: DatasetService,
        principal: Principal,
        *,
        loader: TaskLoader | None = None,
    ) -> None:
        self._service = dataset_service
        self._principal = principal
        self._loader = loader if loader is not None else load_jsonl_tasks

    def load(self, dataset: str, partition: PartitionKind) -> tuple[EvalTask, ...]:
        """Resolve the partition, then load its tasks.

        Raises:
            SealedPartitionError: the resolved partition is sealed.
            TaskSourceError: no such partition, an ambiguous match, or a
                partition whose locator is withheld or unreadable.
        """
        summary = self._resolve(dataset, partition)
        ensure_unsealed(summary.id, summary.kind)
        if summary.content_locator is None:
            raise TaskSourceError(
                f"partition {summary.id} disclosed no content locator; "
                "the harness cannot run tasks it cannot read"
            )
        return validate_task_set(self._loader(summary.content_locator))

    def _resolve(self, dataset: str, partition: PartitionKind) -> PartitionSummary:
        matches = [
            summary
            for summary in self._service.list_partitions(self._principal, dataset_id=dataset)
            if summary.kind is partition
        ]
        if not matches:
            raise TaskSourceError(
                f"dataset {dataset!r} has no {partition.value} partition for tenant "
                f"{self._principal.tenant_id}"
            )
        if len(matches) > 1:
            names = ", ".join(sorted(summary.name for summary in matches))
            raise TaskSourceError(
                f"dataset {dataset!r} has {len(matches)} {partition.value} partitions "
                f"({names}); the experiment must name an unambiguous task set"
            )
        return matches[0]


__all__ = [
    "FILE_LOCATOR_SCHEME",
    "InMemoryTaskSource",
    "PartitionTaskSource",
    "TaskLoader",
    "TaskSource",
    "ensure_unsealed",
    "load_jsonl_tasks",
    "validate_task_set",
]
