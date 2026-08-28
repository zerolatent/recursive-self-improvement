"""Where tasks come from — and the two refusals that guard the boundary.

The trust boundary shows up here as behavior: a sealed partition is
refused before any content is touched, whoever asks, through either
source. The D5-governed source additionally proves the harness gets no
privileged read — it resolves partitions through the same tenant-scoped
`DatasetService` the API uses, with a real principal.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evoruntime.core.principal import Principal
from evoruntime.datasets.partitions import PartitionKind
from evoruntime.datasets.service import DatasetService
from evoruntime.eval import (
    EvalTask,
    InMemoryTaskSource,
    PartitionTaskSource,
    SealedPartitionError,
    TaskSourceError,
    load_jsonl_tasks,
)
from evoruntime.eval.sources import validate_task_set
from tests.eval.conftest import make_tasks


class TestSealedPartitionRefusal:
    """The trust boundary, at the task-source layer."""

    def test_in_memory_source_refuses_the_holdout(self, tasks: tuple[EvalTask, ...]) -> None:
        """Even the trivial source refuses: the boundary holds everywhere or nowhere."""
        source = InMemoryTaskSource(tasks)

        with pytest.raises(SealedPartitionError):
            source.load("ds_any", PartitionKind.HOLDOUT)

    def test_unsealed_partitions_load_normally(self, tasks: tuple[EvalTask, ...]) -> None:
        """Dev content is disclosed by design — a baseline must be runnable."""
        source = InMemoryTaskSource(tasks)

        assert source.load("ds_any", PartitionKind.DEV) == tasks


class TestValidateTaskSet:
    """The pairing contract's precondition: a stable, unique task order."""

    def test_empty_task_set_is_refused(self) -> None:
        """An experiment over zero tasks would report a mean of nothing."""
        with pytest.raises(TaskSourceError, match="empty"):
            validate_task_set([])

    def test_duplicate_ids_are_fatal_not_deduplicated(self) -> None:
        """A duplicated task would be double-weighted in every arm's mean."""
        with pytest.raises(TaskSourceError, match="duplicate"):
            validate_task_set(
                [
                    EvalTask(id="tsk_001", prompt="a"),
                    EvalTask(id="tsk_001", prompt="a"),
                ]
            )

    def test_order_is_preserved(self) -> None:
        """Paired statistics compare task-by-task; order is part of the contract."""
        tasks = make_tasks(3, prefix="tsk")

        assert [task.id for task in validate_task_set(tasks)] == [
            "tsk_000",
            "tsk_001",
            "tsk_002",
        ]


class TestLoadJsonlTasks:
    """The default file loader."""

    def _write(self, tmp_path: Path, lines: list[str]) -> str:
        path = tmp_path / "tasks.jsonl"
        path.write_text("\n".join(lines), encoding="utf-8")
        return str(path)

    def test_reads_id_prompt_and_metadata(self, tmp_path: Path) -> None:
        locator = self._write(
            tmp_path,
            [
                json.dumps(
                    {
                        "id": "tsk_001",
                        "prompt": "fix the test",
                        "metadata": {"category": "localization"},
                    }
                )
            ],
        )

        loaded = load_jsonl_tasks(locator)

        assert len(loaded) == 1
        assert loaded[0].id == "tsk_001"
        assert loaded[0].metadata == {"category": "localization"}

    def test_file_scheme_and_bare_paths_both_work(self, tmp_path: Path) -> None:
        lines = [json.dumps({"id": "tsk_001", "prompt": "p"})]
        path = tmp_path / "tasks.jsonl"
        path.write_text("\n".join(lines), encoding="utf-8")

        assert len(load_jsonl_tasks(str(path))) == 1
        assert len(load_jsonl_tasks(f"file://{path}")) == 1

    def test_blank_lines_are_skipped(self, tmp_path: Path) -> None:
        locator = self._write(
            tmp_path,
            ["", json.dumps({"id": "tsk_001", "prompt": "p"}), ""],
        )

        assert len(load_jsonl_tasks(locator)) == 1

    def test_object_store_schemes_are_refused_not_silently_empty(self) -> None:
        """A loader that answered "no tasks" for object storage would turn a
        missing capability into a quietly empty experiment."""
        with pytest.raises(TaskSourceError, match="object"):
            load_jsonl_tasks("object://traces/dev/tasks.jsonl")

    def test_missing_file_is_a_typed_error(self, tmp_path: Path) -> None:
        with pytest.raises(TaskSourceError, match="could not read"):
            load_jsonl_tasks(str(tmp_path / "absent.jsonl"))

    def test_malformed_json_names_the_file_and_line(self, tmp_path: Path) -> None:
        locator = self._write(tmp_path, ["{not json"])

        with pytest.raises(TaskSourceError, match="tasks.jsonl:1"):
            load_jsonl_tasks(locator)

    def test_non_object_records_are_refused(self, tmp_path: Path) -> None:
        locator = self._write(tmp_path, ['["a", "list"]'])

        with pytest.raises(TaskSourceError, match="expected a JSON object"):
            load_jsonl_tasks(locator)

    def test_records_without_string_id_and_prompt_are_refused(self, tmp_path: Path) -> None:
        locator = self._write(tmp_path, [json.dumps({"id": 7, "prompt": "p"})])

        with pytest.raises(TaskSourceError, match="string 'id' and 'prompt'"):
            load_jsonl_tasks(locator)

    def test_non_string_metadata_values_are_coerced(self, tmp_path: Path) -> None:
        """Metadata rides as strings; a numeric category must not crash the load."""
        locator = self._write(
            tmp_path,
            [json.dumps({"id": "tsk_001", "prompt": "p", "metadata": {"priority": 2}})],
        )

        assert load_jsonl_tasks(locator)[0].metadata == {"priority": "2"}


class TestPartitionTaskSource:
    """Tasks through D5's governed access path — no privileged read."""

    def _create_partition(
        self,
        service: DatasetService,
        principal: Principal,
        *,
        kind: PartitionKind,
        locator: str,
        name: str = "dev-set",
    ) -> str:
        summary = service.create_partition(
            principal,
            dataset_id="ds_repo_repair",
            name=name,
            kind=kind,
            owner="harness",
            content_locator=locator,
            content_digest="sha256:" + "0" * 64,
            item_count=1,
        )
        return summary.id

    def test_loads_dev_partition_tasks_via_the_dataset_service(
        self,
        dataset_service: DatasetService,
        evaluator: Principal,
        tmp_path: Path,
    ) -> None:
        task_file = tmp_path / "tasks.jsonl"
        task_file.write_text(
            json.dumps({"id": "tsk_001", "prompt": "fix it"}), encoding="utf-8"
        )
        self._create_partition(
            dataset_service, evaluator, kind=PartitionKind.DEV, locator=str(task_file)
        )
        source = PartitionTaskSource(dataset_service, evaluator)

        loaded = source.load("ds_repo_repair", PartitionKind.DEV)

        assert [task.id for task in loaded] == ["tsk_001"]

    def test_sealed_partition_is_refused_even_for_its_creator(
        self,
        dataset_service: DatasetService,
        evaluator: Principal,
        tmp_path: Path,
    ) -> None:
        """The evaluator role can create a holdout but still cannot read it
        through the harness: the refusal is about the partition, not the role."""
        task_file = tmp_path / "tasks.jsonl"
        task_file.write_text(json.dumps({"id": "tsk_001", "prompt": "p"}), encoding="utf-8")
        self._create_partition(
            dataset_service, evaluator, kind=PartitionKind.HOLDOUT, locator=str(task_file)
        )
        source = PartitionTaskSource(dataset_service, evaluator)

        with pytest.raises(SealedPartitionError):
            source.load("ds_repo_repair", PartitionKind.HOLDOUT)

    def test_missing_partition_is_a_typed_error(
        self, dataset_service: DatasetService, evaluator: Principal
    ) -> None:
        source = PartitionTaskSource(dataset_service, evaluator)

        with pytest.raises(TaskSourceError, match="no dev partition"):
            source.load("ds_absent", PartitionKind.DEV)

    def test_ambiguous_partition_match_is_refused(
        self,
        dataset_service: DatasetService,
        evaluator: Principal,
        tmp_path: Path,
    ) -> None:
        """Two dev partitions in one dataset is an unresolvable task set."""
        task_file = tmp_path / "tasks.jsonl"
        task_file.write_text(json.dumps({"id": "tsk_001", "prompt": "p"}), encoding="utf-8")
        self._create_partition(
            dataset_service,
            evaluator,
            kind=PartitionKind.DEV,
            locator=str(task_file),
            name="dev-a",
        )
        self._create_partition(
            dataset_service,
            evaluator,
            kind=PartitionKind.DEV,
            locator=str(task_file),
            name="dev-b",
        )
        source = PartitionTaskSource(dataset_service, evaluator)

        with pytest.raises(TaskSourceError, match="2 dev partitions"):
            source.load("ds_repo_repair", PartitionKind.DEV)

    def test_unsealed_partitions_always_disclose_their_locator(
        self,
        dataset_service: DatasetService,
        evaluator: Principal,
        tmp_path: Path,
    ) -> None:
        """Pins the disclosure rule the None-locator refusal guards against:
        unsealed partitions are runnable by design, so their locator shows."""
        task_file = tmp_path / "tasks.jsonl"
        task_file.write_text(json.dumps({"id": "tsk_001", "prompt": "p"}), encoding="utf-8")
        self._create_partition(
            dataset_service,
            evaluator,
            kind=PartitionKind.SELECTION,
            locator=str(task_file),
            name="selection-set",
        )
        source = PartitionTaskSource(dataset_service, evaluator)

        assert source.load("ds_repo_repair", PartitionKind.SELECTION)

    def test_tenant_scoping_comes_from_the_principal(
        self,
        dataset_service: DatasetService,
        evaluator: Principal,
        foreign_evaluator: Principal,
        tmp_path: Path,
    ) -> None:
        """Another tenant's partitions are invisible, per D5's tenancy rule."""
        task_file = tmp_path / "tasks.jsonl"
        task_file.write_text(json.dumps({"id": "tsk_001", "prompt": "p"}), encoding="utf-8")
        self._create_partition(
            dataset_service, evaluator, kind=PartitionKind.DEV, locator=str(task_file)
        )
        source = PartitionTaskSource(dataset_service, foreign_evaluator)

        with pytest.raises(TaskSourceError, match="no dev partition"):
            source.load("ds_repo_repair", PartitionKind.DEV)
