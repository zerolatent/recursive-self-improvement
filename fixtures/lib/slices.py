"""Cost/latency slice annotations over the coding fixture corpus (H7).

The H5 Pareto/slice machinery groups results by task attributes; this
module is the bridge from the fixtures' per-fixture annotations to the
`EvalTask.metadata` the harness records. Every coding fixture declares
`task_type` and `difficulty` on its manifest (v2 fields); the slice keys
are the contract the H5 slices consume — owned by the runtime since H10
(`evoruntime.eval.slices`) and re-exported here so the corpus annotations
and the runtime aggregation cannot drift apart — and
`coding_fixtures_to_eval_tasks` is the single loader both the H5 slices
and the H7 transfer tests build their task sets from.
"""

from __future__ import annotations

from pathlib import Path

from evoruntime.eval.slices import (
    SLICE_COST_METRICS,
    SLICE_DIFFICULTY,
    SLICE_FAILURE_CATEGORY,
    SLICE_FIXTURE_ID,
    SLICE_KEYS,
    SLICE_LANGUAGE,
    SLICE_TASK_TYPE,
)
from evoruntime.eval.tasks import EvalTask
from fixtures.lib.schema import (
    FIXTURES_ROOT,
    CodingFixtureManifest,
    Difficulty,
    TaskType,
    discover_coding_fixtures,
    load_coding_manifest,
)

TASK_TYPE_VALUES = frozenset(t.value for t in TaskType)
DIFFICULTY_VALUES = frozenset(d.value for d in Difficulty)


def coding_slice_metadata(manifest: CodingFixtureManifest) -> dict[str, str]:
    """The slice annotation block for one coding fixture."""
    return {
        SLICE_TASK_TYPE: manifest.task_type.value,
        SLICE_DIFFICULTY: manifest.difficulty.value,
        SLICE_LANGUAGE: manifest.language,
        SLICE_FAILURE_CATEGORY: manifest.failure_category.value,
        SLICE_FIXTURE_ID: manifest.id,
    }


def coding_fixtures_to_eval_tasks(root: Path = FIXTURES_ROOT) -> list[EvalTask]:
    """Every coding fixture as an `EvalTask` carrying its slice annotations.

    The prompt is the fixture's issue text — the same text a real harness
    hands the agent — so a transfer family pointed at these tasks exercises
    the corpus, not a synthetic stand-in.
    """
    tasks: list[EvalTask] = []
    for fixture_dir in discover_coding_fixtures(root):
        manifest = load_coding_manifest(fixture_dir)
        prompt = (fixture_dir / manifest.issue_path).read_text()
        tasks.append(
            EvalTask(id=manifest.id, prompt=prompt, metadata=coding_slice_metadata(manifest))
        )
    return tasks


__all__ = [
    "DIFFICULTY_VALUES",
    "SLICE_COST_METRICS",
    "SLICE_DIFFICULTY",
    "SLICE_FAILURE_CATEGORY",
    "SLICE_FIXTURE_ID",
    "SLICE_KEYS",
    "SLICE_LANGUAGE",
    "SLICE_TASK_TYPE",
    "TASK_TYPE_VALUES",
    "coding_fixtures_to_eval_tasks",
    "coding_slice_metadata",
]
