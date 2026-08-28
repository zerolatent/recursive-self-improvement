"""D5 conformance: holdout-handle resolution and alpha-spend under multi-process contention.

The D5 deliverable's own tests verify row-lock correctness single-process:
one caller, sequential resolutions, one session. That cannot see a lost
update, which only exists when two independent database sessions read the
same handle row before either commits. This module closes that gap the only
way it can be closed — with real OS processes, each owning its own
connections and session cache, racing through the real `HoldoutService.resolve`
path against one shared alpha budget.

Two properties, both required:

1. **Exhaustion under contention.** A budget sized for exactly four grants
   is hit by sixteen attempts from eight processes. Whatever the interleaving,
   exactly four attempts may be granted: no lost update may overspend the
   budget, and no over-strict lock may under-spend it. Every attempt —
   granted or denied — leaves exactly one ledger row, and the final budget
   report must equal the ledger's own accounting.
2. **No lost updates with room to spare.** Sixteen attempts from eight
   processes against a budget that can absorb all of them must produce
   sixteen grants and an exactly-consistent spend. This is the direction a
   naive read-modify-write breaks first: two processes both read `spent=0.05`,
   both write `0.06`, and a grant vanishes without the budget ever going
   negative.
"""

from __future__ import annotations

import json
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import pytest

from evoruntime.core.principal import Principal
from evoruntime.datasets.models import LedgerOutcome
from evoruntime.datasets.partitions import PartitionKind
from evoruntime.datasets.schemas import IssuedHoldoutHandle, PartitionSummary
from evoruntime.datasets.service import DatasetService, HoldoutService

WORKER_SCRIPT = Path(__file__).parent / "holdout_contention_worker.py"

PROCESSES = 8
ATTEMPTS_PER_PROCESS = 2
TOTAL_ATTEMPTS = PROCESSES * ATTEMPTS_PER_PROCESS
GRANT_FLOOR = 4  # budget 0.04 / per-query 0.01 — exactly four reads exist


def _spawn_workers(
    *,
    database_url: str,
    handle_uri: str,
    tenant_id: str,
    attempts: int,
    tmp_path: Path,
) -> list[list[dict[str, str]]]:
    """Launch `PROCESSES` workers concurrently and return each one's records."""
    output_paths = [tmp_path / f"worker-{index}.jsonl" for index in range(PROCESSES)]
    procs = [
        subprocess.Popen(  # noqa: S603 - fixed argv, no shell, test-only
            [
                sys.executable,
                str(WORKER_SCRIPT),
                f"--database-url={database_url}",
                f"--handle-uri={handle_uri}",
                f"--tenant-id={tenant_id}",
                f"--subject=svc_evaluator_{index}",
                f"--attempts={attempts}",
                f"--output-path={output_path}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for index, output_path in enumerate(output_paths)
    ]

    failures: list[str] = []
    for index, proc in enumerate(procs):
        _, stderr = proc.communicate(timeout=120)
        if proc.returncode != 0:
            failures.append(f"worker {index} exited {proc.returncode}: {stderr.decode()}")
    if failures:
        raise AssertionError("contention workers failed:\n" + "\n".join(failures))

    return [
        [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines() if line]
        for output_path in output_paths
    ]


@pytest.fixture
def contention_handle(
    dataset_service: DatasetService,
    holdout_service: HoldoutService,
    evaluator: Principal,
) -> IssuedHoldoutHandle:
    """A sealed holdout partition with a handle budgeted for exactly four grants."""
    partition: PartitionSummary = dataset_service.create_partition(
        evaluator,
        dataset_id="ds_conformance_v1",
        name="concurrency-holdout",
        kind=PartitionKind.HOLDOUT,
        owner="eval-team",
        content_locator="object://evaluation-plane/holdout/conformance-v1",
        content_digest="sha256:" + "c" * 64,
        item_count=40,
    )
    return holdout_service.issue_handle(
        evaluator,
        partition_id=partition.id,
        owner="eval-team",
        alpha_budget_total=Decimal("0.04"),
        alpha_per_query=Decimal("0.01"),
        freshness_window_days=30,
        rotation_plan="rotate-quarterly",
        contamination_audit={"source": "conformance", "contaminated": False},
    )


def test_contention_never_overspends_or_underspends_the_alpha_budget(
    database_url: str,
    holdout_service: HoldoutService,
    evaluator: Principal,
    tenant_id: str,
    contention_handle: IssuedHoldoutHandle,
    tmp_path: Path,
) -> None:
    records = _spawn_workers(
        database_url=database_url,
        handle_uri=contention_handle.handle_uri,
        tenant_id=tenant_id,
        attempts=ATTEMPTS_PER_PROCESS,
        tmp_path=tmp_path,
    )
    flat = [record for worker_records in records for record in worker_records]

    # Every attempt the workers were asked to make actually happened.
    assert len(flat) == TOTAL_ATTEMPTS

    granted = [record for record in flat if record["outcome"] == "granted"]
    denied = [record for record in flat if record["outcome"] == "denied"]
    assert len(granted) == GRANT_FLOOR, (
        f"expected exactly {GRANT_FLOOR} grants under contention, got {len(granted)} — "
        "a lost update (overspend) or an over-strict lock (underspend)"
    )
    assert len(denied) == TOTAL_ATTEMPTS - GRANT_FLOOR
    assert all(record["denial_reason"] == "alpha_budget_exhausted" for record in denied), (
        "any denial under contention must be a budget exhaustion, not a lock or transport error"
    )

    # One ledger row per attempt, granted or denied — no attempt vanishes.
    entries = holdout_service.read_ledger(evaluator, contention_handle.handle_uri)
    assert len(entries) == TOTAL_ATTEMPTS
    assert (
        len([entry for entry in entries if entry.outcome is LedgerOutcome.GRANTED]) == GRANT_FLOOR
    )
    assert len([entry for entry in entries if entry.outcome is LedgerOutcome.DENIED]) == (
        TOTAL_ATTEMPTS - GRANT_FLOOR
    )

    # The budget report and the ledger must tell the same story.
    report = holdout_service.budget_report(evaluator, contention_handle.handle_uri)
    assert report.spent == Decimal("0.04")
    assert report.remaining == Decimal("0.00")
    assert report.queries_remaining == 0
    ledger_grant_spend = sum(
        (entry.alpha_spent for entry in entries if entry.outcome is LedgerOutcome.GRANTED),
        Decimal("0"),
    )
    assert ledger_grant_spend == report.spent


def test_concurrent_grants_with_headroom_lose_no_updates(
    database_url: str,
    dataset_service: DatasetService,
    holdout_service: HoldoutService,
    evaluator: Principal,
    tenant_id: str,
    tmp_path: Path,
) -> None:
    """Ample budget: every concurrent grant must land — no update is lost."""
    partition = dataset_service.create_partition(
        evaluator,
        dataset_id="ds_conformance_v2",
        name="headroom-holdout",
        kind=PartitionKind.HOLDOUT,
        owner="eval-team",
        content_locator="object://evaluation-plane/holdout/conformance-v2",
        content_digest="sha256:" + "d" * 64,
        item_count=40,
    )
    handle = holdout_service.issue_handle(
        evaluator,
        partition_id=partition.id,
        owner="eval-team",
        alpha_budget_total=Decimal("1.00"),
        alpha_per_query=Decimal("0.01"),
        freshness_window_days=30,
        rotation_plan="rotate-quarterly",
        contamination_audit={"source": "conformance", "contaminated": False},
    )

    records = _spawn_workers(
        database_url=database_url,
        handle_uri=handle.handle_uri,
        tenant_id=tenant_id,
        attempts=ATTEMPTS_PER_PROCESS,
        tmp_path=tmp_path,
    )
    flat = [record for worker_records in records for record in worker_records]

    assert len(flat) == TOTAL_ATTEMPTS
    assert all(record["outcome"] == "granted" for record in flat), (
        "with budget for every attempt, contention must not manufacture denials"
    )

    report = holdout_service.budget_report(evaluator, handle.handle_uri)
    assert report.spent == Decimal("0.16"), (
        f"lost update under concurrent grants: spent {report.spent}, expected 0.16"
    )
    assert report.remaining == Decimal("0.84")
    assert report.queries_remaining == 84

    entries = holdout_service.read_ledger(evaluator, handle.handle_uri)
    assert len(entries) == TOTAL_ATTEMPTS
    assert all(entry.outcome is LedgerOutcome.GRANTED for entry in entries)
