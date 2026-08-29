# EvoRuntime Phase 4 — Threshold Verification (H8)

**Branch:** `feat/h8-threshold-harnesses` (based on `release/evoruntime-phase4-coding-agent-mvp-20260829-160500`)
**Date:** 2026-08-29
**Scope:** PRD §17.3 rows 1, 3, 6, and 9 — measured, not asserted. The harnesses live in `src/evoruntime/harness/` and `src/evoruntime/lineage/backup.py`; the verifying tests are `tests/test_harness_fault_injection.py`, `tests/test_harness_secrecy.py`, `tests/test_harness_load.py`, and `tests/test_backup_tier.py`.

## Headline result

Local run on the release branch against a real PostgreSQL instance: **1768 passed, 0 failed**, `ruff check` clean, `ruff format --check` clean, `mypy --strict` clean across 211 source files. Every CI-profile threshold below is a **measured** result from the harnesses themselves, not a restatement of the SLO.

## Design rule: scaled CI profiles, soak runbooks

The full-scale §17.3 runs (10M-event fault injection, 1000 concurrent candidates for 24h) cannot live in CI. Each harness therefore ships two profiles with the **same code path**:

- a **CI profile** — reduced scale, real §17.3 thresholds, runs in `uv run pytest` against the CI `postgres` service;
- a **soak profile** — the full §17.3 scale, runnable from the runbook in this document. The soak is not executed in CI and has not been executed for this report; its recorded numbers are produced by the runbook below when a dedicated run window is scheduled. This section is updated with those numbers when a soak is run.

## §17.3 row 1 — Fault-injection loss rate ≤ 0.01%

**Mechanism.** `src/evoruntime/harness/fault_injection.py` runs N sustained writer subprocesses (`src/evoruntime/harness/writer.py`, launched as `python -m evoruntime.harness.writer`) against real PostgreSQL through the real `ingest_envelope` path, one commit per event, with an fsync'd progress file per writer. Periodically the runner SIGKILLs a writer — no Python cleanup, only what Postgres durably committed survives — and immediately respawns it from the same fixture with the fsync'd progress count as resume offset. The loss rate is counted only after every writer has delivered its full fixture, so the number is never computed over an incomplete run. The per-tenant hash chain is re-verified over the delivered events.

**CI profile** (`FAULT_INJECTION_CI_PROFILE`): 4 writers × 2,500 events (10,000 total — the D2 fixture size), a kill every 800 committed events, ≤2 kills per writer. Same code path as the soak; ~8× the original `tests/test_fault_injection.py` single-writer coverage at comparable CI cost.

**Measured (2026-08-29, local PostgreSQL):** expected 10,000, delivered 10,000, lost 0, loss rate 0.0% (SLO ≤ 0.01%), 8 kills executed, chain valid, 14.8s wall clock.

**Soak profile** (`FAULT_INJECTION_SOAK_PROFILE`): 8 writers × 1,250,000 events = the full 10M-event threshold, a kill every 250,000 committed events, ≤4 kills per writer, 4h deadline.

**Soak runbook.** Against a dedicated PostgreSQL instance with WAL on durable storage:

```bash
uv run python - <<'PY'
from pathlib import Path
from evoruntime.harness.fault_injection import run_loss_rate_probe
from evoruntime.harness.profiles import FAULT_INJECTION_SOAK_PROFILE
result = run_loss_rate_probe(
    database_url="$EVORUNTIME_DATABASE_URL",
    profile=FAULT_INJECTION_SOAK_PROFILE,
    workdir=Path("./soak-fi-workdir"),
)
print(result)
assert result.within_slo()
assert result.chain_valid
PY
```

Record `expected_events`, `delivered_events`, `lost_events`, `loss_rate`, `kills_executed`, `chain_valid`, and `duration_s` in this section. **Status: not yet executed** — requires a multi-hour dedicated run window and is tracked as the Phase 4 soak follow-up.

## §17.3 row 3 — Payload-deletion backup-tier story

**Mechanism.** `src/evoruntime/lineage/backup.py` is the smallest honest version of the backup tier: a documented age-out policy (primary payloads age out after **7 days**, backup-tier copies after **35 days** — §17.3 row 3 values), a sweep that deletes entries past their deadline, and **tombstone coverage**: every deletion records a tombstone whose coverage check proves a deleted payload cannot resurface from *any* tier — a read path that finds a live row, a backup entry, or a stale cache for a tombstoned digest fails closed.

**Verifying tests:** `tests/test_backup_tier.py` — age-out deadlines per tier, sweep deletion past deadline, and the tombstone-coverage property (deleted payload refused on primary, backup, and re-registration paths).

**Crypto-erase remains an open question** per the Phase 4 spec: the backup tier here is a logical age-out + tombstone story; key-material destruction for cryptographically erased backups is deferred and tracked in the spec's open questions.

## §17.3 row 6 — Canary-token 10k secrecy suite

**Mechanism.** `src/evoruntime/harness/secrecy.py` implements the canary-token scheme following the H7 fixture concept: deterministic, HMAC-verified markers planted in holdout item content, so a token appearing anywhere a candidate can emit proves holdout content reached an emission surface — the token exists nowhere else. The harness generates ≥10,000 adversarial emissions — the §17.2 attack corpus shapes (prompt injection, secret exfiltration, destructive operation) plus paraphrase, truncation, encoding, split-across-events, and partial-echo variants — and leak-scans every emission for canary tokens and holdout labels. Zero leaks is the only passing outcome.

**CI profile** (`SECRECY_PROFILE`): 10,000 emissions over 100 holdout items — the full §17.3 row 6 threshold runs natively in CI (no reduction needed; the suite is CPU-bound and completes in seconds).

**Measured (CI, every run):** 10,000/10,000 adversarial emissions scanned, zero canary-token leaks, zero holdout-label leaks.

## §17.3 row 9 — Load: 1000 concurrent candidates / 10M events/day, ingest p99 ≤ 2s, loss ≤ 0.01%, single-worker recovery ≤ 10 min

**Mechanism.** `src/evoruntime/harness/load.py` spawns a real `uvicorn` evaluation-plane process against the configured database and N candidate worker subprocesses (`src/evoruntime/harness/load_worker.py`), each hosting concurrent candidate executions that emit through the adapter SDK's production path (journal → HTTP ingest → per-tenant hash chain). It measures the three row-9 quantities:

- **ingest p99** — client-side per-batch latency at the ingest boundary (send → server ack), nearest-rank percentile over every batch;
- **loss** — emitted (worker progress at the SDK's journal durability boundary, fsync'd) vs delivered (server-side event count). An event is "emitted" once the adapter has fsync'd it to the journal — the point the SDK's crash-flush contract protects; counting `trace.tool_call()` calls instead would race the background flusher and misreport buffer loss as ingest loss. Replay can deliver a few events journaled during the progress reporter's lag window, so delivered may slightly exceed emitted; the accounting clamps at zero.
- **single-worker recovery** — wall-clock from SIGKILL of one worker to its respawned replacement delivering again (journal replay), against the ≤10-minute threshold.

**CI profile** (`LOAD_CI_PROFILE`): 8 concurrent candidate executions (4 processes × 2 threads) × 250 events = 2,016 SDK events (2,000 tool-call events + 16 trace lifecycle events — each execution's `adapter.trace()` context emits one `trace.started` and one `trace.ended`), a single-worker SIGKILL after 400 durable events, real §17.3 thresholds (p99 ≤ 2s, loss ≤ 0.01%, recovery ≤ 600s). Ingest batches are capped at 25 events so per-request latency stays representative of an interactive candidate: the server commits each event in its own transaction, and large batches would measure client buffering, not ingest speed.

**Measured (2026-08-29, local PostgreSQL):** emitted 2,016, delivered 2,016, lost 0, loss rate 0.0% (SLO ≤ 0.01%), ingest p50 0.56s, **ingest p99 0.88s** (SLO ≤ 2s), single-worker recovery **1.25s** (SLO ≤ 600s), 7.8s wall clock.

**Soak profile** (`LOAD_SOAK_PROFILE`): 1,000 concurrent candidate executions (25 processes × 40 threads) × 10,000 events = 10M events — the §17.3 row 9 shape (10M events/day sustained, 24h horizon), one worker killed after 50,000 durable events, full thresholds (p99 ≤ 2s, loss ≤ 0.01%, recovery ≤ 600s), 24h deadline.

**Soak runbook.** On a host sized for 25 worker processes, against a dedicated PostgreSQL instance:

```bash
uv run python - <<'PY'
from pathlib import Path
from evoruntime.harness.load import run_load_probe
from evoruntime.harness.profiles import LOAD_SOAK_PROFILE
result = run_load_probe(
    database_url="$EVORUNTIME_DATABASE_URL",
    profile=LOAD_SOAK_PROFILE,
    workdir=Path("./soak-load-workdir"),
)
print(result)
assert result.within_thresholds(LOAD_SOAK_PROFILE)
PY
```

Record `emitted_events`, `delivered_events`, `lost_events`, `loss_rate`, `ingest_p50_s`, `ingest_p99_s`, `recovery_s`, and `duration_s` in this section. **Status: not yet executed** — requires a 24h dedicated run window and a production-shaped PostgreSQL instance; the runbook above is the exact procedure, and the CI profile exercises the identical code path.

## What is intentionally deferred

- **Full-scale soak execution** (rows 1 and 9): the runbooks above are the procedure; the numbers are recorded here when a dedicated run window is scheduled. CI proves the code paths at reduced scale with real thresholds.
- **Crypto-erase for the backup tier** (row 3): open question per the Phase 4 spec; the shipped tier is the age-out + tombstone-coverage story.
