# EvoRuntime Phase 0 — Conformance Verification Report

**Branch:** `chore/conformance-verification` (based on `release/evoruntime-phase0-eval-foundation-20260827` @ `779246a`)
**Date:** 2026-08-28
**Scope:** Full acceptance matrix from the Phase 0 spec (deliverables D1–D8), executed end-to-end on the integrated release branch, plus the D5 multi-process concurrency gap closed in `tests/conformance/`.

## Headline result

**All acceptance criteria have passing evidence.** Local run on the integrated state: **499 passed, 0 failed** (PostgreSQL-backed integration tests included), `ruff check` clean, `ruff format --check` clean, `mypy --strict` clean across 69 source files.

One known CI-jitter flake is documented in [Known flake](#known-flake) — it did not fail in the final verification run and is being de-flaked by the D3 owner.

## How the matrix was run

- **D1 clean-clone gates:** fresh `uv sync` in this sandbox (no pre-existing venv), then the same four gates CI runs: `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy`, `uv run pytest`.
- **PostgreSQL-backed tests:** all DB-dependent tests (D2 chain, D4 lineage, D5 partitions/ledger, migrations) were executed against a real PostgreSQL 17 instance locally; CI runs the same suite against `postgres:16` (`.github/workflows/ci.yml` service container). The suite skips — rather than fakes — when no database is reachable, so a green run here means the integration tests actually ran.
- **Subprocess fault injection:** D2's ingest-kill test and D3's crash-flush test run real child processes killed with `SIGKILL`, not in-process simulations.
- **New conformance coverage:** `tests/conformance/` adds the one check that could only be demonstrated by a multi-process integration test — holdout alpha-spend accounting under cross-process contention (see [Extra scope](#extra-scope-multi-process-holdout-contention)).

## Acceptance matrix

### D1 — Repo foundation

| Criterion | Evidence | Result |
|---|---|---|
| `uv sync && pytest && ruff check && mypy` pass in a clean clone | Executed in this sandbox from a fresh checkout of the release branch; `uv sync` resolved the lockfile from scratch | ✅ pass |
| Alembic migrates an empty Postgres to head and back | `tests/test_migrations.py::test_upgrade_head_then_downgrade_base` | ✅ pass |
| FastAPI `/healthz` serves | `tests/test_healthz.py::test_healthz_returns_200_ok` | ✅ pass |
| GitHub Actions runs the same gates on PR | `.github/workflows/ci.yml` — ruff check, ruff format --check, mypy, pytest with a `postgres:16` service | ✅ present |

### D2 — Trace schema, ingest, hash chain

| Criterion | Evidence | Result |
|---|---|---|
| 100% of envelope required fields validate | `tests/core/test_events.py::test_valid_envelope_round_trips`, `test_missing_required_field_is_rejected` (parametrized over every required field) | ✅ pass |
| Malformed events rejected with typed errors | `tests/core/test_events.py::test_malformed_field_is_rejected`, `test_extra_field_is_rejected`; `tests/server/test_ingest_api.py::test_malformed_event_is_rejected_others_still_accepted`, `test_duplicate_event_is_rejected_with_typed_error` | ✅ pass |
| Per-tenant hash chain detects any mutation/reorder of a 10k-event fixture | `tests/db/test_chain_verification_at_scale.py::test_flipped_byte_in_10k_chain_is_detected`, `test_swapped_pair_in_10k_chain_is_detected` (10,000-event fixture, real Postgres) | ✅ pass |
| Fault injection: kill ingest mid-batch, event loss ≤ 0.01% | `tests/test_fault_injection.py::test_sigkill_mid_batch_loses_at_most_one_event_and_resume_loses_none` — real subprocess SIGKILLed mid-batch on a 10k-event fixture; asserts ≤1 event stranded at kill and exactly 0 lost after idempotent resume (0.00% ≤ 0.01%) | ✅ pass |
| Per-tenant chain independence | `tests/db/test_ingest.py::test_tenants_chain_independently` | ✅ pass |

### D3 — Agent adapter SDK

| Criterion | Evidence | Result |
|---|---|---|
| Crash-flush: SIGKILL mid-stream loses ≤ 100 buffered events or 1s | `tests/sdk/test_crash_flush.py::test_sigkill_loses_no_more_than_the_conformance_bound` (real child process, `crash_child.py`, SIGKILL); survivors verified as a strict prefix by `test_survivors_are_a_prefix_not_a_random_sample` | ✅ pass |
| Backpressure: full buffer drops-with-counter, emit never blocks | `tests/sdk/test_buffer.py::test_offer_accepts_until_full_then_drops_with_counter`, `test_offer_does_not_block_when_full`, `test_drop_keeps_the_trace_prefix_not_the_tail`; adapter-level: `tests/sdk/test_adapter.py::test_full_buffer_drops_with_a_counter_and_never_blocks_emit` | ✅ pass |
| p95 emit overhead < 3% on the scripted fixture workload | `tests/sdk/test_emit_overhead.py::test_p95_emit_overhead_stays_under_the_budget` (budget asserted as `OVERHEAD_BUDGET = 0.03`); end-to-end guard `test_instrumentation_does_not_slow_the_workload_end_to_end` | ✅ pass (see [Known flake](#known-flake)) |
| No single emit blocks the agent thread > 1 ms | `tests/sdk/test_emit_overhead.py::test_no_single_emit_blocks_the_agent_thread` (`EMIT_BLOCK_BUDGET_S = 0.001`) | ✅ pass (see [Known flake](#known-flake)) |
| Replay after crash | `tests/sdk/test_crash_flush.py::test_a_restarted_adapter_replays_what_the_crash_left`, `test_replayed_events_are_cleared_from_the_journal` | ✅ pass |

### D4 — Lineage store, append-only, deletion SLOs

| Criterion | Evidence | Result |
|---|---|---|
| Append-only enforced at DB level (no UPDATE/DELETE on nodes/edges) | `tests/test_lineage_append_only.py` — hand-written `UPDATE`/`DELETE` against `lineage_nodes` and `lineage_edges` all rejected by the migration-installed SQL trigger; `test_insert_is_still_allowed` proves inserts (the only sanctioned path) stay open | ✅ pass |
| Payload deletion emits tombstone, revokes access ≤ 5 min, purges derivatives ≤ 24 h (shortened SLOs via config) | `tests/test_lineage_deletion.py` — `test_request_deletion_creates_tombstone`, `test_revoke_access_deletes_payload_row`, `test_access_revocation_sweep_processes_expired_tombstones` (SLO shortened to 1 s, 2 s simulated), `test_purge_derived_data_removes_fixture_rows`, `test_full_deletion_flow_end_to_end` | ✅ pass |
| Derived purge covers embeddings/caches rows | `tests/test_lineage_deletion.py::test_purge_derived_data_removes_fixture_rows` (asserts both fixture derived rows gone, `purged_count == 2`) | ✅ pass |
| Revocation actually blocks reads | `tests/test_payload_store.py::test_read_after_access_revoked_raises_access_revoked`, `test_different_tenants_cannot_read_each_others_payloads` | ✅ pass |

### D5 — Dataset partitions, sealed holdout, query ledger

| Criterion | Evidence | Result |
|---|---|---|
| Holdout content unreadable from an identity outside the evaluation-plane role (IAM denial) | `tests/test_holdout_iam_denial.py::test_candidate_runner_cannot_resolve_a_holdout_handle` (denial carries no `object://` locator), `test_candidate_runner_cannot_issue_rotate_or_revoke`, `test_cross_tenant_evaluator_is_denied_without_confirming_existence`; API-level: `test_api_denies_candidate_runner_and_returns_no_content`; policy layer: `tests/test_security_policy.py::test_candidate_runner_cannot_resolve_holdout_handles` | ✅ pass |
| Every holdout resolution appends a ledger row | `tests/test_holdout_handles.py::test_every_resolution_appends_exactly_one_ledger_row`; denials ledgered too: `test_denied_resolution_is_recorded_in_the_ledger` | ✅ pass |
| Ledger reports remaining alpha budget | `tests/test_holdout_handles.py::test_budget_report_tracks_remaining_alpha`, `test_exhausted_budget_denies_further_reads` | ✅ pass |
| Ledger is append-only | `tests/test_holdout_iam_denial.py::test_ledger_rows_cannot_be_updated_or_deleted` | ✅ pass |
| Handle rotation changes the opaque token without content movement | `tests/test_holdout_handles.py::test_rotation_changes_the_token_without_moving_content` (same `content_locator`/`content_digest`, spent alpha preserved, old token dead), `test_ledger_survives_rotation` | ✅ pass |
| Sealed partitions never disclose their locator; six PRD partition kinds | `tests/test_dataset_partitions.py::test_sealed_partition_never_discloses_its_locator`, `test_all_six_prd_partition_kinds_exist`, `test_sealed_kinds_require_evaluation_plane_storage` | ✅ pass |
| **Multi-process contention (extra scope):** alpha-spend accounting holds across independent processes | `tests/conformance/test_holdout_concurrency.py` — 8 OS processes × 2 attempts race one handle: exactly 4 grants (no overspend, no underspend), 12 denials all `alpha_budget_exhausted`, 16 ledger rows, budget report equals ledger sum; headroom variant proves no lost updates (16/16 grants, spent exactly 0.16) | ✅ pass |

### D6 — Evaluation harness

| Criterion | Evidence | Result |
|---|---|---|
| Arms run under identical budgets (equal token/tool/wall-clock ceilings) | `tests/eval/test_runner.py::test_arms_run_under_identical_budgets` — asserts `result.budgets_are_matched is True` and every run in every arm carries the same budget object | ✅ pass |
| Multi-seed variance reported | `tests/eval/test_results.py::test_reports_one_rate_per_seed`, `test_stdev_is_bessel_corrected_across_seeds`; seed floor enforced: `tests/eval/test_experiment.py::test_seeds_below_the_prd_floor_are_rejected` | ✅ pass |
| Paired-bootstrap CI reproduces a known effect within tolerance | `tests/eval/test_statistics.py::test_bootstrap_recovers_a_known_positive_effect`, `test_interval_covers_the_truth_about_as_often_as_advertised`, `test_result_is_reproducible_from_its_recorded_seed` | ✅ pass |
| A regression arm is flagged | `tests/eval/test_statistics.py::test_regression_arm_is_flagged` | ✅ pass |
| Multiplicity adjustment | `tests/eval/test_statistics.py` Bonferroni family: `test_bonferroni_splits_the_family_alpha`, `test_smallest_p_is_scaled_by_the_full_family_size` | ✅ pass |
| Holdout never used as an experiment dataset | `tests/eval/test_experiment.py::test_holdout_partition_is_refused_at_construction` | ✅ pass |

### D7 — Security scaffolding

| Criterion | Evidence | Result |
|---|---|---|
| Candidate-runner identity cannot resolve holdout handles or read evaluator keys | `tests/test_security_policy.py::test_candidate_runner_cannot_resolve_holdout_handles`, `test_candidate_runner_cannot_read_evaluator_keys`; key custody: `tests/test_security_signing.py::test_candidate_runner_cannot_load_evaluator_signing_key` | ✅ pass |
| Egress broker denies undeclared destinations | `tests/test_security_egress.py::test_undeclared_destination_is_denied`, `test_empty_allowlist_denies_everything`, `test_subdomain_of_allowed_host_is_still_denied` | ✅ pass |
| Release/outcome attestations verify with detached signature and fail on any byte change | `tests/test_security_signing.py::test_verify_fails_on_any_byte_change_of_the_payload`, `test_verify_fails_on_signature_corruption`, `test_verify_fails_with_the_wrong_public_key`; outcome attestations: `tests/sdk/test_attestation.py::test_editing_any_bound_field_breaks_the_signature`, `test_a_signature_from_the_wrong_key_does_not_verify`, `test_the_candidate_runner_cannot_sign_even_holding_a_key` | ✅ pass |
| Threat-model document committed | `docs/threat-model.md` | ✅ present |

### D8 — Seed evaluation suite

| Criterion | Evidence | Result |
|---|---|---|
| ≥ 20 coding tasks (issue → patch → executable tests) | 24 fixtures under `fixtures/coding/` (count asserted by the parametrized suite collecting every `fixture.yaml`) | ✅ pass (24) |
| Across ≥ 3 failure categories (localization, test misunderstanding, dependency misuse) | `loc_*` (8), `tm_*` (8), `dm_*` (8) — three categories, eight fixtures each | ✅ pass |
| ≥ 10 adversarial fixtures (prompt injection, secret exfiltration, destructive operation) | 10 fixtures under `fixtures/adversarial/`: 6 `adv_pi_*` (prompt injection), 2 `adv_se_*` (secret exfiltration), 2 `adv_do_*` (destructive operation) | ✅ pass (10) |
| All pass/fail deterministically | `tests/test_fixtures_coding.py::test_unpatched_fixture_fails`, `test_patched_fixture_passes`, `test_patched_fixture_is_deterministic` (runner executed twice); adversarial: `tests/test_fixtures_adversarial.py::test_safe_transcript_scores_safe`, `test_unsafe_transcript_scores_unsafe`, `test_transcript_scoring_is_deterministic` | ✅ pass |

## Known flake

`tests/sdk/test_emit_overhead.py::test_no_single_emit_blocks_the_agent_thread` asserts a hard 1 ms max-emit-block bound and is sensitive to shared-runner jitter: the release-branch push run at `779246a` measured 1.169 ms on a loaded runner while the PR run at the same SHA passed and local trials measured 0.92 ms. Per the D3 owner this is a known CI-jitter flake, not a product defect; the D3 worker is making the test's sampling jitter-robust. It passed in this verification run's final full suite. The conformance verdict does not rest on it: the p95-overhead criterion (`test_p95_emit_overhead_stays_under_the_budget`) and the backpressure criterion (`test_full_buffer_drops_with_a_counter_and_never_blocks_emit`) are independent assertions and both pass.

## Extra scope: multi-process holdout contention

D5's own suite verified row-lock correctness single-process (one caller, sequential resolutions). A lost update only exists when two independent database sessions read the same handle row before either commits, so the check was added in `tests/conformance/test_holdout_concurrency.py` with a standalone worker (`holdout_contention_worker.py`) spawned as real OS processes:

- **Exhaustion under contention:** budget 0.04 / per-query 0.01, 8 processes × 2 attempts = 16 racing attempts → exactly 4 granted, 12 denied (all `alpha_budget_exhausted`), 16 ledger rows, budget report equals ledger sum.
- **No lost updates with headroom:** budget 1.00, 16 concurrent grants → 16/16 granted, spent exactly 0.16, remaining 0.84.

Both pass, demonstrating the `SELECT … FOR UPDATE` handle lock prevents cross-process overspend and lost updates.

## Environment notes

- Local verification ran against PostgreSQL 17.11 (Debian package) with a UTF-8 database; CI runs `postgres:16`. One environment pitfall worth recording: a PostgreSQL initialized with a non-UTF-8 server encoding (e.g. `SQL_ASCII` from a C locale) makes psycopg return the `version()` string as bytes, which crashes SQLAlchemy's server-version detection with `TypeError: cannot use a string pattern on a bytes-like object`. This is an environment configuration issue, not a code defect — CI's `postgres:16` image defaults to UTF-8 and is unaffected.
- The three deferrals named in the spec (load-scale profile, DLP labeled corpus, canary machinery) remain Phase 1 scope and are not part of this matrix.

## Verdict

Phase 0's acceptance matrix is green on the integrated release branch: every criterion in the spec's verification table has named, passing evidence, with the single documented timing flake noted above and owned by the D3 deliverable.
