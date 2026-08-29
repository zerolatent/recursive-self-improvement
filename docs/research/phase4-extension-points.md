# Phase 4 extension points — the coding-agent MVP

**Status:** read-only survey, no code changes. Base: `main` @ `e5d5aca7` (Phase 3 release
merge, PR #37; D1–D9, E1–E10, F1–F12, G1–G11 complete).
**PRD basis:** §17 (coding-agent MVP: §17.1 reference workflow, §17.2 initial evaluation
suite, §17.3 `MvpConformanceProfile/v1`, §17.4 MVP success criteria), §18.3 (event
envelope), §12 (evaluation/selection), §13 (governance).
**Companion docs:** `docs/research/phase3-extension-points.md` (the format this file
mirrors), `docs/threat-model.md`, `docs/phase{0,1,2,3}-verification.md`.

Phase 4 per PRD §17: *make the built runtime actually run as a product.* Instrument a
fixture coding agent through the adapter SDK, run the §17.1 reference workflow end-to-end
(trace → discovery → campaign → sealed holdout → canary → promotion) on real workloads,
close the `MvpConformanceProfile/v1` numeric-threshold gaps, and demonstrate the §17.4
platform-acceptance and product-outcome criteria.

Everything below cites symbols and files actually read at `e5d5aca7`. PRD §17 is quoted
from the project's uploaded PRD document (`fl_7NBb30RG`, lines 980–1050).

---

## 1. Adapter SDK & the fixture agent (`src/evoruntime/sdk/`)

### What exists

- **`adapter.py`** — `Adapter` / `Trace`, the only surface an agent author touches.
  `Trace.model_call` (provider/model/tokens/`usd`), `Trace.tool_call` (name +
  `args_digest`/`result_digest` — content never rides the trace), `Trace.artifact_loaded`
  (digest → envelope `artifact_digests`), `Trace.claim_outcome` (explicitly untrusted).
  Non-blocking by construction: `offer()` returns queued/dropped, never waits. `AdapterStats`
  exposes `dropped_events` as a counter a harness can assert on (FR-001 backpressure).
  `TraceContext` carries `tenant_id`, `agent_id`, `release_id`, `environment_digest`,
  `campaign_id`, `data_classification` — the campaign/release linkage §17.1 step 10 needs
  is already on every event. Default identity is `WorkloadRole.CANDIDATE_RUNNER`
  (`adapter.py:__init__`), so an agent process can never write as the evaluator.
- **`buffer.py`** — `EventBuffer`, bounded (`DEFAULT_BUFFER_MAX_EVENTS = 10_000`), with a
  `high_water` wake so the flusher is driven by volume as well as time.
- **`journal.py`** — `EventJournal`: append-only WAL with `e`/`a` record kinds,
  `fsync_max_events`/`fsync_interval_s` dual bound, `recover()`/`compact()`. The
  ≤100-events/≤1s crash-flush envelope (§17.3 row 1) is this module's design contract.
- **`flusher.py`** — `FlushWorker`: journal *before* send, ack *after* ingest confirms;
  the only crash state is "durable, possibly not delivered", resolved by replay. Duplicates
  are safe (D2 ingest rejects by event id).
- **`transport.py`** — `HttpIngestTransport` (identity headers) + `IngestTransport`
  protocol; `DiscardingIngestTransport` for tests.
- **`attestation.py`** — `OutcomeAttestation`: Ed25519 detached signature over
  `(trace_id, task_set_digest, evaluator_bundle_digest, raw_result_digest, signed_at,
  evaluator_subject)`; `sign()` runs `require_evaluator_key_access` even when a key object
  is supplied; `verify(expected_public_key=...)` pins the evaluator's published key.
- **Tests:** `tests/sdk/test_crash_flush.py` (SIGKILL loses ≤ `LOSS_BOUND_EVENTS = 100`,
  survivors are a prefix, replay-on-restart), `tests/sdk/test_emit_overhead.py`
  (`OVERHEAD_BUDGET = 0.03`, `EMIT_BLOCK_BUDGET_S = 0.001`), `test_buffer.py`,
  `test_journal.py`, `test_adapter.py`, `test_attestation.py`.

### What a fixture coding agent needs (§17.1 steps 1–2)

§17.1 step 2: *the adapter records the issue, repository state, prompt versions, retrieved
skills, tool trace, patch, test output, cost, and untrusted claimed outcome; an external
verifier signs the authoritative outcome.* Mapping onto the SDK:

| §17.1 step 2 datum | Existing surface | Phase 4 delta |
|---|---|---|
| issue, repository state | nothing dedicated | payload references; needs a payload-registration path (see gap 2) |
| prompt versions | `details` dict only | a convention (e.g. `prompt_version` in `model_call` details) or new event type — the six-type vocabulary (`EVENT_TRACE_STARTED`…`EVENT_OUTCOME_CLAIMED`) is closed |
| retrieved skills | `Trace.artifact_loaded(kind=...)` | none — works today |
| tool trace | `Trace.tool_call` | none — works today |
| patch, test output | digests only | payload registration + a verifier that runs tests |
| cost | `CostInfo` on `model_call` | none |
| claimed outcome | `Trace.claim_outcome` | none |
| external verifier signature | `OutcomeAttestation.sign/verify` | a *verifier harness*: something that runs the fixture's tests, computes `raw_result_digest`, and signs as the evaluator |

### Gap

1. **No fixture agent exists.** The repo's only agent-like processes are
   `tests/sdk/crash_child.py` (a crash-probe child) and the eval plane's `ScriptedAgent` /
   `OpenAICompatibleBackend` (`eval/backends.py`) — the latter is a single-shot completion
   call, not a tool loop. Phase 4 needs a runnable harness that: executes a tool loop
   (read/edit/shell/test tools) inside a sandbox workspace, records prompt versions and
   retrieved skills, emits the patch as a digest-referenced payload, claims an outcome, and
   is attested by an external verifier that runs the fixture's executable tests and signs
   `OutcomeAttestation`. The SDK surface is sufficient for all of this *except* the two
   gaps below — the fixture agent is integration work, not SDK work.
2. **No payload-registration path from the agent side.** `Trace.tool_call` demands
   `sha256:` digests, and `artifact_loaded` binds payload digests, but nothing in the SDK
   or the HTTP API lets an agent *store* the bytes those digests reference. The payload
   store (`lineage/payload_store.py`) is server-internal; the only external write surface
   is evidence bundles (`api/service.py:record_evidence`). Without a payload-upload
   endpoint (with `DataClassification` and the D4 deletion policy attached), the digest
   chain §17.1 step 2 describes is unconstructible from a real agent.
3. **No trace read surface.** Ingest (`server/ingest.py`, `/v1/events:ingest`) is
   write-only; there is no `GET` for traces, no per-trace sequence reconstruction endpoint,
   no trace→campaign query. §17.1 steps 2–3 start from traces; today the only reader is
   the hash-chain verifier (`db/chain_verification.py`) invoked through
   `/v1/events:verify-chain`-style endpoints in tests.
4. **Model access bypasses the egress broker.** `OpenAICompatibleBackend` uses
   `urllib` directly (`eval/backends.py:HttpChatCompletionClient`). The broker
   (`security/egress.py:EgressBroker`, `sandbox/egress.py:EgressBrokerProxy`) mediates
   plugin processes and sandboxed tiers, but harness backends are not required through it.
   A fixture agent running in a brokered-tier sandbox gets the proxy via env vars
   (`executor.py:_child_env`); a fixture agent running *outside* the sandbox has no
   broker story at all.

### Extension points

- The fixture agent is a new package (e.g. `src/evoruntime/fixture_agent/` or
  `examples/fixture_agent/`) consuming `evoruntime.sdk` as-is; `Adapter(journal_path=...)`
  gives it crash-flush durability for free.
- Payload registration: one authenticated endpoint on the ingest router family
  (`POST /v1/payloads`) writing through the existing payload store with classification +
  tombstone deletion; the SDK gains a small `register_payload(bytes, classification)`
  helper that returns the digest it records in `tool_call`/`artifact_loaded`.
- Trace reads: read-only router over the existing event tables with tenant scoping
  (`Principal`-scoped like every `CampaignApiService` method) and the sequence
  reconstruction already implemented by `db/chain_verification.py`.
- Event vocabulary: prefer `details` conventions over new event types where possible;
  if a new type is unavoidable it is a schema change to `core/events.py` (envelope
  validation, hash chain, SDK `records.py`) and must be versioned, not appended silently.

---

## 2. Campaign operations (`src/evoruntime/api/`, `src/evoruntime/server/`, `evo` CLI)

### What exists

- **`api/service.py`** (`CampaignApiService`, 1445 lines) — every method
  `Principal`-scoped: `create_campaign`, `transition_campaign`, `register_agent`,
  `register_candidate` (FR-018 admission + F3 static analysis), `semantic_diff`,
  `record_evidence`, `record_evaluation`, `pareto`, `record_approval`, `create_release`,
  `promote_release`, `rollback_release`, `rollback_status`, plus the G6 scaffold
  boundaries (`_refuse_scaffold_outside_research`, `_refuse_scaffold_release`).
- **Routers** (`server/routers/`): datasets (partitions + holdout
  issue/metadata/budget/ledger/resolve/rotate/revoke), ingest, campaigns, candidates,
  agents, evidence, evaluations, approvals (tier-3/tier-4/privileged/
  compensation-plans/analysis-reports), releases (create/promote/rollback/rollback-status).
- **`evo` CLI** (`api/cli.py`, 443 lines) — thin one-client-call wrappers: `init`,
  `agent register`, `eval baseline`, `campaign plan/run/inspect [--pareto]`,
  `release nominate/qualify/canary/promote/rollback/status`,
  `approval request/decide/status`, `candidate diff/evidence`.
- **Dashboard** (`server/dashboard.py`) — read-only campaign views.
- **Holdout plane** (`datasets/service.py:HoldoutService`) — `issue_handle`,
  `resolve` (ledgered, alpha-spending), `rotate_handle`, `revoke_handle`, budget reports;
  IAM denial tested (`tests/test_holdout_iam_denial.py`).

### What an operator needs for §17.1 steps 1–10 without writing Python

| §17.1 step | Existing operational surface | Missing |
|---|---|---|
| 1–2. agent runs, traces recorded | SDK + ingest API | fixture agent (§1); trace read/query CLI |
| 3. discovery clusters failures | `CampaignPhase.DISCOVER` exists in the machine | **nothing implements discovery** — no clustering code anywhere (`grep cluster/discovery` hits only the phase enum and partition code); no discovery report artifact |
| 4. single-strategy campaigns | `evo campaign plan/run`, spec v3 | spec authoring templates/scaffolding; no `evo campaign validate` dry-run |
| 5. candidates run in isolated containers | sandbox plane (§5) | **no service-side execution path**: `SubprocessIsolationBackend` is constructed *only in tests* (`tests/conformance/`, `tests/sandbox/`) — no production code wires candidate execution through it; transitions are manual (`evo campaign run --to-phase`), there is no dev-evaluate worker |
| 6. diverse Pareto archive | `CampaignApiService.pareto` (flat per-campaign report: latest-attestation deltas vs parent) | no *archive* (diversity across success/cost/latency/safety/slices), no persistence, no slice dimension |
| 7. sealed holdout evaluation | `HoldoutService` + datasets router | no `evo` subcommands for holdout lifecycle (API-only today); no harness wiring that runs a frozen candidate against a resolved holdout and records paired results |
| 8. canary eligibility | promotion policy engine (§13.3 tiers) | no resolution of "read-only or transactionally reversible" as an eligibility check feeding canary admission |
| 9. canary monitoring | `release/canary.py:CanaryHarness` (library: fixed horizon, ≤5% allocation, ≥200 paired tasks, severity-1 stop) | **library-only** — no API/CLI/service exposure, no live-traffic comparison, no candidate-state namespacing outside the test `FleetSimulator` |
| 10. next-generation traces | release pointer + `TraceContext.release_id` | release *resolution* for agents (sessions pinned to a manifest) exists only as the test simulator (`release/fleet.py`) |

### Gap

The lifecycle *machine* and its gates are complete and tested; what is missing is the
*operator layer*: discovery tooling (step 3), an execution worker that actually runs
candidates through sandbox + harness (step 5), Pareto-archive semantics (step 6), canary
monitoring as a service (step 9), and `evo` coverage for holdout/analysis/compensation
surfaces that exist only as HTTP endpoints.

### Extension points

- Discovery: a pure clustering module (e.g. `eval/discovery.py`) consuming trace reads +
  the D8 `FailureCategory` taxonomy (`fixtures/lib/schema.py`), emitting a signed
  discovery report through the evidence/checkpoint pattern — no new authoritative table
  needed if reports ride the analysis-report path (`db/models/analysis.py`).
- Execution worker: `eval/runner.py` + `sandbox/executor.py` compose already
  (`tests/conformance/test_phase2_campaigns.py:run_in_sandbox` proves the pattern); the
  worker is orchestration around them, plus a backend-selection seam (§5).
- Pareto archive: extend `ParetoReport` with slice dimensions and a rebuildable archive
  projection (the `selection/productivity.py` rebuild/reconcile pattern — projection over
  immutable attestations, no new authoritative table).
- Canary service: `CanaryHarness` is already config-driven (`CanaryConfig`,
  `GuardrailEvent.is_severity_one`); wrap it in a router + a `evo release canary-status`
  command, and gate canary creation on an eligibility predicate over the release's
  resolved artifact classes.

---

## 3. Evaluation suite vs §17.2 (11 categories)

Fixture inventory at `e5d5aca7`: 24 coding (`fixtures/coding/`: 8 `dm_*` dependency-misuse,
8 `loc_*` localization, 8 `tm_*` test-misunderstanding), 13 adversarial
(`fixtures/adversarial/`: 4 `adv_pi_*` prompt-injection, 3 `adv_se_*` secret-exfiltration,
6 `adv_do_*` destructive-operation incl. 3 scaffold-specific), 11 static-analysis,
12 admission, plus the DLP corpus (`fixtures/dlp/corpus.yaml`). All coding fixtures are
Python, issue → patch → executable tests, loaded through the D5 partition model
(`fixtures/lib/schema.py` reuses `PartitionKind`).

| §17.2 category | Status | Evidence / gap |
|---|---|---|
| repository issue resolution with executable tests | **exists** | 24 coding fixtures + `fixtures/lib/runner.py`; `tests/test_fixtures_coding.py` |
| cross-language code repair | **missing** | zero non-Python fixtures |
| unit-test generation and bug localization | **partial** | localization exists as a *failure category* (`FailureCategory.LOCALIZATION`); no test-generation tasks |
| tool-use and shell safety | **partial** | destructive-op + escape corpora cover the safety half; no positive tool-use/shell task suite |
| dependency and environment diagnosis | **partial** | `dm_*` covers dependency misuse; no environment-diagnosis tasks |
| regression protection on simple tasks | **partial** | `loc_*` simple tasks exist; no explicit regression-protection suite (before/after behavior on untouched tests) |
| prompt-injection and repository-poisoning fixtures | **partial** | `adv_pi_*` (4) covers injection; repository poisoning (poisoned files/READMEs in the workspace) not represented |
| secret and holdout-exfiltration fixtures | **partial** | `adv_se_*` (3) + DLP corpus cover secret exfil; **holdout-exfiltration** fixtures (canary tokens planted in holdout content) absent — this is also the §17.3 evaluation-secrecy row's instrument |
| destructive-operation and sandbox-escape fixtures | **exists** | `adv_do_*` (6) + `tests/sandbox/test_escape_corpus.py` + scaffold severity-1 drill |
| cost and latency slices | **partial** | `BudgetUsage` records tokens/wall-clock per run and `COST_METRIC_KEYS` attests costs; no slice dimension in results/Pareto |
| transfer to a second coding harness and model family | **framework only** | `eval/suites.py` (`TransferFamilyKind.CROSS_HARNESS/CROSS_MODEL/ADJACENT_DOMAIN`, per-family pinning, scope ledger) is complete — but every family in the tests runs `ScriptedAgent`; no second *real* harness or model family exists to point a family at |

The §17.2 caveat is already honored structurally: public-fixture results cannot alone
authorize promotion because sealed holdouts are the only route to holdout content
(`eval/sources.py` refuses sealed partitions; `HoldoutService.resolve` is the only
ledgered route).

### Extension points

- New fixtures are *data*: `fixtures/lib/schema.py` manifests + the existing runner; the
  schema may need a third manifest kind (e.g. multi-language or tool-use tasks) — a
  versioned change to `CodingFixtureManifest`, not a schema break.
- Cost/latency slices: `eval/results.py` summarization gains slice keys; the Pareto
  archive (§2) is the visibility surface.
- Second harness/model: `TransferSuite` needs zero code changes — it needs a second
  harness implementation (the fixture agent is harness #1) and a second model family
  behind `ChatCompletionClient`.

---

## 4. `MvpConformanceProfile/v1` (§17.3) — threshold-by-threshold

| # | Area (§17.3) | Verified today | Untested / gap | Harness work needed |
|---|---|---|---|---|
| 1 | Trace correctness | 100% required fields: `EventEnvelope` validation + per-item ingest rejection (`server/ingest.py`, `tests/db/test_ingest.py`); sequence reconstructable: hash chain + 10k tamper tests (`tests/core/test_hashchain.py`, `tests/db/test_chain_verification_at_scale.py`); crash-flush ≤100 events/1s: `tests/sdk/test_crash_flush.py` | **event loss ≤0.01% over a 10-million-event fault-injection run** — the fault-injection test (`tests/test_fault_injection.py`) SIGKILLs one writer mid-batch at small scale; no 10M-event loss-rate measurement | a sustained fault-injection runner: N writers × M events with periodic SIGKILL, measuring delivered/expected; CI runs a scaled profile, a soak run records the full number |
| 2 | Adapter overhead <3% p95 | `tests/sdk/test_emit_overhead.py` (calibrated CPU-slice workload, paired measurement) | threshold names "the named coding-agent workload" — which does not exist yet | re-run the same harness around the fixture agent's real step loop (H1) |
| 3 | Payload deletion | revocation ≤5min + derived purge ≤24h: `tests/test_lineage_deletion.py` (SLOs shortened in-test, sweep semantics proven) | **7-day primary / 35-day backup crypto-erase or age-out** — the payload store has no backup tier to erase | a backup-tier design decision + lifecycle test; smallest honest version is documented age-out with a tombstone-coverage test |
| 4 | Release rollback | `tests/release/test_rollback_under_load.py`: CAS, fleet p99 convergence, 100% digest reporting, session pinning, no mixed manifest — via `release/fleet.py` **simulator** | real multi-worker fleet convergence is simulated, not measured | a fleet probe against ≥2 real workers, or an explicit profile note that p99 convergence is verified by the simulator's latency model |
| 5 | DLP | `tests/dlp/test_corpus_evaluation.py`: ≥99.5% secrets, ≥99.0% PII, ≤5% FP, zero misses on the versioned corpus | corpus growth as fixtures grow; "all misses reviewed before production" is a process, not a test | corpus extension alongside H7 fixtures; a miss-review runbook |
| 6 | Evaluation secrecy | IAM denial: `tests/test_holdout_iam_denial.py`, `security/policy.py` role gates; every query counted: holdout ledger | **zero canary-token/label leaks across 10,000 adversarial fixtures** — no canary-token fixture class exists at all | canary-token fixtures (planted markers in holdout content) + a leak-scan harness over 10k emissions |
| 7 | Sandbox/supply chain | escape corpus (`tests/sandbox/test_escape_corpus.py`), malformed-output admission corpus (12 fixtures), protected-path (`sa_protected_*`, `tests/security/test_protected_modules.py`) | **dependency/supply-chain fixtures** (malicious dependency, pinned-image drift) and the critical-patch-SLA process are absent | a dependency-fixture class + a documented patch-SLA policy; CVE scanning is an ops process, not a test |
| 8 | P0 canary | `release/canary.py` + `tests/release/test_canary.py`: fixed horizon, ≤5% allocation (`MAX_CANDIDATE_ALLOCATION`), ≥200 paired tasks, power-analysis sample, severity-1 immediate stop, underpowered-canary refusal | parameters verified as library semantics; never exercised against live traffic (see §2 step 9) | the canary monitoring service (H6) re-runs the same assertions as a service-level conformance test |
| 9 | MVP load | nothing | **1,000 concurrent candidate executions, 10M events/day for 24h, ingest p99 ≤2s, loss ≤0.01%, single-worker recovery ≤10min** — no load-generation harness exists; the closest neighbors are `tests/conformance/test_holdout_concurrency.py` (multi-process, small) and the 10k chain test | a load harness (event-emitter fleet + concurrent candidate runner + p99/loss/recovery measurement), a scaled CI profile, and a documented soak run |
| 10 | Memory hygiene | `tests/memory/`: poison/conflict/expiry/revocation/persistence-off/purge quarantine matrix, promotion gates (`memory/gates.py`: `persistence_non_inferiority_gate`, `negative_transfer_gate`, `hygiene_gate`) | essentially complete for the fixture matrix | none beyond keeping the matrix green as fixtures grow |

The pattern across rows 1, 6, 7, 9: the *mechanisms* exist and are unit-verified; what is
missing is **scale** (10M events, 10k fixtures, 1000 concurrent) and **live-traffic**
shapes (canary, fleet). These need harnesses, not features.

---

## 5. Isolation backend seam (`src/evoruntime/sandbox/`)

### What exists

- **`backend.py`** — `IsolationBackend` protocol: one method,
  `run(ExecutionRequest) -> ExecutionResult`. That is the entire swap surface.
- **`executor.py`** — `SubprocessIsolationBackend`: stage (digest-verified,
  `staging.py:StagedWorkspace`) → scrubbed env → pre-exec chain (rlimits → netns
  best-effort → Landlock write zoning to `profile.writable_paths` (G5) → HIGHEST syscall
  denylist → seccomp socket filter) → `EgressBrokerProxy` for brokered tiers →
  digest-verified `capture_paths` extraction (G5) → `ExecutionAttestation` persisted
  content-addressed. Fail-closed twice: `physical_enforcement_available()` refuses to run
  unisolated; HIGHEST refuses to run without the syscall denylist
  (`syscall_denylist_supported()`).
- **`profile.py`** — `ExecutionProfile` (tier, network_mode, resource_limits,
  `writable_paths`, allow_privileged_syscalls), `ExecutionRequest` (tenant_id,
  image_digest, payloads, command, egress_policy, capture_paths), `EnforcementRecord` v2
  (`rlimits_applied`, `network_filter_applied`, `filesystem_contained`,
  `network_namespace`, `broker_proxy`, `write_zone_applied`, `syscall_denylist`),
  `ExecutionAttestation`.
- **Tests:** escape corpus, capture zones, HIGHEST tier, manifest-tier cross-check.

### What a gVisor/Firecracker backend must implement

The contract is small and honest: `run()` honoring the `ExecutionRequest`/`ExecutionResult`
shapes, physical enforcement of the profile's tier semantics, and an `EnforcementRecord`
that states *its own* mechanisms truthfully (a microVM backend would report
`filesystem_contained=True` by VM boundary, `syscall_denylist` per its own profile, and a
new `tier_enforcement` marker — the G5 convention `tier_enforcement="reference"` already
distinguishes the reference backend). Everything else it gets for free: staging, capture,
attestation persistence, and the egress proxy are composed *around* the protocol.

### What is subprocess-coupled (and must not leak into the protocol)

- The pre-exec chain (`_child_setup`) is Linux-syscall work (Landlock, seccomp, rlimits,
  netns) — correct for the reference backend, irrelevant to a microVM one.
- `EgressBrokerProxy` runs *in-process* (`proxy.serve()` on the parent thread); a microVM
  backend needs the broker reachable from the guest — the proxy URL env-var contract
  (`_child_env`) is the seam to preserve.
- Output capture is `Popen` pipes with `MAX_CAPTURED_OUTPUT_BYTES`; the protocol result
  shape is fine, the mechanism is not.

### The structural finding

`SubprocessIsolationBackend` is constructed **only in tests** (`tests/conformance/`,
`tests/sandbox/`); no production code path executes a candidate through the sandbox.
Phase 4's step 5 ("candidates run against public development repositories in isolated
containers") is the first time the sandbox moves from verified-library to load-bearing
infrastructure — the execution worker (§2) is where the backend gets wired, and backend
*selection* (reference vs production microVM) becomes a deployment decision that needs a
policy seam, not an import.

### Extension points

- A backend-registry/selection function (environment → `IsolationBackend`) at the
  execution worker's construction; conformance-kit tests that *any* backend must pass
  (the escape corpus + capture-zone + attestation-honesty assertions parameterized over
  the protocol) so a microVM backend inherits the existing evidence.
- `EnforcementRecord` gains nothing for the swap itself; keep it descriptive, never
  aspirational — the fail-closed refusals in `executor.py` are the pattern to copy.

---

## 6. §17.4 platform-acceptance mapping

| §17.4 bullet | Existing verifying evidence | Named gap |
|---|---|---|
| 80% of five agent engineers instrument the fixture agent within one engineer-day | nothing — no fixture agent, no onboarding doc | fixture agent (H1) + documented prerequisites + task script + a timed onboarding drill |
| 80% of five plugin developers run the reference prompt optimizer within 30 minutes | `plugins/reference/gepa_prompt_optimizer.py` + protocol conformance tests (`tests/plugins/test_protocol_conformance.py`) | a documented clean-environment quickstart (uv sync → run reference plugin against conformance harness) and a timed drill |
| lineage reconstruction task → attestation → signed manifest; deterministic fixtures replay | decision-reconstruction scenarios in all three phase conformance passes (`test_phase1_campaigns.py`, `test_phase2_campaigns.py`, `test_phase3_campaigns.py`) | the chain must now *start at a real trace* (§1's trace-read surface) rather than at test-fabricated records |
| security suites meet the profile | mapped in §4 rows 5–7 | canary-token 10k suite; dependency fixtures |
| planted beneficial/neutral/regressive/leaking/reward-hacking candidates dispositioned | Phase 1 conformance: beneficial promoted, neutral rejected, harmful rejected, leaking quarantined (`test_phase1_campaigns.py` scenarios 1–5) | **reward-hacking candidate** — no fixture or disposition test exists; this is the candidate class the `claim_outcome`-is-untrusted design exists for, so it deserves an explicit drill |
| rollback SLOs + irreversible-effect drills | `test_rollback_under_load.py`, `test_scaffold_severity1_drill.py`, compensation runbook (F5/G8) | live-fleet convergence (§4 row 4) |
| memory gates before suggestion-mode exit | `tests/memory/` complete | none |

---

## 7. Product-outcome enablement (§17.4 product outcome)

The target: *at least one lower-risk plugin achieves a multiplicity-adjusted, adequately
powered 10% relative held-out success gain or 20% cost reduction at non-inferiority.*

- **Seeds / pairing** — exists: `derive_seed` excludes arm ids (common random numbers),
  `MIN_SEEDS = 3`, paired bootstrap + Holm (`eval/statistics.py`).
- **Power analysis** — **missing as a module.** `release/canary.py` refuses an
  underpowered canary and references "the power-analysis sample", but nothing computes a
  required sample size from an effect size and variance. The §17.4 target is explicitly
  "adequately powered" — a power-analysis helper (paired-proportion sample size given
  α, power, minimum detectable effect) is needed before the first real campaign is
  budgeted, and `StatisticsPlan` is where it pins.
- **Budget accounting** — exists end-to-end: `BudgetMeter` (charge-before-spend),
  `CampaignBudgets`, attested cost metrics (`COST_METRIC_KEYS`, F9).
- **Cost/latency slices** — usage is recorded per run; slice aggregation (per-task-type,
  per-difficulty) is absent (§3 row 10).
- **Model access** — the gap of §1.4: harness backends bypass the egress broker; there is
  no model-gateway service. The §17.1 step 4 campaigns (memory suggestion, BootstrapFewShot,
  GEPA, SkillOpt) all need model calls from *candidate* processes — brokered routing is the
  existing pattern (`model_hosts` allowlists, `EgressBrokerProxy`), and the fixture agent
  must use it.
- **Reference plugins** — all four lower-risk plugins exist and are signed
  (`plugins/reference/`); what they lack is a real agent's traces to optimize against.

---

## 8. Recursive-claim path (§17.1 step 10, G4)

### What exists

`ArmKind.FIXED_EDITOR` with the incumbent envelope (`eval/runner.py:strategy_for`),
`RecursiveClaimEvidence` with `fixed_editor_control_arm` and
`_fixed_editor_advantage_holds`, `evaluate_recursive_claim` / `claim_label` /
`assert_label_allowed`, and per-tenant enablement via `_claims_enabled(tenant_policy)`
(`selection/recursive_gate.py`) — the Phase 3 global-constant risk is closed. Holdout
rotation (`HoldoutService.rotate_handle`) and revocation exist for fresh/rotating
holdouts.

### What remains to run two successive generations (§17.1 step 10)

1. **Generation 1** — a real campaign (§17.1 steps 1–9) against the fixture agent in the
   research tenant, promoting a lower-risk artifact. Everything this needs is §2/§7.
2. **Generation 2** — a second campaign whose incumbent binding resolves to the
   generation-1 promoted release, evaluated on *fresh* holdouts (rotate, then issue) with
   the mechanism-appropriate control: no-inheritance/one-shot for RI-2 (exists since D6),
   fixed-editor for RI-3/RI-4 (exists since G4).
3. **Evidence assembly** — `RecursiveClaimEvidence` fields must be populated from real
   paired results (attested costs, holdout deltas) rather than test-fabricated values;
   the paired statistics machinery produces them, but nothing today *assembles* the
   evidence object from an `ExperimentResult` — a small pure adapter is needed.
4. **Label issuance as an operational act** — `claim_label` is a library function; the
   research-tenant operator path (CLI/API) that records the claim decision append-only
   does not exist.

---

## Structural risks (cross-cutting)

1. **The trace plane is write-only.** The entire §17.1 loop begins with traces, but the
   API has no read surface and the SDK has no payload-registration path. Phase 4's first
   deliverables must add both without weakening the existing guarantees: tenant-scoped
   reads only, classification carried on every payload, deletion policy attached at
   registration (the D4 tombstone machinery already exists — reuse it, don't fork it).
2. **Model access bypasses the egress broker.** `OpenAICompatibleBackend` dials providers
   directly; the broker mediates only plugin processes and sandboxed tiers. A fixture
   agent with a direct model route is exactly the leak §13.2's egress control exists to
   prevent. Route harness/model access through the broker (or a gateway in front of it)
   *before* the first real campaign, or the first real campaign normalizes the bypass.
3. **The sandbox has never executed anything in production code.** Every construction
   site of `SubprocessIsolationBackend` is a test. Wiring it into a service-side execution
   worker moves it from verified-library to critical infrastructure in one step — the
   fail-closed refusals and attestation honesty are the right foundation, but the
   operational failure modes (stale workspaces, proxy lifecycle, capture-partial-failure)
   are untested at service level. Budget for an execution-worker conformance slice.
4. **The load thresholds need infrastructure, not features.** 10M-event fault-injection,
   10k canary-token fixtures, 1000-concurrent/10M-events-per-day sustain, and a 24-hour
   horizon cannot run in CI. Plan a scaled-down CI profile plus a documented soak run
   with recorded numbers, or the §17.3 rows stay asserted rather than measured. The
   fault-injection test's structure (real Postgres, SIGKILL, resume) is the seed of the
   harness; the load generator does not exist at all.
5. **Event-vocabulary drift.** §17.1 step 2 tempts new event types (issue, repo state,
   patch, test output). Every addition touches envelope validation, the hash chain, and
   the SDK — the same canonical-digest hazard as a campaign-spec change. Prefer `details`
   conventions and payload references; if a type must be added, version it deliberately.
6. **The reward-hacking disposition is untested.** §17.4 names five planted-candidate
   dispositions; four have Phase 1 conformance scenarios, reward-hacking has neither a
   fixture nor a drill — and it is the disposition that most depends on the
   claimed-vs-attested outcome split actually being enforced end-to-end.

---

## Recommended deliverable decomposition (H1…H12)

Sized like G1–G11 (one deliverable ≈ one reviewable PR with its own conformance slice).
Dependency order in parentheses.

- **H1 — Fixture coding agent (after: nothing).** A runnable agent harness on
  `evoruntime.sdk`: sandboxed tool loop (read/edit/shell/test), prompt-version and
  retrieved-skill recording, patch output as digest-referenced payloads, claimed outcome,
  plus an external verifier that runs the fixture's executable tests and signs
  `OutcomeAttestation`. *Outcome: §17.1 steps 1–2 are real; the §17.3 adapter-overhead row
  gains its named workload.*
- **H2 — Trace read surface + payload registration (after: nothing; parallel with H1).**
  Tenant-scoped trace query/reconstruction endpoints over the existing event tables, and
  an authenticated payload-upload endpoint wired to the D4 payload store with
  classification + tombstone deletion; SDK helper for payload registration.
  *Outcome: the digest chain is constructible and queryable; lineage reconstruction can
  start at a real trace.*
- **H3 — Discovery: failure clustering (after H2).** Pure clustering over trace reads
  against the D8 failure taxonomy, emitting a signed discovery report (analysis-report
  path); `evo campaign discover` reads it. *Outcome: §17.1 step 3 without Python.*
- **H4 — Campaign ops completion (after H2; parallel with H3).** `evo` subcommands for
  holdout lifecycle, analysis reports, compensation plans; spec templates + a validate
  dry-run; a service-side execution worker driving dev-evaluate through the harness +
  sandbox with backend selection. *Outcome: §17.1 steps 4–5 and 7 operable end-to-end;
  the sandbox becomes load-bearing with its own conformance slice.*
- **H5 — Pareto archive + slices (after H4).** Slice dimensions (success/cost/latency/
  safety/task-type) over attested metrics, a rebuildable archive projection
  (productivity.py pattern), dashboard + CLI visibility. *Outcome: §17.1 step 6.*
- **H6 — Canary monitoring service (after H4).** Canary eligibility resolution
  (read-only/transactionally-reversible classes), `CanaryHarness` exposed as an
  operational surface with candidate-state namespacing and severity-1 auto-rollback;
  `evo release canary-status`. *Outcome: §17.1 steps 8–9; §17.3 row 8 measured live.*
- **H7 — §17.2 suite expansion (after H1).** Cross-language repair, unit-test generation,
  shell-safety depth, repository-poisoning, holdout-exfiltration (canary-token) fixtures,
  cost/latency slice data, second-harness + second-model-family transfer fixtures.
  *Outcome: all 11 §17.2 categories present.*
- **H8 — Conformance threshold harnesses (after H1, H2).** 10M-event fault-injection
  loss-rate runner (scaled CI profile + soak), canary-token 10k secrecy suite, load
  harness (1000 concurrent / 10M events/day, ingest p99, single-worker recovery),
  payload-deletion backup-tier story. *Outcome: §17.3 rows 1, 3, 6, 9 measured.*
- **H9 — Isolation-backend conformance kit (after: nothing; parallel).** Backend
  selection seam + a conformance kit (escape corpus, capture zones, attestation honesty)
  parameterized over `IsolationBackend`, so a gVisor/Firecracker backend inherits the
  evidence. *Outcome: the microVM path is a documented, testable swap.*
- **H10 — Product-outcome enablement (after H4, H7).** Power-analysis module pinning
  sample sizes into `StatisticsPlan`, brokered model access for harness backends,
  cost/latency slice reporting. *Outcome: the first lower-risk plugin campaign is
  runnable with powered statistics on real traces.*
- **H11 — Two-generation recursive-claim operations (after H10).** Generation-2 campaign
  tooling (incumbent = generation-1 release, rotated holdouts), evidence assembly from
  real paired results into `RecursiveClaimEvidence`, label issuance recorded append-only.
  *Outcome: §17.1 step 10 operational in the research tenant.*
- **H12 — Phase 4 conformance pass (after H1–H11).** §17.4 platform-acceptance matrix
  green including the reward-hacking planted-candidate drill and the two timed onboarding
  drills (agent instrumentation, plugin 30-minute path); `docs/phase4-verification.md`.
  *Outcome: the Phase 4 acceptance matrix is green and every claim reconstructs from
  append-only records.*

Natural order: **H1 ∥ H2 → (H3 ∥ H4) → (H5 ∥ H6 ∥ H7) → H8 ∥ H9 ∥ H10 → H11 → H12**, with
H9 startable immediately. The critical path to the §17.1 reference workflow is
**H1 → H2 → H4 → H6 → H10 → H11**; the critical path to §17.4 platform acceptance adds
**H3, H7, H8, H12**.
