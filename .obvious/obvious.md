# zerolatent/recursive-self-improvement

## Status: EvoRuntime Phase 0 (evaluation foundation) in progress

This repository implements EvoRuntime — a governed self-improvement runtime
and control plane for software-engineering agents. See the pinned EvoRuntime
Phase 0 spec for the full design; this file only documents how to work with
the code as it exists today.

## Stack

- **Language / runtime:** Python 3.12
- **Package manager:** [uv](https://docs.astral.sh/uv/)
- **Web framework:** FastAPI (the evaluation-plane service)
- **Database:** PostgreSQL, via SQLAlchemy 2.0 (`psycopg` driver) + Alembic migrations

## Layout

```
src/evoruntime/
  core/    shared schemas and types
  server/  the FastAPI evaluation-plane service (/healthz)
  sdk/     the agent adapter SDK (placeholder — deliverable D3)
  eval/    the evaluation harness (placeholder — deliverable D6)
  db/       SQLAlchemy models, sessions, and Alembic migrations
  security/ workload identities, egress broker, signing service (D7)
tests/     pytest suite
docs/       threat-model.md and other design docs
```

## Commands

```bash
uv sync                      # install
uv run ruff check .          # lint
uv run ruff format --check . # format check
uv run mypy                  # typecheck (strict)
uv run pytest                # test
uv run evoruntime-server     # run the FastAPI service
```

`uv run pytest` includes an Alembic upgrade/downgrade round-trip test against
a real PostgreSQL (`tests/test_migrations.py`); it skips locally without a
reachable database and always runs in CI, which provides a `postgres` service.

## Security scaffolding (D7)

`src/evoruntime/security/` separates the evaluator and candidate-runner
workload identities (`identities.py`), the policy checks that gate holdout
access and evaluator key access to the evaluator role only (`policy.py`),
a deny-by-default egress broker (`egress.py`), and an Ed25519 detached-
signature signing service for release manifests and outcome attestations
(`signing.py`). See `docs/threat-model.md` for the trust model these
enforce and what is still deferred to Phase 1.

## What's not here yet

Domain tables (trace events, payloads, lineage nodes/edges, dataset
partitions, holdout handles, the holdout query ledger), the trace ingest
API, the adapter SDK's buffering/attestation logic, and the evaluation
harness's experiment-arm execution are later Phase 0 deliverables
(D2–D6, D8), not gaps in this scaffold. Those deliverables are expected to
call into `evoruntime.security.policy` at their own API boundaries once
they exist — D7 ships the primitives, not the call sites.

## Isolation-backend selection (H9)

The sandbox plane is a protocol, not a product: production code resolves
its isolation backend through
`evoruntime.sandbox.selection.resolve_isolation_backend`
(env var `EVO_ISOLATION_BACKEND`, default `reference`, fail-closed on
unknown names). The swap runbook — what a gVisor/Firecracker backend must
implement and how it inherits the conformance evidence — is
`docs/isolation-backend-swap.md`.
