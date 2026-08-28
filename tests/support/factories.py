"""Deterministic event envelope fixtures for D2 tests.

Every event built here is independently valid against `EventEnvelope`; only
`event_id`/`trace_id`/`task_id`/`occurred_at` vary per index so a whole
fixture set is unique and ordered. `event_id` also folds in `tenant_id`
(sanitized to satisfy its `evt_[A-Za-z0-9]+` pattern) because, unlike
`trace_id`/`task_id`, it carries a *global* uniqueness constraint — tests
share one long-lived database with no row cleanup between them, so an
index-only id (e.g. `evt_000000000000`) collides across every test/tenant
that happens to start from the same index.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from evoruntime.core.events import parse_wire_envelope
from evoruntime.core.hashchain import GENESIS_HASH, compute_event_hash
from evoruntime.db.models.events import Event

BASE_TIME = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)


def make_raw_event(
    index: int,
    *,
    tenant_id: str = "tnt_test",
    agent_id: str = "agt_test",
    release_id: str = "rel_test",
    trace_id: str | None = None,
    task_id: str | None = None,
    event_type: str = "tool.completed",
) -> dict[str, Any]:
    """A raw (dict-form) envelope, valid as-is, suitable for JSON transport.

    `index` only drives uniqueness (event_id/trace_id/task_id/occurred_at);
    every other field is a fixed, valid value so tests stay focused on what
    they're actually exercising.
    """
    digest = f"sha256:{index:064x}"
    tenant_suffix = re.sub(r"[^A-Za-z0-9]", "", tenant_id)
    return {
        "event_id": f"evt_{tenant_suffix}{index:012d}",
        "occurred_at": (BASE_TIME + timedelta(seconds=index)).isoformat(),
        "tenant_id": tenant_id,
        "agent_id": agent_id,
        "release_id": release_id,
        "campaign_id": None,
        "trace_id": trace_id or f"trc_{index:012d}",
        "task_id": task_id or f"tsk_{index:012d}",
        "type": event_type,
        "schema_version": 1,
        "artifact_digests": [digest],
        "model": {"provider": "openai", "name": "gpt-5.3-codex", "version": "2026-08-01"},
        "environment_digest": digest,
        "cost": {"input_tokens": 100 + index, "output_tokens": 50, "usd": 0.01},
        "data_classification": "internal",
        "payload_uri": f"object://traces/{index}",
        "payload_digest": digest,
    }


def make_raw_batch(
    count: int, *, start_index: int = 0, tenant_id: str = "tnt_test"
) -> list[dict[str, Any]]:
    """`count` sequential raw events for one tenant, in chain order."""
    return [make_raw_event(start_index + i, tenant_id=tenant_id) for i in range(count)]


def insert_chain_fixture(session: Session, *, tenant_id: str, count: int) -> list[Event]:
    """Insert `count` correctly-chained events for `tenant_id` in one commit.

    Computes the same chain (`chain_seq`/`prev_hash`/`event_hash`) that
    `evoruntime.db.ingest.ingest_envelope` would, one event at a time, but
    persists it as a single bulk transaction instead of one commit per
    event. Scale tests (10k+ rows) only care that `verify_chain` scans a
    large, genuinely valid chain correctly — the per-event-commit durability
    story is a different property, exercised by `tests/test_fault_injection.py`
    with the real `ingest_envelope` path instead.
    """
    rows: list[Event] = []
    prev_hash = GENESIS_HASH
    for i, raw in enumerate(make_raw_batch(count, tenant_id=tenant_id)):
        envelope = parse_wire_envelope(raw)
        event_hash = compute_event_hash(envelope, prev_hash)
        rows.append(
            Event(
                event_id=envelope.event_id,
                occurred_at=envelope.occurred_at,
                tenant_id=envelope.tenant_id,
                agent_id=envelope.agent_id,
                release_id=envelope.release_id,
                campaign_id=envelope.campaign_id,
                trace_id=envelope.trace_id,
                task_id=envelope.task_id,
                type=envelope.type,
                schema_version=envelope.schema_version,
                artifact_digests=list(envelope.artifact_digests),
                model=envelope.model.model_dump(mode="json"),
                environment_digest=envelope.environment_digest,
                cost=envelope.cost.model_dump(mode="json"),
                data_classification=envelope.data_classification.value,
                payload_uri=envelope.payload_uri,
                payload_digest=envelope.payload_digest,
                chain_seq=i + 1,
                prev_hash=prev_hash,
                event_hash=event_hash,
            )
        )
        prev_hash = event_hash

    session.add_all(rows)
    session.commit()
    return rows


def make_campaign_spec_mapping() -> dict[str, Any]:
    """A minimal valid §11.2 campaign spec as a plain mapping.

    Mirrors the fixture in `tests/campaign/conftest.py` so the API and CLI
    suites can plan a real campaign without importing from another test
    package's conftest.
    """
    return {
        "schema_version": 1,
        "name": "prompt-bundle-campaign-1",
        "incumbent": {
            "release_manifest_digest": "sha256:" + "a" * 64,
            "artifact_type": "prompt_bundle",
        },
        "mutable_artifact": {
            "artifact_type": "prompt_bundle",
            "paths": ["prompts/system.md"],
        },
        "strategy_plugin": {
            "plugin_id": "evo-prompt-strategist",
            "pinned_image": "ghcr.io/evoruntime/strategist@sha256:" + "b" * 64,
        },
        "arms": [
            {"id": "incumbent", "kind": "incumbent"},
            {"id": "retry", "kind": "retry-self-consistency", "max_attempts": 3},
            {"id": "one-shot", "kind": "one-shot-control"},
            {"id": "strategy", "kind": "strategy"},
        ],
        "datasets": {
            "dev_partition": "dev-primary",
            "selection_partition": "selection-primary",
            "holdout_handle": "holdout://ledger/alpha-1",
        },
        "evaluators": [
            {
                "name": "coding-verifier",
                "pinned_image": "ghcr.io/evoruntime/verifier@sha256:" + "c" * 64,
            }
        ],
        "budgets": {
            "task_budget_profile": "task-budget-v1",
            "max_proposals": 10,
            "max_model_tokens": 100_000,
            "max_wall_clock_minutes": 30.0,
        },
        "promotion_policy": {
            "policy_id": "tier-2-standard",
            "policy_digest": "sha256:" + "d" * 64,
        },
        "statistics": {
            "alpha": 0.05,
            "multiplicity": "bonferroni",
            "bootstrap_iterations": 200,
            "bootstrap_seed": 7,
        },
        "stopping_rules": {"max_rounds": 5, "max_no_improvement_rounds": 2},
        "metadata": {"owner": "evaluator"},
    }
