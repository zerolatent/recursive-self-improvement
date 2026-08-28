"""Shared fixtures for the memory-hygiene test suite (deliverable E6).

Follows the registry suite's conventions: tests are tenant-scoped (the
shared `db_session` truncates `memory_entries` alongside the lineage
tables, so each test uses a fresh tenant and asserts only on rows it
wrote), and every entry body embeds the tenant id so digests never
collide across tests.

The `entry` factory builds a §9.3-valid entry that passes intake cleanly
— the hygiene tests then mutate exactly one field to produce each poison
profile, so a failure names the field that broke, not the factory.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from sqlalchemy.orm import Session

from evoruntime.memory.schemas import (
    Claim,
    EvidenceRef,
    MemoryEntry,
    MemoryScope,
    Provenance,
    SemanticType,
    Sensitivity,
    TimeValidity,
)
from evoruntime.memory.service import MemoryService

PASSED_SCORES = [0.8, 0.82, 0.79, 0.81, 0.8, 0.83, 0.78, 0.8, 0.81, 0.8]
"""Paired per-task scores where memory ON is clearly not worse than OFF."""

FAILED_SCORES = [0.3, 0.32, 0.29, 0.31, 0.3, 0.33, 0.28, 0.3, 0.31, 0.3]
"""Paired per-task scores where memory ON is clearly worse than OFF."""


@pytest.fixture
def memory_tenant() -> str:
    """A tenant unique to this test — memory rows accumulate across tests."""
    return f"tnt_{uuid.uuid4().hex[:12]}"


@pytest.fixture
def memory_service(db_session: Session) -> MemoryService:
    return MemoryService(db_session)


def make_entry(**overrides: Any) -> MemoryEntry:
    """A §9.3-valid entry that passes intake: admitted trust domain,
    supporting evidence, open-ended validity."""
    tenant = overrides.pop("tenant", "tnt_factory")
    defaults: dict[str, Any] = {
        "semantic_type": SemanticType.FACT,
        "provenance": Provenance(
            strategy_id=f"strat_{uuid.uuid4().hex[:8]}",
            trust_domain="candidate-proposed",
            source_ref=f"trace://{tenant}/{uuid.uuid4().hex[:8]}",
        ),
        "scope": MemoryScope(
            subject=f"repo_{tenant}",
            environment="ci",
            task_type="test-writing",
        ),
        "claim": Claim(
            key="pytest-fixture-style",
            statement="the repo prefers factory fixtures over setUp methods",
        ),
        "confidence": 0.8,
        "supporting_evidence": (
            EvidenceRef(kind="trace", ref=f"trace://{tenant}/supporting-1"),
            EvidenceRef(kind="task_run", ref=f"run://{tenant}/supporting-2"),
        ),
        "time_validity": TimeValidity(valid_from=datetime.now(UTC) - timedelta(days=1)),
        "sensitivity": Sensitivity.INTERNAL,
    }
    defaults.update(overrides)
    return MemoryEntry(**defaults)


@pytest.fixture
def entry_factory() -> Callable[..., MemoryEntry]:
    """Build a uniquely-claimable entry; pass `tenant` to scope digests."""
    return make_entry


def propose(
    service: MemoryService,
    tenant_id: str,
    entry: MemoryEntry,
    *,
    actor: str = "svc_eval_test",
) -> Any:
    """Propose an entry and return the row (short-hand for tests)."""
    return service.propose_entry(tenant_id=tenant_id, entry=entry, actor_identity=actor)


def passing_gate_inputs() -> dict[str, list[float]]:
    """Gate inputs where persistence non-inferiority and negative transfer
    both clearly pass."""
    return {
        "persistence_on": PASSED_SCORES,
        "persistence_off": PASSED_SCORES,
        "probe_baseline": PASSED_SCORES,
        "probe_with_memory": PASSED_SCORES,
    }
