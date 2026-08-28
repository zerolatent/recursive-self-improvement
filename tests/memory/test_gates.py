"""Promotion-gate tests (FR-016).

The invariant under test: there is exactly one suggestion -> active path
(`MemoryService.promote_entry`) and it refuses unless the persistence
non-inferiority gate, the negative-transfer gate, and the hygiene gate
all pass. A blocked promotion must leave the entry unchanged — same
status, same reason — and must not touch the incumbents it would have
superseded.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from evoruntime.memory.errors import (
    MemoryNotFoundError,
    PromotionBlockedError,
    SupersessionTargetNotFoundError,
)
from evoruntime.memory.schemas import Claim, MemoryStatus, TimeValidity
from tests.memory.conftest import (
    FAILED_SCORES,
    PASSED_SCORES,
    make_entry,
    passing_gate_inputs,
    propose,
)


def _promote(service, tenant: str, memory_id: str, **overrides):
    inputs = passing_gate_inputs()
    inputs.update(overrides)
    return service.promote_entry(
        tenant_id=tenant, memory_id=memory_id, actor_identity="svc_eval_test", **inputs
    )


def test_promotion_blocked_without_gate_inputs(memory_service, memory_tenant) -> None:
    """Empty score lists mean the evaluation was never run — refuse."""
    row = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    with pytest.raises(PromotionBlockedError) as excinfo:
        _promote(
            memory_service,
            memory_tenant,
            row.memory_id,
            persistence_on=[],
            persistence_off=[],
            probe_baseline=[],
            probe_with_memory=[],
        )
    assert "persistence_non_inferiority" in excinfo.value.report.failures


def test_promotion_blocked_when_persistence_regresses(memory_service, memory_tenant) -> None:
    row = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    with pytest.raises(PromotionBlockedError) as excinfo:
        _promote(
            memory_service,
            memory_tenant,
            row.memory_id,
            persistence_on=FAILED_SCORES,
            persistence_off=PASSED_SCORES,
        )
    assert "persistence_non_inferiority" in excinfo.value.report.failures


def test_promotion_blocked_on_negative_transfer(memory_service, memory_tenant) -> None:
    row = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    with pytest.raises(PromotionBlockedError) as excinfo:
        _promote(
            memory_service,
            memory_tenant,
            row.memory_id,
            probe_baseline=PASSED_SCORES,
            probe_with_memory=FAILED_SCORES,
        )
    assert "negative_transfer" in excinfo.value.report.failures


def test_blocked_promotion_leaves_entry_unchanged(memory_service, memory_tenant) -> None:
    row = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    with pytest.raises(PromotionBlockedError):
        _promote(
            memory_service,
            memory_tenant,
            row.memory_id,
            persistence_on=FAILED_SCORES,
            persistence_off=PASSED_SCORES,
        )
    reloaded = memory_service.get_entry(tenant_id=memory_tenant, memory_id=row.memory_id)
    assert reloaded.status == MemoryStatus.SUGGESTION
    assert reloaded.status_reason == row.status_reason


def test_promotion_blocked_for_quarantined_entry(memory_service, memory_tenant) -> None:
    """Even perfect gate scores cannot promote a quarantined entry — the
    hygiene gate is not overridable by evaluation results."""
    entry = make_entry(tenant=memory_tenant, supporting_evidence=())
    row = propose(memory_service, memory_tenant, entry)
    assert row.status == MemoryStatus.QUARANTINED
    with pytest.raises(PromotionBlockedError) as excinfo:
        _promote(memory_service, memory_tenant, row.memory_id)
    assert "hygiene_clear" in excinfo.value.report.failures


def test_promotion_blocked_while_conflict_unresolved(memory_service, memory_tenant) -> None:
    """Defense-in-depth backstop: intake quarantines any newcomer that
    conflicts with a live entry, so the service API alone cannot produce
    two live competing claims. The gate must still refuse to promote into
    that state if it ever arises (e.g. rows written before a scope
    tightened, or a direct DB write) — so the test constructs it directly
    by flipping a quarantined rival back to SUGGESTION, bypassing intake."""
    first = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    rival = make_entry(
        tenant=memory_tenant,
        claim=Claim(
            key=first.claim_key,
            statement="a competing claim that arrived before promotion",
        ),
    )
    rival_row = propose(memory_service, memory_tenant, rival)
    assert rival_row.status == MemoryStatus.QUARANTINED  # intake resolved it

    # Simulate the out-of-band state: the rival is live again.
    rival_row.status = MemoryStatus.SUGGESTION
    rival_row.status_reason = None
    memory_service._session.flush()

    with pytest.raises(PromotionBlockedError) as excinfo:
        _promote(memory_service, memory_tenant, first.memory_id)
    assert "hygiene_clear" in excinfo.value.report.failures
    assert "unresolved conflicting claim" in excinfo.value.report.results[-1].detail


def test_promotion_succeeds_when_all_gates_pass(memory_service, memory_tenant) -> None:
    row = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    promoted = _promote(memory_service, memory_tenant, row.memory_id)
    assert promoted.status == MemoryStatus.ACTIVE
    assert promoted.status_reason is None


def test_promotion_of_unknown_memory_raises(memory_service, memory_tenant) -> None:
    with pytest.raises(MemoryNotFoundError):
        _promote(memory_service, memory_tenant, "mem_does_not_exist")


def test_promotion_supersedes_declared_targets(memory_service, memory_tenant) -> None:
    old = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    replacement = make_entry(
        tenant=memory_tenant,
        claim=Claim(
            key=old.claim_key,
            statement=old.claim_statement,
        ),
        supersedes=(old.memory_id,),
    )
    row = propose(memory_service, memory_tenant, replacement)
    _promote(memory_service, memory_tenant, row.memory_id)
    assert row.status == MemoryStatus.ACTIVE
    superseded = memory_service.get_entry(tenant_id=memory_tenant, memory_id=old.memory_id)
    assert superseded.status == MemoryStatus.REVOKED
    assert superseded.status_reason == f"superseded by {row.memory_id}"


def test_dangling_supersession_link_blocks_promotion(memory_service, memory_tenant) -> None:
    replacement = make_entry(tenant=memory_tenant, supersedes=("mem_missing_target",))
    row = propose(memory_service, memory_tenant, replacement)
    with pytest.raises(SupersessionTargetNotFoundError):
        _promote(memory_service, memory_tenant, row.memory_id)
    reloaded = memory_service.get_entry(tenant_id=memory_tenant, memory_id=row.memory_id)
    assert reloaded.status == MemoryStatus.SUGGESTION


def test_no_entry_reaches_active_except_via_promotion(memory_service, memory_tenant) -> None:
    """Suggestion-first, end to end: propose a batch of entries — clean,
    poison, and stale — and assert none of them is ACTIVE without an
    explicit gated promotion call."""
    entries = [
        make_entry(tenant=memory_tenant),
        make_entry(tenant=memory_tenant, supporting_evidence=()),
        make_entry(
            tenant=memory_tenant,
            time_validity=TimeValidity(
                valid_from=datetime.now(UTC) - timedelta(days=5),
                valid_until=datetime.now(UTC) - timedelta(hours=2),
            ),
        ),
    ]
    rows = [propose(memory_service, memory_tenant, entry) for entry in entries]
    assert all(row.status != MemoryStatus.ACTIVE for row in rows)
