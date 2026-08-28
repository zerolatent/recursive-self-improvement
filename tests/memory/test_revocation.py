"""Revocation, purge-propagation, and TTL tests (§17.3 memory-hygiene row).

Revocation must propagate through the D4 tombstone machinery — memory
adds no deletion path of its own. The assertions here follow the
tombstone through both SLO sweeps: access revocation (payload row hard-
deleted) and derived-data purge (embeddings, caches, plugin checkpoints,
exports registered against the payload digest all removed). Generalized
lessons citing revoked evidence are quarantined, not deleted; revoking a
lesson never touches its evidence entries.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from evoruntime.db.models.lineage import DerivedDataRecord
from evoruntime.db.models.registry import ArtifactContent
from evoruntime.lineage.purge import run_access_revocation_sweep, run_derived_purge_sweep
from evoruntime.memory.schemas import Claim, MemoryStatus, TimeValidity
from evoruntime.registry.canonical import STORAGE_URI_SCHEME
from tests.memory.conftest import make_entry, passing_gate_inputs, propose


def _payload_digest(service, tenant: str, memory_id: str) -> str:
    row = service.get_entry(tenant_id=tenant, memory_id=memory_id)
    artifact = service._session.execute(
        select(ArtifactContent).where(
            ArtifactContent.tenant_id == tenant, ArtifactContent.digest == row.artifact_digest
        )
    ).scalar_one()
    return artifact.storage_uri.removeprefix(f"{STORAGE_URI_SCHEME}://")


def _revoke(service, tenant: str, memory_id: str, reason: str):
    return service.revoke_entry(
        tenant_id=tenant,
        memory_id=memory_id,
        reason=reason,
        requested_by="svc_eval_test",
        actor_identity="svc_eval_test",
    )


def _promote(service, tenant: str, memory_id: str) -> None:
    service.promote_entry(
        tenant_id=tenant,
        memory_id=memory_id,
        actor_identity="svc_eval_test",
        **passing_gate_inputs(),
    )


def test_revocation_revokes_the_entry(memory_service, memory_tenant) -> None:
    row = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    outcome = _revoke(memory_service, memory_tenant, row.memory_id, "poison confirmed by audit")
    assert outcome.revoked.status == MemoryStatus.REVOKED
    assert outcome.revoked.status_reason == "poison confirmed by audit"


def test_revocation_requests_a_tombstone_over_the_payload(memory_service, memory_tenant) -> None:
    row = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    outcome = _revoke(memory_service, memory_tenant, row.memory_id, "poison confirmed by audit")
    assert outcome.tombstone.resource_type == "payload"
    assert outcome.tombstone.resource_id == _payload_digest(
        memory_service, memory_tenant, row.memory_id
    )
    assert outcome.tombstone.access_revoked_at is None  # the sweep's job, not intake's


def test_revocation_propagates_through_both_d4_sweeps(memory_service, memory_tenant) -> None:
    """The full propagation chain: revoke -> tombstone -> access-revocation
    sweep (payload row gone) -> derived-purge sweep (every derived record
    gone). Memory-specific purge code: none."""
    row = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    payload_digest = _payload_digest(memory_service, memory_tenant, row.memory_id)
    for kind, ref in [
        ("embedding", f"pgvector://{memory_tenant}/{row.memory_id}"),
        ("cache", f"redis://{memory_tenant}/{row.memory_id}"),
        ("plugin_checkpoint", f"oci://{memory_tenant}/{row.memory_id}"),
        ("export", f"s3://exports/{memory_tenant}/{row.memory_id}"),
    ]:
        memory_service.register_derived_data(
            tenant_id=memory_tenant, memory_id=row.memory_id, kind=kind, ref=ref
        )

    outcome = _revoke(memory_service, memory_tenant, row.memory_id, "poison confirmed by audit")

    now = datetime.now(UTC)
    assert run_access_revocation_sweep(memory_service._session, now=now, sla_seconds=0)
    assert run_derived_purge_sweep(memory_service._session, now=now, sla_seconds=0)

    remaining = (
        memory_service._session.execute(
            select(DerivedDataRecord).where(
                DerivedDataRecord.tenant_id == memory_tenant,
                DerivedDataRecord.resource_id == payload_digest,
            )
        )
        .scalars()
        .all()
    )
    assert list(remaining) == []
    assert outcome.tombstone.access_revoked_at is not None
    assert outcome.tombstone.purge_completed_at is not None


def test_revocation_quarantines_dependent_lessons(memory_service, memory_tenant) -> None:
    evidence = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    lesson = make_entry(
        tenant=memory_tenant,
        is_generalized_lesson=True,
        parent_memory_ids=(evidence.memory_id,),
        claim=Claim(
            key="generalization",
            statement="factories beat setUp across this repo's test suites",
        ),
    )
    lesson_row = propose(memory_service, memory_tenant, lesson)
    assert lesson_row.status == MemoryStatus.SUGGESTION

    outcome = _revoke(memory_service, memory_tenant, evidence.memory_id, "evidence retracted")
    assert outcome.quarantined_lessons == (lesson_row,)
    assert lesson_row.status == MemoryStatus.QUARANTINED
    assert evidence.memory_id in (lesson_row.status_reason or "")


def test_revoking_a_lesson_never_touches_its_evidence(memory_service, memory_tenant) -> None:
    evidence = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    lesson = make_entry(
        tenant=memory_tenant,
        is_generalized_lesson=True,
        parent_memory_ids=(evidence.memory_id,),
        claim=Claim(key="generalization", statement="a lesson derived from the evidence"),
    )
    lesson_row = propose(memory_service, memory_tenant, lesson)

    _revoke(memory_service, memory_tenant, lesson_row.memory_id, "bad abstraction")
    assert lesson_row.status == MemoryStatus.REVOKED
    assert evidence.status == MemoryStatus.SUGGESTION  # untouched


def test_derived_data_rejects_unknown_kinds(memory_service, memory_tenant) -> None:
    row = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    with pytest.raises(ValueError):  # noqa: PT011 - narrow kind validation
        memory_service.register_derived_data(
            tenant_id=memory_tenant, memory_id=row.memory_id, kind="sidecar_db", ref="x://y"
        )


def test_ttl_expiry_retires_only_entries_past_their_ttl(memory_service, memory_tenant) -> None:
    now = datetime.now(UTC)
    already_stale = propose(
        memory_service,
        memory_tenant,
        make_entry(
            tenant=memory_tenant,
            time_validity=TimeValidity(
                valid_from=now - timedelta(days=2), valid_until=now - timedelta(hours=1)
            ),
        ),
    )
    assert already_stale.status == MemoryStatus.QUARANTINED  # stale at intake

    expired_active = propose(
        memory_service,
        memory_tenant,
        make_entry(
            tenant=memory_tenant,
            time_validity=TimeValidity(
                valid_from=now - timedelta(days=1), valid_until=now + timedelta(hours=1)
            ),
        ),
    )
    _promote(memory_service, memory_tenant, expired_active.memory_id)
    assert expired_active.status == MemoryStatus.ACTIVE

    not_yet_stale = propose(
        memory_service,
        memory_tenant,
        make_entry(
            tenant=memory_tenant,
            time_validity=TimeValidity(
                valid_from=now - timedelta(days=1), valid_until=now + timedelta(days=30)
            ),
        ),
    )
    open_ended = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))

    # Nothing has passed its TTL yet.
    assert memory_service.expire_stale(now=now) == []

    # Two hours later, only the entry whose valid_until has passed retires.
    later = now + timedelta(hours=2)
    stale_rows = memory_service.expire_stale(now=later)
    assert [row.memory_id for row in stale_rows] == [expired_active.memory_id]
    assert expired_active.status == MemoryStatus.EXPIRED
    assert not_yet_stale.status == MemoryStatus.SUGGESTION
    assert open_ended.status == MemoryStatus.SUGGESTION


def test_retrieval_utility_is_recorded(memory_service, memory_tenant) -> None:
    row = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    assert row.retrieval_count == 0
    now = datetime.now(UTC)
    memory_service.record_retrieval(tenant_id=memory_tenant, memory_id=row.memory_id, now=now)
    memory_service.record_retrieval(tenant_id=memory_tenant, memory_id=row.memory_id, now=now)
    assert row.retrieval_count == 2
    assert row.last_retrieved_at == now
