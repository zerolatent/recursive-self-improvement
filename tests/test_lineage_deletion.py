"""D4 acceptance: the tombstone-driven deletion flow.

request_deletion -> tombstone row -> access revoked (<=5min SLO,
shortened here via `sla_seconds` overrides) -> derived data purged
(<=24h SLO). Covers embeddings/caches fixture rows via
`DerivedDataRecord`, as the D4 acceptance criteria require.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from evoruntime.db.models.lineage import DerivedDataRecord, Payload
from evoruntime.lineage.deletion import DeletionService
from evoruntime.lineage.payload_store import PayloadStore
from evoruntime.lineage.purge import run_access_revocation_sweep, run_derived_purge_sweep


@pytest.fixture
def deletion(db_session: Session) -> DeletionService:
    return DeletionService(db_session)


def _seed_payload_with_derived_data(db_session: Session, *, tenant_id: str = "tnt_1") -> Payload:
    payload = PayloadStore(db_session).store(
        tenant_id=tenant_id, plaintext=b"trace payload", data_classification="internal"
    )
    for kind in ("embedding", "cache"):
        db_session.add(
            DerivedDataRecord(
                tenant_id=tenant_id,
                resource_id=payload.payload_digest,
                kind=kind,
                ref=f"{kind}-ref-1",
            )
        )
    db_session.flush()
    return payload


def test_request_deletion_creates_tombstone(deletion: DeletionService, db_session: Session) -> None:
    payload = _seed_payload_with_derived_data(db_session)

    tombstone = deletion.request_deletion(
        tenant_id="tnt_1",
        resource_type="payload",
        resource_id=payload.payload_digest,
        requested_by="usr_1",
        reason="user requested erasure",
    )

    assert tombstone.access_revoked_at is None
    assert tombstone.purge_completed_at is None


def test_revoke_access_deletes_payload_row(deletion: DeletionService, db_session: Session) -> None:
    payload = _seed_payload_with_derived_data(db_session)
    tombstone = deletion.request_deletion(
        tenant_id="tnt_1",
        resource_type="payload",
        resource_id=payload.payload_digest,
        requested_by="usr_1",
    )

    deletion.revoke_access(tombstone)

    assert tombstone.access_revoked_at is not None
    remaining = db_session.execute(
        select(Payload).where(Payload.id == payload.id)
    ).scalar_one_or_none()
    assert remaining is None


def test_revoke_access_is_idempotent(deletion: DeletionService, db_session: Session) -> None:
    payload = _seed_payload_with_derived_data(db_session)
    tombstone = deletion.request_deletion(
        tenant_id="tnt_1",
        resource_type="payload",
        resource_id=payload.payload_digest,
        requested_by="usr_1",
    )

    deletion.revoke_access(tombstone)
    deletion.revoke_access(tombstone)  # payload already gone — must not raise


def test_purge_derived_data_removes_fixture_rows(
    deletion: DeletionService, db_session: Session
) -> None:
    payload = _seed_payload_with_derived_data(db_session)
    tombstone = deletion.request_deletion(
        tenant_id="tnt_1",
        resource_type="payload",
        resource_id=payload.payload_digest,
        requested_by="usr_1",
    )
    deletion.revoke_access(tombstone)

    purged_count = deletion.purge_derived_data(tombstone)

    assert purged_count == 2
    remaining = (
        db_session.execute(
            select(DerivedDataRecord).where(DerivedDataRecord.resource_id == payload.payload_digest)
        )
        .scalars()
        .all()
    )
    assert remaining == []
    assert tombstone.purge_completed_at is not None


def test_access_revocation_sweep_processes_expired_tombstones(
    deletion: DeletionService, db_session: Session
) -> None:
    payload = _seed_payload_with_derived_data(db_session)
    tombstone = deletion.request_deletion(
        tenant_id="tnt_1",
        resource_type="payload",
        resource_id=payload.payload_digest,
        requested_by="usr_1",
    )
    # Shorten the SLO to 1 second and simulate 2 seconds having passed —
    # avoids a real 5-minute wall-clock sleep in the test suite.
    processed = run_access_revocation_sweep(
        db_session, now=datetime.now(UTC) + timedelta(seconds=2), sla_seconds=1
    )

    assert [t.id for t in processed] == [tombstone.id]
    db_session.refresh(tombstone)
    assert tombstone.access_revoked_at is not None
    assert (
        db_session.execute(select(Payload).where(Payload.id == payload.id)).scalar_one_or_none()
        is None
    )


def test_access_revocation_sweep_skips_tombstones_within_sla(
    deletion: DeletionService, db_session: Session
) -> None:
    payload = _seed_payload_with_derived_data(db_session)
    deletion.request_deletion(
        tenant_id="tnt_1",
        resource_type="payload",
        resource_id=payload.payload_digest,
        requested_by="usr_1",
    )

    processed = run_access_revocation_sweep(db_session, sla_seconds=300)

    assert processed == []


def test_derived_purge_sweep_only_processes_already_revoked_tombstones(
    deletion: DeletionService, db_session: Session
) -> None:
    payload = _seed_payload_with_derived_data(db_session)
    tombstone = deletion.request_deletion(
        tenant_id="tnt_1",
        resource_type="payload",
        resource_id=payload.payload_digest,
        requested_by="usr_1",
    )

    # Access not yet revoked — the purge sweep must not touch it, even
    # though its "requested_at" is already far in the past.
    processed = run_derived_purge_sweep(
        db_session, now=datetime.now(UTC) + timedelta(days=2), sla_seconds=1
    )
    assert processed == []

    deletion.revoke_access(tombstone, now=datetime.now(UTC))
    processed = run_derived_purge_sweep(
        db_session, now=datetime.now(UTC) + timedelta(seconds=2), sla_seconds=1
    )

    assert [t.id for t in processed] == [tombstone.id]
    remaining = (
        db_session.execute(
            select(DerivedDataRecord).where(DerivedDataRecord.resource_id == payload.payload_digest)
        )
        .scalars()
        .all()
    )
    assert remaining == []


def test_full_deletion_flow_end_to_end(deletion: DeletionService, db_session: Session) -> None:
    """The complete request -> revoke -> purge pipeline, driven entirely
    through the sweep functions a scheduler would call.
    """
    payload = _seed_payload_with_derived_data(db_session)
    tombstone = deletion.request_deletion(
        tenant_id="tnt_1",
        resource_type="payload",
        resource_id=payload.payload_digest,
        requested_by="usr_1",
    )

    t0 = datetime.now(UTC)
    run_access_revocation_sweep(db_session, now=t0 + timedelta(seconds=2), sla_seconds=1)
    run_derived_purge_sweep(db_session, now=t0 + timedelta(seconds=4), sla_seconds=1)

    db_session.refresh(tombstone)
    assert tombstone.access_revoked_at is not None
    assert tombstone.purge_completed_at is not None
    assert (
        db_session.execute(select(Payload).where(Payload.id == payload.id)).scalar_one_or_none()
        is None
    )
    assert (
        db_session.execute(
            select(DerivedDataRecord).where(DerivedDataRecord.resource_id == payload.payload_digest)
        )
        .scalars()
        .all()
        == []
    )
