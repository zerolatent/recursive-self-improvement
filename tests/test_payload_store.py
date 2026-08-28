"""Tests for `PayloadStore`: encrypted storage, content-addressed
idempotency, and tombstone-aware read errors.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from evoruntime.db.models.lineage import Payload
from evoruntime.lineage.deletion import DeletionService
from evoruntime.lineage.exceptions import PayloadAccessRevokedError, PayloadNotFoundError
from evoruntime.lineage.payload_store import PayloadStore, digest_for


@pytest.fixture
def store(db_session: Session) -> PayloadStore:
    return PayloadStore(db_session)


def test_store_then_read_roundtrips_plaintext(store: PayloadStore) -> None:
    plaintext = b"trace event payload bytes"
    payload = store.store(tenant_id="tnt_1", plaintext=plaintext, data_classification="internal")

    assert payload.payload_digest == digest_for(plaintext)
    assert store.read(tenant_id="tnt_1", payload_digest=payload.payload_digest) == plaintext


def test_ciphertext_never_contains_plaintext(store: PayloadStore) -> None:
    plaintext = b"a secret nobody should see raw in the database"
    payload = store.store(tenant_id="tnt_1", plaintext=plaintext, data_classification="internal")

    assert plaintext not in payload.ciphertext


def test_store_is_idempotent_by_content(store: PayloadStore, db_session: Session) -> None:
    plaintext = b"same bytes twice"
    first = store.store(tenant_id="tnt_1", plaintext=plaintext, data_classification="internal")
    second = store.store(tenant_id="tnt_1", plaintext=plaintext, data_classification="internal")

    assert first.id == second.id
    count = len(
        db_session.execute(
            select(Payload).where(
                Payload.tenant_id == "tnt_1", Payload.payload_digest == first.payload_digest
            )
        )
        .scalars()
        .all()
    )
    assert count == 1


def test_read_unknown_digest_raises_not_found(store: PayloadStore) -> None:
    with pytest.raises(PayloadNotFoundError):
        store.read(tenant_id="tnt_1", payload_digest="sha256:" + "0" * 64)


def test_read_after_access_revoked_raises_access_revoked(
    store: PayloadStore, db_session: Session
) -> None:
    plaintext = b"will be deleted"
    payload = store.store(tenant_id="tnt_1", plaintext=plaintext, data_classification="internal")
    deletion = DeletionService(db_session)
    tombstone = deletion.request_deletion(
        tenant_id="tnt_1",
        resource_type="payload",
        resource_id=payload.payload_digest,
        requested_by="usr_1",
    )
    deletion.revoke_access(tombstone)

    with pytest.raises(PayloadAccessRevokedError):
        store.read(tenant_id="tnt_1", payload_digest=payload.payload_digest)


def test_different_tenants_cannot_read_each_others_payloads(store: PayloadStore) -> None:
    plaintext = b"tenant 1 only"
    payload = store.store(tenant_id="tnt_1", plaintext=plaintext, data_classification="internal")

    with pytest.raises(PayloadNotFoundError):
        store.read(tenant_id="tnt_2", payload_digest=payload.payload_digest)
