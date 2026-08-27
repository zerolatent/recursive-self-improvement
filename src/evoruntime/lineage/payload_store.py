"""Content-addressed, tenant-key-encrypted payload storage.

Payloads are stored separately from the trace event envelope that
references them (PRD §18.3, spec Data model section): the envelope carries
a `payload_digest`; the actual bytes live here, encrypted at rest, and are
independently deletable without touching the (append-only) envelope
record — which is what makes the deletion flow possible at all.
"""

from __future__ import annotations

import hashlib
from typing import NoReturn

from sqlalchemy import select
from sqlalchemy.orm import Session

from evoruntime.db.models.lineage import Payload, Tombstone
from evoruntime.lineage.crypto import TenantKeyProvider
from evoruntime.lineage.exceptions import PayloadAccessRevokedError, PayloadNotFoundError


def digest_for(plaintext: bytes) -> str:
    """Return the content digest a caller should use as `payload_digest`."""
    return f"sha256:{hashlib.sha256(plaintext).hexdigest()}"


class PayloadStore:
    """Stores and retrieves encrypted payload content, keyed by
    `(tenant_id, payload_digest)`.
    """

    def __init__(self, session: Session, key_provider: TenantKeyProvider | None = None) -> None:
        self._session = session
        self._keys = key_provider or TenantKeyProvider()

    def store(
        self,
        *,
        tenant_id: str,
        plaintext: bytes,
        data_classification: str,
    ) -> Payload:
        """Store `plaintext` for `tenant_id`, encrypting it first.

        Idempotent by content: storing the same bytes for the same tenant
        again returns the existing row rather than creating a duplicate,
        since `payload_digest` is a content address.
        """
        payload_digest = digest_for(plaintext)
        existing = self._session.execute(
            select(Payload).where(
                Payload.tenant_id == tenant_id, Payload.payload_digest == payload_digest
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing

        ciphertext = self._keys.encrypt(tenant_id, plaintext)
        payload = Payload(
            tenant_id=tenant_id,
            payload_digest=payload_digest,
            data_classification=data_classification,
            ciphertext=ciphertext,
            encryption_key_id=self._keys.key_version,
            byte_size=len(plaintext),
        )
        self._session.add(payload)
        self._session.flush()
        return payload

    def read(self, *, tenant_id: str, payload_digest: str) -> bytes:
        """Decrypt and return the plaintext for `(tenant_id, payload_digest)`.

        Raises `PayloadAccessRevokedError` (not `PayloadNotFoundError`) when
        the digest is claimed by a tombstone whose access has already been
        revoked, so callers can distinguish "never existed" from "was
        deleted on request" — the deletion flow's whole point is that the
        second case is provable, not silent.
        """
        payload = self._session.execute(
            select(Payload).where(
                Payload.tenant_id == tenant_id, Payload.payload_digest == payload_digest
            )
        ).scalar_one_or_none()
        if payload is None:
            self._raise_not_found_or_revoked(tenant_id=tenant_id, payload_digest=payload_digest)
        return self._keys.decrypt(tenant_id, payload.ciphertext)

    def _raise_not_found_or_revoked(self, *, tenant_id: str, payload_digest: str) -> NoReturn:
        tombstone = self._session.execute(
            select(Tombstone).where(
                Tombstone.tenant_id == tenant_id,
                Tombstone.resource_type == "payload",
                Tombstone.resource_id == payload_digest,
                Tombstone.access_revoked_at.is_not(None),
            )
        ).scalar_one_or_none()
        if tombstone is not None:
            raise PayloadAccessRevokedError(
                f"payload {payload_digest!r} for tenant {tenant_id!r} was deleted "
                f"on request {tombstone.requested_at.isoformat()}"
            )
        raise PayloadNotFoundError(f"no payload {payload_digest!r} for tenant {tenant_id!r}")
