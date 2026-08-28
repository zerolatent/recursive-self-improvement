"""E1 acceptance: the five-record model's core behavior.

Registration is content-addressed and deterministic; the digested body
excludes the generated id, storage URI, and signature; canonical bytes
round-trip through the per-tenant-encrypted payload store; and the
artifact digest is re-verified on every read.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from evoruntime.db.models.lineage import Payload
from evoruntime.db.models.registry import ArtifactContent
from evoruntime.lineage.crypto import TenantKeyProvider
from evoruntime.registry import canonical
from evoruntime.registry.errors import ArtifactNotFoundError, DigestMismatchError
from evoruntime.registry.service import RegistryService

from .conftest import unique_body


def test_register_artifact_computes_content_addressed_digest(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    body = unique_body(registry_tenant, "digest-check")
    artifact = registry_service.register_artifact(
        tenant_id=registry_tenant,
        artifact_type="prompt_bundle",
        canonical_bytes=body,
        capability_requests={"model": {"allow": ["gpt-5-mini"]}},
    )

    expected = canonical.artifact_digest_for(
        artifact_type="prompt_bundle",
        canonical_body_digest=canonical.payload_body_digest(body),
        dependencies=[],
        capability_requests={"model": {"allow": ["gpt-5-mini"]}},
    )
    assert artifact.digest == expected
    assert artifact.digest.startswith("sha256:")


def test_digest_excludes_generated_id_storage_uri_and_signature(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    """PRD §9.2: the digest covers the canonical body only. The generated
    id and storage URI are derived from (or point at) the body — they must
    not be able to change what the digest vouches for."""
    body = unique_body(registry_tenant, "exclusion")
    first = registry_service.register_artifact(
        tenant_id=registry_tenant, artifact_type="memory_entry", canonical_bytes=body
    )

    assert first.artifact_id not in first.digest
    assert first.storage_uri not in first.digest
    # Recomputing from the digested body alone reproduces the digest.
    recomputed = canonical.artifact_digest_for(
        artifact_type=first.artifact_type,
        canonical_body_digest=first.canonical_body_digest,
        dependencies=list(first.dependencies),
        capability_requests=dict(first.capability_requests),
    )
    assert recomputed == first.digest


def test_canonical_bytes_round_trip_through_encrypted_payload_store(
    registry_service: RegistryService, registry_tenant: str, db_session: Session
) -> None:
    body = unique_body(registry_tenant, "roundtrip")
    artifact = registry_service.register_artifact(
        tenant_id=registry_tenant, artifact_type="prompt_bundle", canonical_bytes=body
    )

    assert registry_service.read_artifact(tenant_id=registry_tenant, digest=artifact.digest) == body
    # The payload row really is ciphertext, not plaintext at rest.
    payload_digest = artifact.storage_uri.removeprefix(f"{canonical.STORAGE_URI_SCHEME}://")
    payload = db_session.execute(
        select(Payload).where(Payload.payload_digest == payload_digest)
    ).scalar_one()
    assert payload.ciphertext != body
    assert body not in payload.ciphertext


def test_registration_is_idempotent_for_identical_content(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    body = unique_body(registry_tenant, "idempotent")
    first = registry_service.register_artifact(
        tenant_id=registry_tenant, artifact_type="prompt_bundle", canonical_bytes=body
    )
    second = registry_service.register_artifact(
        tenant_id=registry_tenant, artifact_type="prompt_bundle", canonical_bytes=body
    )
    assert first.digest == second.digest
    assert first.id == second.id


def test_identical_content_in_two_tenants_gets_independent_rows(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    """Content addressing is scoped per tenant: the second tenant's
    registration of byte-identical content must not resolve to the first
    tenant's row (cross-tenant leak dressed up as deduplication)."""
    body = unique_body(registry_tenant, "shared-content")
    other_tenant = f"tnt_{uuid.uuid4().hex[:12]}"
    first = registry_service.register_artifact(
        tenant_id=registry_tenant, artifact_type="prompt_bundle", canonical_bytes=body
    )
    second = registry_service.register_artifact(
        tenant_id=other_tenant, artifact_type="prompt_bundle", canonical_bytes=body
    )
    assert first.digest == second.digest  # same content, same address
    assert first.id != second.id  # ...but independent, tenant-scoped rows


def test_read_of_unknown_digest_raises_artifact_not_found(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    with pytest.raises(ArtifactNotFoundError):
        registry_service.read_artifact(tenant_id=registry_tenant, digest=f"sha256:{'0' * 64}")


def test_read_reverifies_digest_against_tampered_storage(
    registry_service: RegistryService, registry_tenant: str, db_session: Session
) -> None:
    """Storage-layer corruption (or a swapped payload) must be caught on
    read: the bytes no longer hash to the recorded canonical body digest."""
    body = unique_body(registry_tenant, "tamper-target")
    artifact = registry_service.register_artifact(
        tenant_id=registry_tenant, artifact_type="prompt_bundle", canonical_bytes=body
    )
    db_session.commit()

    # Simulate corruption: re-encrypt different plaintext under the same
    # tenant key, in place, under the same payload digest.
    payload_digest = artifact.storage_uri.removeprefix(f"{canonical.STORAGE_URI_SCHEME}://")
    keys = TenantKeyProvider()
    forged = keys.encrypt(registry_tenant, unique_body(registry_tenant, "forged"))
    db_session.execute(
        text("UPDATE payloads SET ciphertext = :c WHERE payload_digest = :d"),
        {"c": forged, "d": payload_digest},
    )
    db_session.commit()

    with pytest.raises(DigestMismatchError, match="hash to"):
        registry_service.read_artifact(tenant_id=registry_tenant, digest=artifact.digest)


def test_artifact_row_is_immutable_at_the_database_level(
    registry_service: RegistryService, registry_tenant: str, db_session: Session
) -> None:
    artifact = registry_service.register_artifact(
        tenant_id=registry_tenant,
        artifact_type="prompt_bundle",
        canonical_bytes=unique_body(registry_tenant, "immutable"),
    )
    db_session.commit()

    with pytest.raises(ProgrammingError, match="append-only table"):
        db_session.execute(
            text("UPDATE artifact_content SET artifact_type = 'mutated' WHERE id = :id"),
            {"id": str(artifact.id)},
        )
    db_session.rollback()

    with pytest.raises(ProgrammingError, match="append-only table"):
        db_session.execute(
            text("DELETE FROM artifact_content WHERE id = :id"), {"id": str(artifact.id)}
        )
    db_session.rollback()

    # Registry tables accumulate across tests — select this artifact's row.
    assert (
        db_session.execute(select(ArtifactContent).where(ArtifactContent.id == artifact.id))
        .scalar_one()
        .artifact_type
        == "prompt_bundle"
    )
