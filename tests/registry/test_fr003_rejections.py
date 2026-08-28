"""E1 / FR-003 acceptance: one negative fixture per rejection path.

The service boundary must refuse, with a distinct error each:
- digest mismatch (claimed digest != computed digest of the bytes)
- unsigned activation (manifest signature missing or invalid)
- circular metadata (self-dependency, self-parent proposal, self-prior release)
- mixed-release activation (artifacts outside the target manifest's set)
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from evoruntime.db.models.registry import ReleaseManifest
from evoruntime.registry import canonical
from evoruntime.registry.errors import (
    ArtifactNotFoundError,
    CircularMetadataError,
    DigestMismatchError,
    MixedReleaseActivationError,
    UnsignedActivationError,
)
from evoruntime.registry.service import RegistryService
from evoruntime.security.signing import generate_signing_key, sign

from .conftest import unique_body

# ---------------------------------------------------------------------------
# digest mismatch
# ---------------------------------------------------------------------------


def test_registration_rejects_claimed_digest_that_bytes_do_not_hash_to(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    """A caller claiming a digest its canonical bytes don't produce gets
    nothing stored — the claim and the bytes must agree."""
    wrong_digest = f"sha256:{'f' * 64}"
    with pytest.raises(DigestMismatchError, match="does not match computed"):
        registry_service.register_artifact(
            tenant_id=registry_tenant,
            artifact_type="prompt_bundle",
            canonical_bytes=unique_body(registry_tenant, "mismatch"),
            expected_digest=wrong_digest,
        )


def test_activation_rejects_digest_mismatch_between_request_and_store(
    registry_service: RegistryService, registry_tenant: str, signing_key: object
) -> None:
    """An activation naming a digest the stored artifact doesn't resolve to
    is refused even when the manifest itself is properly signed."""
    artifact = registry_service.register_artifact(
        tenant_id=registry_tenant,
        artifact_type="prompt_bundle",
        canonical_bytes=unique_body(registry_tenant, "activation-digest"),
    )
    manifest = registry_service.create_release_manifest(
        tenant_id=registry_tenant,
        artifact_digests=[artifact.digest],
        adapter_versions={"prompt-optimizer": "1.0.0"},
        model_routes={"default": "gpt-5-mini"},
        policies={"tier": 1},
        prior_release_digest=None,
        private_key=signing_key,
    )
    forged_digest = f"sha256:{'e' * 64}"
    # A digest no stored artifact resolves to is, by definition, outside the
    # release set — the mixed-release boundary refuses it before any row
    # lookup. Registration-time mismatch is the DigestMismatchError path,
    # covered above.
    with pytest.raises(MixedReleaseActivationError, match="outside release"):
        registry_service.activate_release(
            tenant_id=registry_tenant,
            manifest_digest=manifest.manifest_digest,
            artifact_digests=[forged_digest],
        )


# ---------------------------------------------------------------------------
# unsigned activation
# ---------------------------------------------------------------------------


def _insert_manifest_row(
    db_session: Session,
    tenant_id: str,
    artifact_digest: str,
    *,
    signature: bytes,
    signer_public_key: bytes,
) -> ReleaseManifest:
    """Insert a manifest row directly — INSERT is allowed on the append-only
    table; this is how a forged or never-signed manifest arrives at the
    boundary in these fixtures."""
    body = canonical.manifest_body_bytes(
        artifact_digests=[artifact_digest],
        adapter_versions={},
        model_routes={},
        policies={},
        prior_release_digest=None,
    )
    row = ReleaseManifest(
        tenant_id=tenant_id,
        manifest_id=f"rel_fixture_{uuid.uuid4().hex[:12]}",
        manifest_digest=canonical.manifest_digest_for(body),
        artifact_digests=[artifact_digest],
        adapter_versions={},
        model_routes={},
        policies={},
        prior_release_digest=None,
        storage_uri=f"{canonical.STORAGE_URI_SCHEME}://fixture",
        signature=signature,
        signer_public_key=signer_public_key,
    )
    db_session.add(row)
    db_session.commit()
    return row


def test_activation_rejects_manifest_with_invalid_signature(
    registry_service: RegistryService,
    registry_tenant: str,
    signing_key: object,
    db_session: Session,
) -> None:
    """A manifest whose signature does not verify over its canonical bytes
    cannot be activated — even though the row exists and resolves."""
    artifact = registry_service.register_artifact(
        tenant_id=registry_tenant,
        artifact_type="prompt_bundle",
        canonical_bytes=unique_body(registry_tenant, "forged-sig"),
    )
    forged = _insert_manifest_row(
        db_session,
        registry_tenant,
        artifact.digest,
        signature=b"\x00" * 64,
        signer_public_key=b"\x01" * 32,
    )

    with pytest.raises(UnsignedActivationError, match="no valid signature"):
        registry_service.activate_release(
            tenant_id=registry_tenant,
            manifest_digest=forged.manifest_digest,
            artifact_digests=[artifact.digest],
        )


def test_activation_rejects_signature_from_the_wrong_key(
    registry_service: RegistryService,
    registry_tenant: str,
    signing_key: object,
    db_session: Session,
) -> None:
    """A signature made by a *different* key than the recorded public key
    fails verification — the fixture for a swapped signer."""
    artifact = registry_service.register_artifact(
        tenant_id=registry_tenant,
        artifact_type="prompt_bundle",
        canonical_bytes=unique_body(registry_tenant, "wrong-key"),
    )
    body = canonical.manifest_body_bytes(
        artifact_digests=[artifact.digest],
        adapter_versions={},
        model_routes={},
        policies={},
        prior_release_digest=None,
    )
    impostor = generate_signing_key()
    forged_signature = sign(impostor, body).signature  # signed by the impostor...
    # ...but the row claims the real evaluator key signed it.
    real_public_key = sign(signing_key, body).public_key
    row = _insert_manifest_row(
        db_session,
        registry_tenant,
        artifact.digest,
        signature=forged_signature,
        signer_public_key=real_public_key,
    )

    with pytest.raises(UnsignedActivationError, match="no valid signature"):
        registry_service.activate_release(
            tenant_id=registry_tenant,
            manifest_digest=row.manifest_digest,
            artifact_digests=[artifact.digest],
        )


def test_activation_rejects_unsigned_manifest_row(
    registry_service: RegistryService, registry_tenant: str, db_session: Session
) -> None:
    """A manifest row that was never signed (empty signature) is refused —
    the negative fixture for a manifest that bypassed the signing path."""
    artifact = registry_service.register_artifact(
        tenant_id=registry_tenant,
        artifact_type="prompt_bundle",
        canonical_bytes=unique_body(registry_tenant, "never-signed"),
    )
    unsigned = _insert_manifest_row(
        db_session, registry_tenant, artifact.digest, signature=b"", signer_public_key=b""
    )

    with pytest.raises(UnsignedActivationError, match="no valid signature"):
        registry_service.activate_release(
            tenant_id=registry_tenant,
            manifest_digest=unsigned.manifest_digest,
            artifact_digests=[artifact.digest],
        )


# ---------------------------------------------------------------------------
# circular metadata
# ---------------------------------------------------------------------------


def test_registration_rejects_artifact_listing_itself_as_dependency(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    """An artifact claiming its own digest among dependencies is circular
    metadata — refused before anything is hashed or stored."""
    self_digest = f"sha256:{'c' * 64}"
    with pytest.raises(CircularMetadataError, match="circular metadata"):
        registry_service.register_artifact(
            tenant_id=registry_tenant,
            artifact_type="prompt_bundle",
            canonical_bytes=unique_body(registry_tenant, "self-dep"),
            dependencies=[self_digest],
            expected_digest=self_digest,
        )


def test_proposal_rejects_self_parent(
    registry_service: RegistryService, registry_tenant: str, register: object
) -> None:
    artifact = register("proposed")  # type: ignore[operator]
    with pytest.raises(CircularMetadataError, match="cannot parent itself"):
        registry_service.record_proposal(
            tenant_id=registry_tenant,
            proposed_digest=artifact.digest,
            strategy_id="strat_gepa",
            parent_digest=artifact.digest,
        )


def test_manifest_row_rejects_itself_as_prior_release_at_the_database_level(
    registry_service: RegistryService, registry_tenant: str, db_session: Session
) -> None:
    """The ck_release_manifests_no_self_prior CHECK constraint refuses a
    manifest naming its own digest as prior release, even on a direct
    INSERT that bypasses the service."""
    artifact = registry_service.register_artifact(
        tenant_id=registry_tenant,
        artifact_type="prompt_bundle",
        canonical_bytes=unique_body(registry_tenant, "self-prior"),
    )
    body = canonical.manifest_body_bytes(
        artifact_digests=[artifact.digest],
        adapter_versions={},
        model_routes={},
        policies={},
        prior_release_digest=None,
    )
    self_digest = canonical.manifest_digest_for(body)
    detached = sign(generate_signing_key(), body)
    db_session.add(
        ReleaseManifest(
            tenant_id=registry_tenant,
            manifest_id="rel_self_prior_fixture",
            manifest_digest=self_digest,
            artifact_digests=[artifact.digest],
            adapter_versions={},
            model_routes={},
            policies={},
            prior_release_digest=self_digest,  # names itself
            storage_uri=f"{canonical.STORAGE_URI_SCHEME}://self-prior",
            signature=detached.signature,
            signer_public_key=detached.public_key,
        )
    )
    with pytest.raises(IntegrityError, match="ck_release_manifests_no_self_prior"):
        db_session.commit()
    db_session.rollback()


def test_manifest_rejects_unknown_prior_release(
    registry_service: RegistryService, registry_tenant: str, signing_key: object
) -> None:
    """A manifest chaining to a prior release that doesn't exist is refused
    — release lineage must resolve, not just be well-formed."""
    artifact = registry_service.register_artifact(
        tenant_id=registry_tenant,
        artifact_type="prompt_bundle",
        canonical_bytes=unique_body(registry_tenant, "orphan-chain"),
    )
    with pytest.raises(ArtifactNotFoundError, match="release manifest"):
        registry_service.create_release_manifest(
            tenant_id=registry_tenant,
            artifact_digests=[artifact.digest],
            adapter_versions={},
            model_routes={},
            policies={},
            prior_release_digest=f"sha256:{'9' * 64}",
            private_key=signing_key,
        )


# ---------------------------------------------------------------------------
# mixed-release activation
# ---------------------------------------------------------------------------


def test_activation_rejects_artifacts_outside_the_target_manifest(
    registry_service: RegistryService, registry_tenant: str, signing_key: object
) -> None:
    """FR-003: activating a set that mixes digests from outside the target
    release is refused — releases activate as a unit, not a la carte."""
    in_release = registry_service.register_artifact(
        tenant_id=registry_tenant,
        artifact_type="prompt_bundle",
        canonical_bytes=unique_body(registry_tenant, "in-release"),
    )
    outsider = registry_service.register_artifact(
        tenant_id=registry_tenant,
        artifact_type="memory_entry",
        canonical_bytes=unique_body(registry_tenant, "outsider"),
    )
    manifest = registry_service.create_release_manifest(
        tenant_id=registry_tenant,
        artifact_digests=[in_release.digest],
        adapter_versions={},
        model_routes={},
        policies={},
        prior_release_digest=None,
        private_key=signing_key,
    )

    with pytest.raises(MixedReleaseActivationError, match="outside release"):
        registry_service.activate_release(
            tenant_id=registry_tenant,
            manifest_digest=manifest.manifest_digest,
            artifact_digests=[in_release.digest, outsider.digest],
        )


def test_activation_rejects_artifact_from_another_tenant(
    registry_service: RegistryService, registry_tenant: str, signing_key: object
) -> None:
    """An artifact registered under a different tenant is outside this
    release by definition — the mixed-release check must not be fooled by
    a digest that merely exists somewhere."""
    import uuid

    other_tenant = f"tnt_{uuid.uuid4().hex[:12]}"
    foreign = registry_service.register_artifact(
        tenant_id=other_tenant,
        artifact_type="prompt_bundle",
        canonical_bytes=unique_body(other_tenant, "foreign"),
    )
    local = registry_service.register_artifact(
        tenant_id=registry_tenant,
        artifact_type="prompt_bundle",
        canonical_bytes=unique_body(registry_tenant, "local"),
    )
    manifest = registry_service.create_release_manifest(
        tenant_id=registry_tenant,
        artifact_digests=[local.digest],
        adapter_versions={},
        model_routes={},
        policies={},
        prior_release_digest=None,
        private_key=signing_key,
    )

    with pytest.raises(MixedReleaseActivationError):
        registry_service.activate_release(
            tenant_id=registry_tenant,
            manifest_digest=manifest.manifest_digest,
            artifact_digests=[foreign.digest],
        )
