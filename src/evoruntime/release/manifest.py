"""The signed ReleaseManifest as a value object (PRD §9.2).

The manifest is the atomic activation and rollback unit: fully resolved
artifact digests, adapter versions, model routes, policies, and the prior
release, signed over canonical bytes. Promotion and rollback operate on
the *entire* manifest — there is no floating per-artifact pointer in this
package's API surface at all, so a partial activation is not something a
caller can accidentally perform.

This module is the in-memory twin of the registry's ``ReleaseManifest``
row (E1): the registry persists and activates manifests in the database;
the release controller consumes the same canonical bytes and detached
signature as a value object. Both sides recompute the digest from
``evoruntime.registry.canonical`` so there is exactly one definition of
what a manifest's bytes are.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from evoruntime.registry.canonical import manifest_body_bytes, manifest_digest_for
from evoruntime.release.errors import UnsignedManifestError
from evoruntime.security.signing import DetachedSignature, sign, verify


@dataclass(frozen=True, slots=True)
class SignedReleaseManifest:
    """A signed release manifest: the atomic activation/rollback unit.

    ``manifest_digest`` is the content address of the canonical body — the
    value the active release pointer holds. The signature and public key
    are excluded from the digested body by construction (they vouch for
    it, they are not part of it).
    """

    manifest_digest: str
    artifact_digests: tuple[str, ...]
    adapter_versions: Mapping[str, Any]
    model_routes: Mapping[str, Any]
    policies: Mapping[str, Any]
    prior_release_digest: str | None
    signature: bytes
    signer_public_key: bytes


def sign_release_manifest(
    *,
    artifact_digests: Sequence[str],
    adapter_versions: Mapping[str, Any],
    model_routes: Mapping[str, Any],
    policies: Mapping[str, Any],
    prior_release_digest: str | None,
    private_key: Any,
) -> SignedReleaseManifest:
    """Resolve, digest, and sign a release manifest over its canonical bytes.

    The resolved digests are deduplicated in order — a manifest is a set
    of artifacts, and a duplicate entry would be two names for one thing.
    """
    resolved = tuple(dict.fromkeys(artifact_digests))
    body = manifest_body_bytes(
        artifact_digests=resolved,
        adapter_versions=dict(adapter_versions),
        model_routes=dict(model_routes),
        policies=dict(policies),
        prior_release_digest=prior_release_digest,
    )
    detached = sign(private_key, body)
    return SignedReleaseManifest(
        manifest_digest=manifest_digest_for(body),
        artifact_digests=resolved,
        adapter_versions=dict(adapter_versions),
        model_routes=dict(model_routes),
        policies=dict(policies),
        prior_release_digest=prior_release_digest,
        signature=detached.signature,
        signer_public_key=detached.public_key,
    )


def verify_release_manifest(manifest: SignedReleaseManifest) -> None:
    """Verify the manifest's detached signature over its canonical bytes.

    Raises:
        UnsignedManifestError: the signature is missing or does not verify.
            The manifest is refused as an activation/rollback unit — its
            bytes are not vouched for, so trusting them would be trust
            without evidence.
    """
    body = manifest_body_bytes(
        artifact_digests=manifest.artifact_digests,
        adapter_versions=dict(manifest.adapter_versions),
        model_routes=dict(manifest.model_routes),
        policies=dict(manifest.policies),
        prior_release_digest=manifest.prior_release_digest,
    )
    if not verify(
        DetachedSignature(signature=manifest.signature, public_key=manifest.signer_public_key),
        body,
    ):
        raise UnsignedManifestError(
            f"release manifest {manifest.manifest_digest!r} has no valid signature "
            "over its canonical bytes — refusing to treat it as an activation "
            "or rollback unit"
        )


def assert_distinct_from_prior(manifest: SignedReleaseManifest) -> None:
    """Refuse a manifest that names itself as its own prior release —
    circular metadata (FR-003), restated here because rollback trusts the
    prior-release link to lead somewhere else."""
    if manifest.prior_release_digest == manifest.manifest_digest:
        raise UnsignedManifestError(
            f"release manifest {manifest.manifest_digest!r} names itself as its "
            "own prior release — circular metadata"
        )


__all__ = [
    "SignedReleaseManifest",
    "assert_distinct_from_prior",
    "sign_release_manifest",
    "verify_release_manifest",
]
