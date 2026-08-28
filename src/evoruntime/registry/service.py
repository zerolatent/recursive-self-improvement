"""Service-layer API for the artifact registry (deliverable E1, PRD §9.2).

The service boundary is where FR-003's rejection paths live:

- **digest mismatch** — a caller claiming a digest the body doesn't hash
  to, or a read whose stored bytes no longer hash to the recorded digest,
  is refused (`DigestMismatchError`). Verification happens on *every* read,
  not only on write: a content address that is never re-checked is a
  filename, not an integrity guarantee.
- **unsigned activation** — a release manifest whose signature is missing
  or does not verify over its canonical bytes cannot be activated
  (`UnsignedActivationError`).
- **circular metadata** — an artifact listing its own digest among
  dependencies, a proposal parenting itself, or a manifest naming itself
  as prior release is refused (`CircularMetadataError`).
- **mixed-release activation** — an activation request naming artifacts the
  target manifest does not resolve is refused (`MixedReleaseActivationError`).

Canonical bytes are stored through the lineage payload store
(`evoruntime.lineage.payload_store`) so they get the same per-tenant
AES-256-GCM encryption at rest as every other payload.

All five tables are append-only at the database level (see the E1
migration); this service only ever INSERTs into them. Current status is
read from the `artifact_current_status` projection view, never stored.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from evoruntime.db.models.registry import (
    STATUS_EVENT_KINDS,
    ArtifactContent,
    ArtifactStatusEvent,
    EvaluationAttestation,
    ProposalRecord,
    ReleaseManifest,
)
from evoruntime.lineage.payload_store import PayloadStore
from evoruntime.registry import canonical
from evoruntime.registry.errors import (
    ArtifactNotFoundError,
    CircularMetadataError,
    DigestMismatchError,
    InvalidProposalError,
    InvalidStatusEventError,
    MixedReleaseActivationError,
    UnsignedActivationError,
)
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.policy import PermissionDeniedError
from evoruntime.security.signing import DetachedSignature, sign, verify

_VALID_OUTCOMES = ("pass", "fail")


class RegistryService:
    """Registers artifacts, records proposals/attestations/status events,
    creates and activates signed release manifests."""

    def __init__(self, session: Session) -> None:
        self._session = session
        self._payloads = PayloadStore(session)

    # ------------------------------------------------------------------
    # ArtifactContent
    # ------------------------------------------------------------------

    def register_artifact(
        self,
        *,
        tenant_id: str,
        artifact_type: str,
        canonical_bytes: bytes,
        dependencies: list[str] | None = None,
        capability_requests: dict[str, Any] | None = None,
        expected_digest: str | None = None,
        data_classification: str = "artifact",
    ) -> ArtifactContent:
        """Register an artifact's immutable canonical body.

        `canonical_bytes` are the artifact's canonical serialization; they
        are stored (encrypted, per tenant) through the payload store, and
        the artifact digest is computed over the digested body derived from
        them. If `expected_digest` is supplied and does not match the
        computed digest, registration is refused — the caller's claim and
        the bytes must agree, or nothing is stored.
        """
        dependencies = list(dependencies or [])
        capability_requests = dict(capability_requests or {})

        if expected_digest is not None and expected_digest in dependencies:
            raise CircularMetadataError(
                f"artifact lists its own claimed digest {expected_digest!r} "
                "among dependencies — circular metadata"
            )

        body_digest = canonical.payload_body_digest(canonical_bytes)
        digest = canonical.artifact_digest_for(
            artifact_type=artifact_type,
            canonical_body_digest=body_digest,
            dependencies=dependencies,
            capability_requests=capability_requests,
        )
        if expected_digest is not None and expected_digest != digest:
            raise DigestMismatchError(
                f"claimed digest {expected_digest!r} does not match computed "
                f"digest {digest!r} for the supplied canonical bytes"
            )

        existing = self._find_artifact(tenant_id=tenant_id, digest=digest)
        if existing is not None:
            return existing

        for dependency in dependencies:
            self._require_artifact(tenant_id=tenant_id, digest=dependency)

        payload = self._payloads.store(
            tenant_id=tenant_id,
            plaintext=canonical_bytes,
            data_classification=data_classification,
        )
        artifact = ArtifactContent(
            tenant_id=tenant_id,
            artifact_id=canonical.new_artifact_id(),
            digest=digest,
            artifact_type=artifact_type,
            canonical_body_digest=body_digest,
            dependencies=dependencies,
            capability_requests=capability_requests,
            storage_uri=canonical.storage_uri_for(payload.payload_digest),
        )
        self._session.add(artifact)
        self._session.flush()
        return artifact

    def read_artifact(self, *, tenant_id: str, digest: str) -> bytes:
        """Decrypt and return the artifact's canonical bytes, re-verifying
        both the payload digest and the artifact digest on the way out."""
        artifact = self._require_artifact(tenant_id=tenant_id, digest=digest)
        payload_digest = artifact.storage_uri.removeprefix(f"{canonical.STORAGE_URI_SCHEME}://")
        plaintext = self._payloads.read(tenant_id=tenant_id, payload_digest=payload_digest)

        recomputed_body = canonical.payload_body_digest(plaintext)
        if recomputed_body != artifact.canonical_body_digest:
            raise DigestMismatchError(
                f"stored bytes for artifact {digest!r} hash to {recomputed_body!r} "
                f"but the record claims {artifact.canonical_body_digest!r}"
            )
        recomputed = canonical.artifact_digest_for(
            artifact_type=artifact.artifact_type,
            canonical_body_digest=recomputed_body,
            dependencies=list(artifact.dependencies),
            capability_requests=dict(artifact.capability_requests),
        )
        if recomputed != artifact.digest:
            raise DigestMismatchError(
                f"artifact {digest!r} body re-hashes to {recomputed!r}, "
                "not the recorded digest — record integrity violated"
            )
        return plaintext

    def get_artifact(self, *, tenant_id: str, digest: str) -> ArtifactContent:
        return self._require_artifact(tenant_id=tenant_id, digest=digest)

    # ------------------------------------------------------------------
    # ProposalRecord
    # ------------------------------------------------------------------

    def record_proposal(
        self,
        *,
        tenant_id: str,
        proposed_digest: str,
        strategy_id: str,
        parent_digest: str | None = None,
        campaign_id: str | None = None,
        proposal_metadata: dict[str, Any] | None = None,
    ) -> ProposalRecord:
        """Record that `strategy_id` proposed `proposed_digest` (derived from
        `parent_digest`, when given)."""
        if not strategy_id or not strategy_id.strip():
            raise InvalidProposalError(
                "strategy_id must be a non-empty identifier — a proposal without "
                "a strategy breaks lineage attribution"
            )

        if parent_digest == proposed_digest:
            raise CircularMetadataError(
                f"proposal {proposed_digest!r} cannot parent itself — circular metadata"
            )
        self._require_artifact(tenant_id=tenant_id, digest=proposed_digest)
        if parent_digest is not None:
            self._require_artifact(tenant_id=tenant_id, digest=parent_digest)

        proposal = ProposalRecord(
            tenant_id=tenant_id,
            proposal_id=canonical.new_proposal_id(),
            proposed_digest=proposed_digest,
            parent_digest=parent_digest,
            strategy_id=strategy_id,
            campaign_id=campaign_id,
            proposal_metadata=dict(proposal_metadata or {}),
        )
        self._session.add(proposal)
        self._session.flush()
        return proposal

    # ------------------------------------------------------------------
    # EvaluationAttestation
    # ------------------------------------------------------------------

    def record_attestation(
        self,
        *,
        tenant_id: str,
        evaluator: WorkloadIdentity,
        artifact_digest: str,
        outcome: str,
        result_metrics: dict[str, Any],
        evaluation_payload_digest: str,
        private_key: Any,
    ) -> EvaluationAttestation:
        """Sign and record an evaluation outcome for an artifact.

        Only the evaluator role may attest: the signature is produced with
        the evaluator-held key and the identity is checked here before
        anything is written, so a candidate-runner cannot mint attestations
        even when it can reach the process.
        """
        if evaluator.role is not WorkloadRole.EVALUATOR:
            raise PermissionDeniedError(evaluator, "record evaluation attestation")
        if outcome not in _VALID_OUTCOMES:
            raise ValueError(f"outcome {outcome!r} is not one of {', '.join(_VALID_OUTCOMES)}")
        artifact = self._require_artifact(tenant_id=tenant_id, digest=artifact_digest)

        body = canonical.attestation_body_bytes(
            artifact_digest=artifact.digest,
            evaluator_subject=evaluator.subject,
            outcome=outcome,
            result_metrics=result_metrics,
            evaluation_payload_digest=evaluation_payload_digest,
        )
        detached = sign(private_key, body)
        attestation = EvaluationAttestation(
            tenant_id=tenant_id,
            attestation_id=canonical.new_attestation_id(),
            artifact_digest=artifact.digest,
            evaluator_subject=evaluator.subject,
            outcome=outcome,
            result_metrics=dict(result_metrics),
            evaluation_payload_digest=evaluation_payload_digest,
            signature=detached.signature,
            signer_public_key=detached.public_key,
        )
        self._session.add(attestation)
        self._session.flush()
        return attestation

    def verify_attestation(self, attestation: EvaluationAttestation) -> bool:
        """Verify an attestation's detached signature against its recorded
        body. False means the row no longer vouches for bytes anyone
        produced — treat as tampering, not as a soft failure."""
        body = canonical.attestation_body_bytes(
            artifact_digest=attestation.artifact_digest,
            evaluator_subject=attestation.evaluator_subject,
            outcome=attestation.outcome,
            result_metrics=dict(attestation.result_metrics),
            evaluation_payload_digest=attestation.evaluation_payload_digest,
        )
        return verify(
            DetachedSignature(
                signature=attestation.signature, public_key=attestation.signer_public_key
            ),
            body,
        )

    # ------------------------------------------------------------------
    # ArtifactStatusEvent + projection
    # ------------------------------------------------------------------

    def append_status_event(
        self,
        *,
        tenant_id: str,
        artifact_digest: str,
        kind: str,
        actor_identity: str,
        reason: str | None = None,
    ) -> ArtifactStatusEvent:
        """Append one lifecycle event. There is no update or delete path:
        corrections are new events, and the projection follows the latest."""
        if kind not in STATUS_EVENT_KINDS:
            raise InvalidStatusEventError(
                f"status kind {kind!r} is not one of {', '.join(STATUS_EVENT_KINDS)}"
            )
        if not actor_identity:
            raise InvalidStatusEventError("actor_identity must be a non-empty identity string")
        artifact = self._require_artifact(tenant_id=tenant_id, digest=artifact_digest)

        event = ArtifactStatusEvent(
            tenant_id=tenant_id,
            event_id=canonical.new_event_id(),
            artifact_digest=artifact.digest,
            kind=kind,
            actor_identity=actor_identity,
            reason=reason,
        )
        self._session.add(event)
        self._session.flush()
        return event

    def current_status(self, *, tenant_id: str, artifact_digest: str) -> str | None:
        """The artifact's current status, read from the projection view.

        None means no status event has ever been recorded — the artifact is
        registered but its lifecycle has not started.
        """
        self._require_artifact(tenant_id=tenant_id, digest=artifact_digest)
        row = self._session.execute(
            text(
                "SELECT current_status FROM artifact_current_status "
                "WHERE tenant_id = :tenant_id AND artifact_digest = :digest"
            ),
            {"tenant_id": tenant_id, "digest": artifact_digest},
        ).scalar_one_or_none()
        return str(row) if row is not None else None

    # ------------------------------------------------------------------
    # ReleaseManifest
    # ------------------------------------------------------------------

    def create_release_manifest(
        self,
        *,
        tenant_id: str,
        artifact_digests: list[str],
        adapter_versions: dict[str, Any],
        model_routes: dict[str, Any],
        policies: dict[str, Any],
        prior_release_digest: str | None,
        private_key: Any,
    ) -> ReleaseManifest:
        """Resolve, sign, and record a release manifest over its canonical
        bytes. Every artifact digest must resolve in this tenant; a manifest
        naming itself as its own prior release is circular metadata."""
        if prior_release_digest is not None:
            self._require_manifest(tenant_id=tenant_id, manifest_digest=prior_release_digest)

        resolved = [
            self._require_artifact(tenant_id=tenant_id, digest=d).digest for d in artifact_digests
        ]
        body = canonical.manifest_body_bytes(
            artifact_digests=resolved,
            adapter_versions=dict(adapter_versions),
            model_routes=dict(model_routes),
            policies=dict(policies),
            prior_release_digest=prior_release_digest,
        )
        manifest_digest = canonical.manifest_digest_for(body)
        if manifest_digest == prior_release_digest:
            raise CircularMetadataError(
                "release manifest names itself as its own prior release — circular metadata"
            )

        detached = sign(private_key, body)
        manifest = ReleaseManifest(
            tenant_id=tenant_id,
            manifest_id=canonical.new_manifest_id(),
            manifest_digest=manifest_digest,
            artifact_digests=resolved,
            adapter_versions=dict(adapter_versions),
            model_routes=dict(model_routes),
            policies=dict(policies),
            prior_release_digest=prior_release_digest,
            storage_uri=canonical.storage_uri_for(manifest_digest),
            signature=detached.signature,
            signer_public_key=detached.public_key,
        )
        self._session.add(manifest)
        self._session.flush()
        return manifest

    def activate_release(
        self,
        *,
        tenant_id: str,
        manifest_digest: str,
        artifact_digests: list[str],
    ) -> ReleaseManifest:
        """Activate the artifact set of a signed release manifest.

        This is the FR-003 boundary: unsigned manifests are refused, digest
        mismatches between request and stored rows are refused, artifacts
        outside the manifest's resolved set are refused (mixed release), and
        the dependency graph of the activated set must be acyclic.
        """
        manifest = self._require_manifest(tenant_id=tenant_id, manifest_digest=manifest_digest)

        body = canonical.manifest_body_bytes(
            artifact_digests=list(manifest.artifact_digests),
            adapter_versions=dict(manifest.adapter_versions),
            model_routes=dict(manifest.model_routes),
            policies=dict(manifest.policies),
            prior_release_digest=manifest.prior_release_digest,
        )
        if not verify(
            DetachedSignature(signature=manifest.signature, public_key=manifest.signer_public_key),
            body,
        ):
            raise UnsignedActivationError(
                f"release manifest {manifest_digest!r} has no valid signature over "
                "its canonical bytes — refusing activation"
            )

        resolved_set = set(manifest.artifact_digests)
        requested = list(dict.fromkeys(artifact_digests))
        outside = [d for d in requested if d not in resolved_set]
        if outside:
            raise MixedReleaseActivationError(
                f"activation request names artifacts outside release "
                f"{manifest_digest!r}: {sorted(outside)} — mixed-release activation"
            )

        for artifact_digest in requested:
            artifact = self._require_artifact(tenant_id=tenant_id, digest=artifact_digest)
            if artifact.digest != artifact_digest:
                raise DigestMismatchError(
                    f"activation names digest {artifact_digest!r} but the stored "
                    f"artifact resolves to {artifact.digest!r}"
                )
        self._assert_acyclic(tenant_id=tenant_id, digests=requested)
        return manifest

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _find_artifact(self, *, tenant_id: str, digest: str) -> ArtifactContent | None:
        return self._session.execute(
            select(ArtifactContent).where(
                ArtifactContent.tenant_id == tenant_id, ArtifactContent.digest == digest
            )
        ).scalar_one_or_none()

    def _require_artifact(self, *, tenant_id: str, digest: str) -> ArtifactContent:
        artifact = self._find_artifact(tenant_id=tenant_id, digest=digest)
        if artifact is None:
            raise ArtifactNotFoundError(
                f"no artifact {digest!r} registered for tenant {tenant_id!r}"
            )
        return artifact

    def _require_manifest(self, *, tenant_id: str, manifest_digest: str) -> ReleaseManifest:
        manifest = self._session.execute(
            select(ReleaseManifest).where(
                ReleaseManifest.tenant_id == tenant_id,
                ReleaseManifest.manifest_digest == manifest_digest,
            )
        ).scalar_one_or_none()
        if manifest is None:
            raise ArtifactNotFoundError(
                f"no release manifest {manifest_digest!r} for tenant {tenant_id!r}"
            )
        return manifest

    def _assert_acyclic(self, *, tenant_id: str, digests: list[str]) -> None:
        """Walk the dependency graph of `digests`; any cycle (including a
        self-dependency) is circular metadata and refuses the activation."""
        for root in digests:
            visited: set[str] = set()
            stack = [root]
            while stack:
                current = stack.pop()
                if current in visited:
                    raise CircularMetadataError(
                        f"dependency graph reachable from {root!r} contains a "
                        f"cycle at {current!r} — circular metadata"
                    )
                visited.add(current)
                artifact = self._require_artifact(tenant_id=tenant_id, digest=current)
                stack.extend(str(d) for d in artifact.dependencies)
