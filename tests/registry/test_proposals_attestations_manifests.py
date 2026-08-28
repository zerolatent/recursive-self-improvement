"""E1 acceptance: proposals, signed attestations, and signed release
manifests round-trip through the service with signature verification."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from evoruntime.db.models.registry import ProposalRecord
from evoruntime.registry.errors import (
    ArtifactNotFoundError,
    InvalidProposalError,
)
from evoruntime.registry.service import RegistryService
from evoruntime.security.signing import generate_signing_key


def test_proposal_record_round_trips_with_parent_lineage(
    registry_service: RegistryService, registry_tenant: str, register: object
) -> None:
    parent = register("parent")  # type: ignore[operator]
    child = register("child")  # type: ignore[operator]
    proposal = registry_service.record_proposal(
        tenant_id=registry_tenant,
        proposed_digest=child.digest,
        strategy_id="strat_gepa_v1",
        parent_digest=parent.digest,
    )
    assert proposal.proposed_digest == child.digest
    assert proposal.parent_digest == parent.digest
    assert proposal.strategy_id == "strat_gepa_v1"


def test_proposal_for_unknown_artifact_is_rejected(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    with pytest.raises(ArtifactNotFoundError):
        registry_service.record_proposal(
            tenant_id=registry_tenant,
            proposed_digest=f"sha256:{'b' * 64}",
            strategy_id="strat_gepa_v1",
            parent_digest=None,
        )


def test_proposal_with_unknown_parent_is_rejected(
    registry_service: RegistryService, registry_tenant: str, register: object
) -> None:
    child = register("orphan-child")  # type: ignore[operator]
    with pytest.raises(ArtifactNotFoundError):
        registry_service.record_proposal(
            tenant_id=registry_tenant,
            proposed_digest=child.digest,
            strategy_id="strat_gepa_v1",
            parent_digest=f"sha256:{'a' * 64}",
        )


def test_proposal_requires_a_strategy_id(
    registry_service: RegistryService, registry_tenant: str, register: object
) -> None:
    artifact = register("no-strategy")  # type: ignore[operator]
    with pytest.raises(InvalidProposalError, match="strategy_id"):
        registry_service.record_proposal(
            tenant_id=registry_tenant,
            proposed_digest=artifact.digest,
            strategy_id="",
            parent_digest=None,
        )


def test_proposal_row_is_append_only_at_the_database_level(
    registry_service: RegistryService,
    registry_tenant: str,
    db_session: Session,
    register: object,
) -> None:
    artifact = register("append-only-proposal")  # type: ignore[operator]
    proposal = registry_service.record_proposal(
        tenant_id=registry_tenant,
        proposed_digest=artifact.digest,
        strategy_id="strat_gepa_v1",
        parent_digest=None,
    )
    db_session.commit()

    with pytest.raises(Exception, match="append-only table"):
        db_session.execute(
            text("UPDATE proposal_records SET strategy_id = 'mutated' WHERE id = :id"),
            {"id": str(proposal.id)},
        )
    db_session.rollback()

    assert db_session.query(ProposalRecord).count() >= 1


def test_attestation_is_signed_and_verifies(
    registry_service: RegistryService,
    registry_tenant: str,
    register: object,
    evaluator_identity: object,
) -> None:
    artifact = register("attested")  # type: ignore[operator]
    key = generate_signing_key()
    attestation = registry_service.record_attestation(
        tenant_id=registry_tenant,
        evaluator=evaluator_identity,
        artifact_digest=artifact.digest,
        outcome="pass",
        result_metrics={"score": 0.87},
        evaluation_payload_digest=f"sha256:{'3' * 64}",
        private_key=key,
    )
    assert attestation.outcome == "pass"
    assert attestation.signature  # non-empty detached signature
    assert attestation.signer_public_key
    assert registry_service.verify_attestation(attestation) is True


def test_attestation_with_invalid_outcome_is_rejected(
    registry_service: RegistryService,
    registry_tenant: str,
    register: object,
    evaluator_identity: object,
) -> None:
    artifact = register("bad-verdict")  # type: ignore[operator]
    with pytest.raises(ValueError, match="outcome"):
        registry_service.record_attestation(
            tenant_id=registry_tenant,
            evaluator=evaluator_identity,
            artifact_digest=artifact.digest,
            outcome="maybe",
            result_metrics={},
            evaluation_payload_digest=f"sha256:{'3' * 64}",
            private_key=generate_signing_key(),
        )


def test_manifest_round_trips_with_signature_and_prior_chain(
    registry_service: RegistryService,
    registry_tenant: str,
    signing_key: object,
) -> None:
    """A first release activates; a second release chains to it as prior
    and both signatures verify over their canonical bytes."""
    artifact = registry_service.register_artifact(
        tenant_id=registry_tenant,
        artifact_type="prompt_bundle",
        canonical_bytes=b'{"gen":1}',
    )
    first = registry_service.create_release_manifest(
        tenant_id=registry_tenant,
        artifact_digests=[artifact.digest],
        adapter_versions={"adapter": "1.0.0"},
        model_routes={"default": "gpt-5-mini"},
        policies={"tier": 1},
        prior_release_digest=None,
        private_key=signing_key,
    )
    registry_service.activate_release(
        tenant_id=registry_tenant,
        manifest_digest=first.manifest_digest,
        artifact_digests=[artifact.digest],
    )

    artifact_v2 = registry_service.register_artifact(
        tenant_id=registry_tenant,
        artifact_type="prompt_bundle",
        canonical_bytes=b'{"gen":2}',
    )
    second = registry_service.create_release_manifest(
        tenant_id=registry_tenant,
        artifact_digests=[artifact_v2.digest],
        adapter_versions={"adapter": "1.1.0"},
        model_routes={"default": "gpt-5-mini"},
        policies={"tier": 1},
        prior_release_digest=first.manifest_digest,
        private_key=signing_key,
    )
    assert second.prior_release_digest == first.manifest_digest

    # Activation of the second release succeeds (signature valid, set matches).
    registry_service.activate_release(
        tenant_id=registry_tenant,
        manifest_digest=second.manifest_digest,
        artifact_digests=[artifact_v2.digest],
    )


def test_activate_release_of_unknown_manifest_is_rejected(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    with pytest.raises(ArtifactNotFoundError, match="release manifest"):
        registry_service.activate_release(
            tenant_id=registry_tenant,
            manifest_digest=f"sha256:{'d' * 64}",
            artifact_digests=[],
        )


def test_tampered_manifest_row_cannot_land_and_honest_path_still_works(
    registry_service: RegistryService,
    registry_tenant: str,
    signing_key: object,
    db_session: Session,
) -> None:
    """A manifest row whose metadata drifted from its signed body cannot
    even be written — the append-only trigger refuses the UPDATE, and the
    honest activation path still works afterwards."""
    artifact = registry_service.register_artifact(
        tenant_id=registry_tenant,
        artifact_type="prompt_bundle",
        canonical_bytes=b'{"tamper":1}',
    )
    manifest = registry_service.create_release_manifest(
        tenant_id=registry_tenant,
        artifact_digests=[artifact.digest],
        adapter_versions={},
        model_routes={},
        policies={},
        prior_release_digest=None,
        private_key=signing_key,
    )
    db_session.commit()

    with pytest.raises(Exception, match="append-only table"):
        db_session.execute(
            text("UPDATE release_manifests SET artifact_digests = :d WHERE id = :id"),
            {"d": '["sha256:' + "0" * 64 + '"]', "id": str(manifest.id)},
        )
    db_session.rollback()

    registry_service.activate_release(
        tenant_id=registry_tenant,
        manifest_digest=manifest.manifest_digest,
        artifact_digests=[artifact.digest],
    )
