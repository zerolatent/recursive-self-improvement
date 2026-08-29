"""G10 — mutation-class graduation: comparability, dossiers, decisions.

The acceptance matrix: the comparability check passes for a comparable
class and refuses with a typed reason for every refusal path; dossier
digest pinning matches G3's ``MutationClassBinding.risk_dossier_digest``;
graduation decisions (granted and refused) are append-only signed
records whose rows refuse UPDATE/DELETE at the database level.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import text
from sqlalchemy.orm import Session

from evoruntime.campaign.spec import MutationClassBinding
from evoruntime.core.isolation import IsolationTier
from evoruntime.plugins.manifest import PluginArtifactType
from evoruntime.security.signing import generate_signing_key
from evoruntime.selection.graduation import (
    BlastRadius,
    GraduationRefusal,
    InvalidRiskDossierError,
    RiskDossier,
    SignedRiskDossier,
    UnsignedRiskDossierError,
    evaluate_graduation,
    record_graduation_decision,
    sign_risk_dossier,
    verify_graduation_decision,
    verify_risk_dossier,
)

CLASS_ID = "prompt_module_edit"


def make_dossier(**overrides: Any) -> RiskDossier:
    """A scaffold-class dossier whose resolved risk is tier 4 (self-source)."""
    fields: dict[str, Any] = {
        "dossier_id": "dossier-prompt-module-edit-v1",
        "class_id": CLASS_ID,
        "artifact_class": PluginArtifactType.SCAFFOLD.value,
        "isolation_tier_demanded": IsolationTier.HIGHEST,
        "blast_radius": BlastRadius.SELF_SOURCE,
        "reversible": False,
        "compensable": True,
    }
    fields.update(overrides)
    return RiskDossier(**fields)


def make_production_dossier(private_key: Ed25519PrivateKey, **overrides: Any) -> SignedRiskDossier:
    """A signed production reference dossier (defaults: harness patch, tier 4)."""
    fields: dict[str, Any] = {
        "dossier_id": "dossier-harness-patch-production",
        "class_id": "harness_patch_edit",
        "artifact_class": PluginArtifactType.HARNESS_PATCH.value,
        "isolation_tier_demanded": IsolationTier.HIGHEST,
        "blast_radius": BlastRadius.SELF_SOURCE,
        "reversible": False,
        "compensable": True,
    }
    fields.update(overrides)
    return sign_risk_dossier(RiskDossier(**fields), private_key)


def make_binding(dossier: RiskDossier, **overrides: Any) -> MutationClassBinding:
    fields: dict[str, Any] = {
        "class_id": dossier.class_id,
        "risk_dossier_digest": dossier.digest,
        "max_tier": dossier.isolation_tier_demanded,
    }
    fields.update(overrides)
    return MutationClassBinding(**fields)


# ---------------------------------------------------------------- dossiers


def test_dossier_digest_is_stable_and_field_sensitive() -> None:
    """Equivalent dossiers pin equal digests; any risk-fact change re-pins."""
    first = make_dossier()
    second = make_dossier()
    assert first.digest == second.digest
    assert first.digest.startswith("sha256:")

    retiered = make_dossier(
        blast_radius=BlastRadius.RUNTIME,
        isolation_tier_demanded=IsolationTier.EXECUTABLE,
    )
    assert retiered.digest != first.digest
    widened = make_dossier(blast_radius=BlastRadius.RUNTIME)
    assert widened.digest != first.digest
    versioned = make_dossier(dossier_version=2)
    assert versioned.digest != first.digest


def test_dossier_digest_matches_g3_binding_pin() -> None:
    """The digest a G3 MutationClassBinding pins is the dossier's digest."""
    dossier = make_dossier()
    binding = MutationClassBinding(
        class_id=dossier.class_id,
        risk_dossier_digest=dossier.digest,
        max_tier=dossier.isolation_tier_demanded,
    )
    assert binding.risk_dossier_digest == dossier.digest


def test_dossier_rejects_incoherent_risk_claims() -> None:
    """Self-source blast radius demands HIGHEST; reversible implies compensable."""
    with pytest.raises(InvalidRiskDossierError, match="HIGHEST"):
        make_dossier(isolation_tier_demanded=IsolationTier.EXECUTABLE)
    with pytest.raises(InvalidRiskDossierError, match="EXECUTABLE"):
        make_dossier(
            artifact_class=PluginArtifactType.WORKFLOW_GRAPH.value,
            blast_radius=BlastRadius.RUNTIME,
            isolation_tier_demanded=IsolationTier.BROKERED,
        )
    with pytest.raises(InvalidRiskDossierError, match="incoherent"):
        make_dossier(reversible=True, compensable=False)
    with pytest.raises(InvalidRiskDossierError, match="artifact class"):
        make_dossier(artifact_class="not_a_class")


def test_signed_dossier_verifies_and_detects_tampering() -> None:
    key = generate_signing_key()
    signed = sign_risk_dossier(make_dossier(), key)
    verify_risk_dossier(signed)

    tampered = sign_risk_dossier(make_dossier(compensable=False), key)
    forged = SignedRiskDossier(
        dossier=tampered.dossier,
        digest=signed.digest,  # digest no longer matches the dossier's bytes
        signature=tampered.signature,
        signer_public_key=tampered.signer_public_key,
    )
    assert not forged.verify()
    with pytest.raises(UnsignedRiskDossierError, match="no valid signature"):
        verify_risk_dossier(forged)


# ------------------------------------------------- comparability: the pass


def test_comparable_class_graduates() -> None:
    """A class whose resolved tier is at or below production's graduates."""
    key = generate_signing_key()
    dossier = make_dossier()
    signed = sign_risk_dossier(dossier, key)
    binding = MutationClassBinding(
        class_id=CLASS_ID,
        risk_dossier_digest=dossier.digest,
        max_tier=IsolationTier.HIGHEST,
    )
    production = [make_production_dossier(key)]

    decision = evaluate_graduation(
        class_id=CLASS_ID,
        signed_dossier=signed,
        binding=binding,
        production_dossiers=production,
    )
    assert decision.granted
    assert decision.refusal_reason is None
    assert decision.dossier_digest == dossier.digest
    assert decision.candidate_resolved_tier == 4
    assert decision.production_resolved_tier == 4


def test_lower_risk_than_production_graduates() -> None:
    """Comparable means *at or below* — a gentler class still graduates."""
    key = generate_signing_key()
    dossier = make_dossier(
        blast_radius=BlastRadius.RUNTIME,
        isolation_tier_demanded=IsolationTier.EXECUTABLE,
        reversible=True,
        compensable=True,
    )
    signed = sign_risk_dossier(dossier, key)
    binding = MutationClassBinding(
        class_id=CLASS_ID,
        risk_dossier_digest=dossier.digest,
        max_tier=IsolationTier.EXECUTABLE,
    )
    production = [make_production_dossier(key)]

    decision = evaluate_graduation(
        class_id=CLASS_ID,
        signed_dossier=signed,
        binding=binding,
        production_dossiers=production,
    )
    assert decision.granted
    assert decision.candidate_resolved_tier < decision.production_resolved_tier


# --------------------------------------------- comparability: refusal reasons


def test_graduation_without_dossier_is_refused() -> None:
    decision = evaluate_graduation(
        class_id=CLASS_ID,
        signed_dossier=None,
        binding=None,
        production_dossiers=[],
    )
    assert not decision.granted
    assert decision.refusal_reason is GraduationRefusal.NO_DOSSIER


def test_tampered_dossier_is_refused() -> None:
    """A dossier whose risk facts changed after signing fails verification."""
    key = generate_signing_key()
    signed = sign_risk_dossier(make_dossier(), key)
    tampered = SignedRiskDossier(
        dossier=make_dossier(compensable=False),  # risk facts changed post-signing
        digest=signed.digest,
        signature=signed.signature,
        signer_public_key=signed.signer_public_key,
    )
    assert not tampered.verify()
    decision = evaluate_graduation(
        class_id=CLASS_ID,
        signed_dossier=tampered,
        binding=None,
        production_dossiers=[],
    )
    assert decision.refusal_reason is GraduationRefusal.UNVERIFIED_DOSSIER


def test_unverified_production_reference_is_refused() -> None:
    """Comparability against a tampered production dossier is meaningless."""
    key = generate_signing_key()
    dossier = make_dossier()
    signed = sign_risk_dossier(dossier, key)
    binding = MutationClassBinding(
        class_id=CLASS_ID,
        risk_dossier_digest=dossier.digest,
        max_tier=IsolationTier.HIGHEST,
    )
    tampered_production = SignedRiskDossier(
        dossier=make_production_dossier(key).dossier,
        digest="sha256:" + "0" * 64,  # digest does not match its bytes
        signature=b"not-a-signature",
        signer_public_key=b"not-a-key",
    )
    decision = evaluate_graduation(
        class_id=CLASS_ID,
        signed_dossier=signed,
        binding=binding,
        production_dossiers=[tampered_production],
    )
    assert decision.refusal_reason is GraduationRefusal.UNVERIFIED_DOSSIER


def test_dossier_for_another_class_is_refused() -> None:
    key = generate_signing_key()
    dossier = make_dossier()
    signed = sign_risk_dossier(dossier, key)
    decision = evaluate_graduation(
        class_id="tool_use_rewrite",
        signed_dossier=signed,
        binding=None,
        production_dossiers=[],
    )
    assert decision.refusal_reason is GraduationRefusal.CLASS_ID_MISMATCH


def test_dossier_digest_pin_mismatch_is_refused() -> None:
    """A dossier whose digest no longer matches the G3 pin is a different
    preregistration — graduation is refused, not re-based."""
    key = generate_signing_key()
    dossier = make_dossier()
    signed = sign_risk_dossier(dossier, key)
    stale_binding = MutationClassBinding(
        class_id=CLASS_ID,
        risk_dossier_digest=make_dossier(dossier_version=2).digest,
        max_tier=IsolationTier.HIGHEST,
    )
    decision = evaluate_graduation(
        class_id=CLASS_ID,
        signed_dossier=signed,
        binding=stale_binding,
        production_dossiers=[make_production_dossier(key)],
    )
    assert decision.refusal_reason is GraduationRefusal.DOSSIER_DIGEST_MISMATCH

    unpinned = evaluate_graduation(
        class_id=CLASS_ID,
        signed_dossier=signed,
        binding=None,
        production_dossiers=[make_production_dossier(key)],
    )
    assert unpinned.refusal_reason is GraduationRefusal.DOSSIER_DIGEST_MISMATCH


def test_tier_above_binding_max_is_refused() -> None:
    key = generate_signing_key()
    dossier = make_dossier()
    signed = sign_risk_dossier(dossier, key)
    binding = MutationClassBinding(
        class_id=CLASS_ID,
        risk_dossier_digest=dossier.digest,
        max_tier=IsolationTier.EXECUTABLE,  # preregistered lower than demanded
    )
    decision = evaluate_graduation(
        class_id=CLASS_ID,
        signed_dossier=signed,
        binding=binding,
        production_dossiers=[make_production_dossier(key)],
    )
    assert decision.refusal_reason is GraduationRefusal.TIER_EXCEEDS_BINDING


def test_non_compensable_class_is_refused() -> None:
    key = generate_signing_key()
    dossier = make_dossier(reversible=False, compensable=False)
    signed = sign_risk_dossier(dossier, key)
    binding = MutationClassBinding(
        class_id=CLASS_ID,
        risk_dossier_digest=dossier.digest,
        max_tier=IsolationTier.HIGHEST,
    )
    decision = evaluate_graduation(
        class_id=CLASS_ID,
        signed_dossier=signed,
        binding=binding,
        production_dossiers=[make_production_dossier(key)],
    )
    assert decision.refusal_reason is GraduationRefusal.NOT_COMPENSABLE


def test_risk_above_production_is_refused() -> None:
    """Self-source candidate against only suggestion-radius production."""
    key = generate_signing_key()
    dossier = make_dossier()
    signed = sign_risk_dossier(dossier, key)
    binding = MutationClassBinding(
        class_id=CLASS_ID,
        risk_dossier_digest=dossier.digest,
        max_tier=IsolationTier.HIGHEST,
    )
    production = [
        make_production_dossier(
            key,
            dossier_id="dossier-prompt-bundle-production",
            class_id="prompt_bundle_tweak",
            artifact_class=PluginArtifactType.PROMPT_BUNDLE.value,
            isolation_tier_demanded=IsolationTier.TEXT_ONLY,
            blast_radius=BlastRadius.SUGGESTION,
            reversible=True,
            compensable=True,
        )
    ]
    decision = evaluate_graduation(
        class_id=CLASS_ID,
        signed_dossier=signed,
        binding=binding,
        production_dossiers=production,
    )
    assert decision.refusal_reason is GraduationRefusal.RISK_NOT_COMPARABLE
    assert decision.candidate_resolved_tier > decision.production_resolved_tier


def test_graduation_with_no_production_extensions_is_refused() -> None:
    """An empty production plane is no precedent — fail closed."""
    key = generate_signing_key()
    dossier = make_dossier()
    signed = sign_risk_dossier(dossier, key)
    binding = MutationClassBinding(
        class_id=CLASS_ID,
        risk_dossier_digest=dossier.digest,
        max_tier=IsolationTier.HIGHEST,
    )
    decision = evaluate_graduation(
        class_id=CLASS_ID,
        signed_dossier=signed,
        binding=binding,
        production_dossiers=[],
    )
    assert decision.refusal_reason is GraduationRefusal.RISK_NOT_COMPARABLE


# --------------------------------------------------------- decision records


def _record_refusal(db_session: Session, key: Ed25519PrivateKey) -> Any:
    decision = evaluate_graduation(
        class_id=CLASS_ID,
        signed_dossier=None,
        binding=None,
        production_dossiers=[],
    )
    return record_graduation_decision(
        db_session,
        private_key=key,
        tenant_id=f"grad-{uuid.uuid4().hex[:12]}",
        decision=decision,
    )


def test_refusal_is_recorded_as_a_signed_decision(db_session: Session) -> None:
    """The acceptance criterion: refusal without a comparable dossier is
    recorded, and the record verifies from the row alone."""
    row = _record_refusal(db_session, generate_signing_key())
    assert row.granted is False
    assert row.refusal_reason == GraduationRefusal.NO_DOSSIER.value
    assert row.dossier_digest is None
    assert verify_graduation_decision(row)

    # The signed payload is the row's own detail — tampering with any
    # stored field breaks verification.
    row.detail["granted"] = True
    assert not verify_graduation_decision(row)


def test_graduation_records_are_append_only_at_the_database_level(
    db_session: Session,
) -> None:
    key = generate_signing_key()
    row = _record_refusal(db_session, key)
    with pytest.raises(Exception, match="append-only"):
        db_session.execute(
            text("UPDATE graduation_decisions SET granted = true WHERE tenant_id = :tenant"),
            {"tenant": row.tenant_id},
        )
    db_session.rollback()
    with pytest.raises(Exception, match="append-only"):
        db_session.execute(
            text("DELETE FROM graduation_decisions WHERE tenant_id = :tenant"),
            {"tenant": row.tenant_id},
        )
    db_session.rollback()
