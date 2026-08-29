"""Mutation-class graduation (Phase 3, G10).

A mutation class lives in the research tenant until it graduates — and
graduation is a *recorded, comparable-risk decision*, not a promotion
that happens because a campaign did well. This module is that decision
plane, built from three pieces:

**Risk dossiers are signed policy data** (the
:class:`evoruntime.security.protected_modules.ProtectedModulesDocument`
pattern). A dossier declares, per mutation class, the isolation tier the
class demands, its blast radius, whether it is reversible, and whether a
compensation path exists. The document is frozen at construction,
canonical-JSON digestable, and signed with the same detached Ed25519
service release manifests use — a dossier edited in flight is not an
update, it is a forgery of one. G3's ``MutationClassBinding.
risk_dossier_digest`` pins the dossier into the campaign's
preregistration; graduation refuses a dossier whose digest no longer
matches that pin.

**Comparability is pure.** :func:`evaluate_graduation` takes the
candidate's signed dossier, the class binding that pinned it, and the
signed dossiers of the production extensions already running, and
compares *resolved* risk: each dossier is projected onto a
:class:`evoruntime.selection.authority.ResolvedRelease` and tiered with
:func:`evoruntime.selection.authority.resolve_authority_tier` — the same
engine that tiers real releases, so a class cannot graduate into more
authority than production already runs by describing itself gently. The
function has no session, no clock, and no I/O; every refusal is a typed
reason on the returned decision, never an exception, because a refusal
is itself a recorded outcome.

**Graduation decisions are append-only signed records.**
:func:`record_graduation_decision` signs the canonical decision payload
and appends it to ``graduation_decisions``; the table's migration
installs a trigger that refuses ``UPDATE``/``DELETE``/``TRUNCATE`` at
the database level — the same guarantee the refusal ledger (G6) and the
holdout query ledger (D5) carry. Granted *and* refused decisions are
recorded: the acceptance criterion is that graduation without a
comparable-risk dossier is refused *by recorded decision*.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol

from sqlalchemy.orm import Session

from evoruntime.core.isolation import IsolationTier
from evoruntime.db.models.graduation import GraduationDecision as GraduationDecisionRow
from evoruntime.plugins.manifest import PluginArtifactType
from evoruntime.security.signing import DetachedSignature, sign, verify
from evoruntime.selection.authority import ResolvedRelease, resolve_authority_tier

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

__all__ = [
    "BLAST_RADIUS_SURFACES",
    "GRADUATION_DECISION_SCHEMA_ID",
    "GRADUATION_DOSSIER_SCHEMA_ID",
    "BlastRadius",
    "GraduationBinding",
    "GraduationDecision",
    "GraduationRefusal",
    "InvalidRiskDossierError",
    "RiskDossier",
    "SignedRiskDossier",
    "UnsignedRiskDossierError",
    "evaluate_graduation",
    "record_graduation_decision",
    "sign_risk_dossier",
    "verify_graduation_decision",
    "verify_risk_dossier",
]

audit_log = logging.getLogger("evoruntime.audit")

GRADUATION_DOSSIER_SCHEMA_ID = "evoruntime.policy.risk-dossier/v1"
"""Schema id for the canonical dossier bytes a digest/signature covers."""

GRADUATION_DECISION_SCHEMA_ID = "evoruntime.decision.graduation/v1"
"""Schema id for the canonical graduation-decision bytes a record signs."""

_DIGEST_PREFIX = "sha256:"

#: Execution-isolation ranking. ``IsolationTier`` is a ``StrEnum`` whose
#: values do not order alphabetically, so every tier comparison in this
#: module goes through this explicit rank table.
_TIER_RANK: dict[IsolationTier, int] = {
    IsolationTier.TEXT_ONLY: 0,
    IsolationTier.BROKERED: 1,
    IsolationTier.EXECUTABLE: 2,
    IsolationTier.HIGHEST: 3,
}


class BlastRadius(StrEnum):
    """How far beyond the evaluated candidate a class's changes reach.

    The ordering that matters is the *authority* the resolved release
    warrants (via :func:`resolve_authority_tier`), not this enum's
    declaration order: ``SELF_SOURCE`` resolves to tier 4 the same way a
    harness patch does, because replacing the agent's own source tree is
    the same blast radius.
    """

    SUGGESTION = "suggestion"
    """Read-only output — the runtime is asked, never changed."""

    KEPT_STATE = "kept_state"
    """Alters what the runtime keeps (memory, compiled programs, config)."""

    RUNTIME = "runtime"
    """Executable content on the runtime surface."""

    SELF_SOURCE = "self_source"
    """Replaces the agent's own source tree — harness-patch blast radius."""


#: Blast radius → the deepest runtime surface the resolved release touches
#: (the ``ResolvedRelease.runtime_surface`` vocabulary).
BLAST_RADIUS_SURFACES: dict[BlastRadius, str] = {
    BlastRadius.SUGGESTION: "read_only",
    BlastRadius.KEPT_STATE: "config",
    BlastRadius.RUNTIME: "runtime",
    BlastRadius.SELF_SOURCE: "runtime",
}


class InvalidRiskDossierError(ValueError):
    """Raised when a risk dossier is malformed or internally incoherent."""


@dataclass(frozen=True, slots=True)
class RiskDossier:
    """The declared risk of one mutation class (G10, as data).

    Four risk facts, exactly the ones the Phase 3 spec names: the
    isolation tier the class demands, its blast radius, whether the
    change is reversible, and whether a compensation path exists. The
    dossier is frozen at construction — a risk claim that could be
    edited in place would silently widen every graduation decision that
    reads it.
    """

    dossier_id: str
    class_id: str
    artifact_class: str
    """The artifact class the mutation class mutates (a
    :class:`evoruntime.plugins.manifest.PluginArtifactType` value)."""

    isolation_tier_demanded: IsolationTier
    blast_radius: BlastRadius
    reversible: bool
    compensable: bool
    dossier_version: int = 1

    def __post_init__(self) -> None:
        for name, value in (("dossier_id", self.dossier_id), ("class_id", self.class_id)):
            if not value or value != value.strip():
                raise InvalidRiskDossierError(f"{name} must be non-empty and trimmed")
        if self.artifact_class not in {t.value for t in PluginArtifactType}:
            raise InvalidRiskDossierError(
                f"artifact_class {self.artifact_class!r} is not a known artifact class"
            )
        if self.dossier_version < 1:
            raise InvalidRiskDossierError(
                f"dossier_version must be >= 1, got {self.dossier_version}"
            )
        if not isinstance(self.isolation_tier_demanded, IsolationTier):
            try:
                object.__setattr__(
                    self, "isolation_tier_demanded", IsolationTier(self.isolation_tier_demanded)
                )
            except ValueError as exc:
                raise InvalidRiskDossierError(
                    f"isolation_tier_demanded {self.isolation_tier_demanded!r} is not an "
                    f"isolation tier (one of {', '.join(t.value for t in IsolationTier)})"
                ) from exc
        if not isinstance(self.blast_radius, BlastRadius):
            try:
                object.__setattr__(self, "blast_radius", BlastRadius(self.blast_radius))
            except ValueError as exc:
                raise InvalidRiskDossierError(
                    f"blast_radius {self.blast_radius!r} is not a blast radius "
                    f"(one of {', '.join(b.value for b in BlastRadius)})"
                ) from exc
        # Coherence, failed closed: a blast radius implies the minimum
        # isolation its own execution needs, and a change that pointer-CAS
        # alone restores is compensable by definition — claiming otherwise
        # is an authoring bug, not a risk appetite.
        demanded = _TIER_RANK[self.isolation_tier_demanded]
        if (
            self.blast_radius is BlastRadius.SELF_SOURCE
            and demanded < _TIER_RANK[IsolationTier.HIGHEST]
        ):
            raise InvalidRiskDossierError(
                f"blast radius 'self_source' demands isolation tier HIGHEST, "
                f"got {self.isolation_tier_demanded.value}"
            )
        if (
            self.blast_radius is BlastRadius.RUNTIME
            and demanded < _TIER_RANK[IsolationTier.EXECUTABLE]
        ):
            raise InvalidRiskDossierError(
                f"blast radius 'runtime' demands at least isolation tier EXECUTABLE, "
                f"got {self.isolation_tier_demanded.value}"
            )
        if self.reversible and not self.compensable:
            raise InvalidRiskDossierError(
                "a reversible change is compensable by pointer rollback — a dossier "
                "claiming reversible=True with compensable=False is incoherent"
            )

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form — the bytes the digest and signature cover."""
        return {
            "schema_id": GRADUATION_DOSSIER_SCHEMA_ID,
            "dossier_id": self.dossier_id,
            "dossier_version": self.dossier_version,
            "class_id": self.class_id,
            "artifact_class": self.artifact_class,
            "isolation_tier_demanded": self.isolation_tier_demanded.value,
            "blast_radius": self.blast_radius.value,
            "reversible": self.reversible,
            "compensable": self.compensable,
        }

    def canonical_bytes(self) -> bytes:
        """Canonical JSON bytes: sorted keys, no whitespace, UTF-8."""
        return json.dumps(
            self.to_canonical_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    @property
    def digest(self) -> str:
        """Content digest of the canonical bytes (``sha256:...``) — the
        value a ``MutationClassBinding.risk_dossier_digest`` pins."""
        return _DIGEST_PREFIX + hashlib.sha256(self.canonical_bytes()).hexdigest()

    def resolved_release(self) -> ResolvedRelease:
        """Project the dossier onto the §13.3 tier input.

        The projection is deliberately faithful and dumb: blast radius
        becomes the runtime surface (and executable/harness flags),
        reversibility carries over as-is. The tier is then computed by
        :func:`resolve_authority_tier` — the same function that tiers
        real releases — so graduation compares risk in the only
        vocabulary the release plane already trusts.
        """
        return ResolvedRelease(
            artifact_classes=(self.artifact_class,),
            contains_executable_content=self.blast_radius
            in (BlastRadius.RUNTIME, BlastRadius.SELF_SOURCE),
            touches_harness=self.blast_radius is BlastRadius.SELF_SOURCE,
            reversible=self.reversible,
            runtime_surface=BLAST_RADIUS_SURFACES[self.blast_radius],
        )


@dataclass(frozen=True, slots=True)
class SignedRiskDossier:
    """A risk dossier bound to its digest and a detached signature.

    Mirrors :class:`evoruntime.security.protected_modules.
    SignedProtectedModulesDocument`: the digest addresses the canonical
    body; the signature and public key vouch for it and are excluded
    from it by construction.
    """

    dossier: RiskDossier
    digest: str
    signature: bytes
    signer_public_key: bytes

    def verify(self) -> bool:
        """True when the digest matches AND the signature verifies over
        the canonical bytes. Either failing means the dossier was
        tampered with."""
        if self.digest != self.dossier.digest:
            return False
        return verify(
            DetachedSignature(signature=self.signature, public_key=self.signer_public_key),
            self.dossier.canonical_bytes(),
        )


class UnsignedRiskDossierError(ValueError):
    """Raised when a risk dossier's signature does not verify."""


def sign_risk_dossier(dossier: RiskDossier, private_key: Ed25519PrivateKey) -> SignedRiskDossier:
    """Sign a risk dossier over its canonical bytes.

    The same detached-signature service release manifests and protected
    modules use, so any party holding the public key can verify which
    risk claim a graduation decision was actually made on.
    """
    detached = sign(private_key, dossier.canonical_bytes())
    return SignedRiskDossier(
        dossier=dossier,
        digest=dossier.digest,
        signature=detached.signature,
        signer_public_key=detached.public_key,
    )


def verify_risk_dossier(signed: SignedRiskDossier) -> None:
    """Verify a signed risk dossier, raising on any mismatch.

    Raises:
        UnsignedRiskDossierError: the digest does not match the
            dossier's canonical bytes, or the signature does not verify.
    """
    if not signed.verify():
        raise UnsignedRiskDossierError(
            f"risk dossier {signed.dossier.dossier_id!r} ({signed.digest}) has no valid "
            "signature over its canonical bytes — refusing to treat it as a risk claim"
        )


class GraduationBinding(Protocol):
    """What graduation needs from a G3 ``MutationClassBinding``.

    Structural, not nominal: the campaign spec's binding satisfies this
    without :mod:`evoruntime.campaign.spec` and the selection plane
    importing each other.
    """

    class_id: str
    risk_dossier_digest: str
    max_tier: IsolationTier


class GraduationRefusal(StrEnum):
    """Why a mutation class was refused graduation.

    Every reason is a recorded decision outcome, not an exception —
    the refusal record is the audit trail the acceptance criterion
    asks for.
    """

    NO_DOSSIER = "no_dossier"
    """No dossier was presented for the class at all."""

    UNVERIFIED_DOSSIER = "unverified_dossier"
    """A presented dossier (candidate or production reference) fails its
    digest/signature verification — tampered policy is not policy."""

    DOSSIER_DIGEST_MISMATCH = "dossier_digest_mismatch"
    """The dossier's digest does not match the digest the class binding
    pinned (G3), or the class was never pinned in a preregistration."""

    CLASS_ID_MISMATCH = "class_id_mismatch"
    """The dossier describes a different mutation class than the one
    being graduated."""

    TIER_EXCEEDS_BINDING = "tier_exceeds_binding"
    """The dossier demands more isolation than the binding's ``max_tier``
    preregistered."""

    NOT_COMPENSABLE = "not_compensable"
    """The dossier declares no compensation path — production rollback
    would be a promise the runtime cannot keep."""

    RISK_NOT_COMPARABLE = "risk_not_comparable"
    """The class's resolved authority tier exceeds the highest tier the
    existing production extensions resolve to (or there are none to
    compare against)."""


@dataclass(frozen=True, slots=True)
class GraduationDecision:
    """The outcome of the comparability check — granted or refused.

    Both outcomes are recordable: :func:`record_graduation_decision`
    appends either to the append-only ``graduation_decisions`` table.
    """

    class_id: str
    granted: bool
    refusal_reason: GraduationRefusal | None
    detail: str
    dossier_digest: str | None = None
    candidate_resolved_tier: int = 0
    production_resolved_tier: int | None = None

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form of the decision (excludes the tenant —
        the record service adds it before signing)."""
        return {
            "schema_id": GRADUATION_DECISION_SCHEMA_ID,
            "class_id": self.class_id,
            "granted": self.granted,
            "refusal_reason": self.refusal_reason.value if self.refusal_reason else None,
            "detail": self.detail,
            "dossier_digest": self.dossier_digest,
            "candidate_resolved_tier": self.candidate_resolved_tier,
            "production_resolved_tier": self.production_resolved_tier,
        }


def _refused(
    class_id: str,
    reason: GraduationRefusal,
    detail: str,
    *,
    dossier_digest: str | None = None,
    candidate_tier: int = 0,
    production_tier: int | None = None,
) -> GraduationDecision:
    return GraduationDecision(
        class_id=class_id,
        granted=False,
        refusal_reason=reason,
        detail=detail,
        dossier_digest=dossier_digest,
        candidate_resolved_tier=candidate_tier,
        production_resolved_tier=production_tier,
    )


def evaluate_graduation(
    *,
    class_id: str,
    signed_dossier: SignedRiskDossier | None,
    binding: GraduationBinding | None,
    production_dossiers: Sequence[SignedRiskDossier],
) -> GraduationDecision:
    """The pure comparability check (G10).

    A class graduates only when its *resolved* risk — the authority tier
    :func:`resolve_authority_tier` computes over the dossier's
    :class:`ResolvedRelease` projection — is comparable to (at or below)
    the highest resolved tier among the production extensions already
    running. Every other failure is a typed refusal:

    1. no dossier presented → ``NO_DOSSIER``
    2. dossier (candidate or production) fails verification →
       ``UNVERIFIED_DOSSIER``
    3. dossier describes another class → ``CLASS_ID_MISMATCH``
    4. digest ≠ the binding's pinned digest, or no binding →
       ``DOSSIER_DIGEST_MISMATCH``
    5. demanded tier exceeds the binding's ``max_tier`` →
       ``TIER_EXCEEDS_BINDING``
    6. no compensation path → ``NOT_COMPENSABLE``
    7. resolved tier above production's, or no production extensions →
       ``RISK_NOT_COMPARABLE``

    The function is pure: no session, no clock, no I/O, and refusals are
    returned decisions rather than exceptions so the caller can record
    them.
    """
    if signed_dossier is None:
        return _refused(
            class_id,
            GraduationRefusal.NO_DOSSIER,
            "no risk dossier was presented for this mutation class — graduation "
            "without a signed comparable-risk dossier is refused",
        )
    if not signed_dossier.verify():
        return _refused(
            class_id,
            GraduationRefusal.UNVERIFIED_DOSSIER,
            f"candidate risk dossier {signed_dossier.dossier.dossier_id!r} fails "
            "digest/signature verification — a tampered dossier is not a risk claim",
            dossier_digest=signed_dossier.digest,
        )
    dossier = signed_dossier.dossier
    if dossier.class_id != class_id:
        return _refused(
            class_id,
            GraduationRefusal.CLASS_ID_MISMATCH,
            f"dossier {dossier.dossier_id!r} describes class {dossier.class_id!r}, "
            f"not the class being graduated ({class_id!r})",
            dossier_digest=signed_dossier.digest,
        )
    if binding is None or signed_dossier.digest != binding.risk_dossier_digest:
        pinned = binding.risk_dossier_digest if binding is not None else None
        return _refused(
            class_id,
            GraduationRefusal.DOSSIER_DIGEST_MISMATCH,
            "dossier digest does not match the digest pinned by the class binding "
            f"(pinned: {pinned!r}, presented: {signed_dossier.digest!r}) — a class "
            "whose dossier changed is a different preregistration",
            dossier_digest=signed_dossier.digest,
        )
    if _TIER_RANK[dossier.isolation_tier_demanded] > _TIER_RANK[binding.max_tier]:
        return _refused(
            class_id,
            GraduationRefusal.TIER_EXCEEDS_BINDING,
            f"dossier demands isolation tier {dossier.isolation_tier_demanded.value} "
            f"but the binding preregistered max_tier {binding.max_tier.value}",
            dossier_digest=signed_dossier.digest,
        )
    if not dossier.compensable:
        return _refused(
            class_id,
            GraduationRefusal.NOT_COMPENSABLE,
            "dossier declares no compensation path — a class production cannot "
            "roll back cannot graduate",
            dossier_digest=signed_dossier.digest,
        )

    candidate_tier = resolve_authority_tier(dossier.resolved_release())
    for production in production_dossiers:
        if not production.verify():
            return _refused(
                class_id,
                GraduationRefusal.UNVERIFIED_DOSSIER,
                f"production reference dossier {production.dossier.dossier_id!r} fails "
                "digest/signature verification — comparability against unverified "
                "policy is meaningless",
                dossier_digest=signed_dossier.digest,
                candidate_tier=int(candidate_tier),
            )
    if not production_dossiers:
        return _refused(
            class_id,
            GraduationRefusal.RISK_NOT_COMPARABLE,
            "no production extensions exist to compare risk against — an empty "
            "production plane is no precedent for graduation",
            dossier_digest=signed_dossier.digest,
            candidate_tier=int(candidate_tier),
        )
    production_tier = max(
        resolve_authority_tier(production.dossier.resolved_release())
        for production in production_dossiers
    )
    if candidate_tier > production_tier:
        return _refused(
            class_id,
            GraduationRefusal.RISK_NOT_COMPARABLE,
            f"resolved authority tier {int(candidate_tier)} exceeds the highest tier "
            f"existing production extensions resolve to ({int(production_tier)}) — "
            "graduation demands risk comparable to production, not more",
            dossier_digest=signed_dossier.digest,
            candidate_tier=int(candidate_tier),
            production_tier=int(production_tier),
        )
    return GraduationDecision(
        class_id=class_id,
        granted=True,
        refusal_reason=None,
        detail=(
            f"resolved authority tier {int(candidate_tier)} is comparable to the "
            f"highest production extension tier ({int(production_tier)}); dossier "
            f"{signed_dossier.digest} matches the binding's pinned digest"
        ),
        dossier_digest=signed_dossier.digest,
        candidate_resolved_tier=int(candidate_tier),
        production_resolved_tier=int(production_tier),
    )


def _decision_payload(decision: GraduationDecision, tenant_id: str) -> dict[str, Any]:
    """The canonical signed payload for one decision record."""
    return {"tenant_id": tenant_id, **decision.to_canonical_dict()}


def decision_canonical_bytes(payload: dict[str, Any]) -> bytes:
    """Canonical JSON bytes of a decision payload (sorted keys, compact)."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def record_graduation_decision(
    session: Session,
    *,
    private_key: Ed25519PrivateKey,
    tenant_id: str,
    decision: GraduationDecision,
) -> GraduationDecisionRow:
    """Append one signed graduation decision to the ledger.

    The canonical decision payload (tenant included) is signed with the
    evaluator key and stored alongside the row, so
    :func:`verify_graduation_decision` can re-derive the signed bytes
    from the row alone. Granted and refused decisions are recorded
    alike — a refusal that leaves no record is not a governed refusal.
    The caller owns the commit discipline, as everywhere in the runtime.
    """
    payload = _decision_payload(decision, tenant_id)
    detached = sign(private_key, decision_canonical_bytes(payload))
    row = GraduationDecisionRow(
        tenant_id=tenant_id,
        class_id=decision.class_id,
        dossier_digest=decision.dossier_digest,
        granted=decision.granted,
        refusal_reason=decision.refusal_reason.value if decision.refusal_reason else None,
        detail=payload,
        candidate_resolved_tier=decision.candidate_resolved_tier,
        production_resolved_tier=decision.production_resolved_tier,
        signature=detached.signature,
        signer_public_key=detached.public_key,
    )
    session.add(row)
    session.flush()
    audit_log.warning(
        "graduation.decision",
        extra={
            "tenant_id": tenant_id,
            "class_id": decision.class_id,
            "granted": decision.granted,
            "refusal_reason": decision.refusal_reason.value if decision.refusal_reason else None,
        },
    )
    return row


def verify_graduation_decision(row: GraduationDecisionRow) -> bool:
    """True when the stored record still verifies against its signature.

    Re-derives the canonical bytes from the row's own ``detail`` payload
    and checks the detached signature — a row whose payload was edited
    (by a bug, a migration script, or a psql session) no longer
    verifies, even though the append-only trigger already made editing
    it impossible.
    """
    detail = row.detail
    if not isinstance(detail, dict) or "tenant_id" not in detail:
        return False
    return verify(
        DetachedSignature(signature=row.signature, public_key=row.signer_public_key),
        decision_canonical_bytes(detail),
    )
