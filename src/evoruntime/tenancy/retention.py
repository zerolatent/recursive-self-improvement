"""§21 decision 7 (2026-08-30 ruling): the retention policy, as signed data.

The ruling fixes five retention facts for every tenant:

* trace events are retained 90 days;
* payloads are retained 30 days, unless a lineage node still references
  them — then retention follows the lineage node's lifetime;
* evaluation attestations, admission records, ledger rows, and tombstones
  are retained indefinitely — they are the evidence substrate, and a
  runtime that could purge its own evidence would vouch for nothing;
* derived payloads (embeddings, caches, index rows) must be
  crypto-erased within 24 hours of the owning payload's access being
  revoked;
* backups must age out within 30 days.

Like the tenant-policy seeds, this ships as a signed document rather
than enforcement code: the D4 deletion machinery (tombstones, derived
purge sweep, backup age-out) already implements the mechanics, and the
document's job is to pin the numbers that machinery resolves to. The
resolution helpers below read the existing knobs —
``LineageSettings.derived_purge_sla_seconds`` and
``BackupAgeOutPolicy`` — so a deployment loading this document gets the
§21 values through the same surfaces the sweeps already consume.
"""

from __future__ import annotations

import base64
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy.orm import Session

from evoruntime.lineage.backup import BackupAgeOutPolicy
from evoruntime.lineage.settings import LineageSettings, get_lineage_settings

SEED_RETENTION_POLICY_ID = "evoruntime-seed-retention-policy"

#: §21 decision 7 values. Module constants so tests and operators can
#: import the ruling's numbers without constructing a document.
TRACE_RETENTION_DAYS = 90
PAYLOAD_RETENTION_DAYS = 30
DERIVED_CRYPTO_ERASURE_SLA_HOURS = 24
BACKUP_CRYPTO_ERASURE_DAYS = 30

#: The evidence substrate: record classes that are never purged. A
#: retention document that claims any of these is purgeable is refused
#: at construction — the ruling is structural, not a default.
INDEFINITE_RETENTION_RECORDS: frozenset[str] = frozenset(
    {
        "evaluation_attestations",
        "admission_records",
        "ledger_rows",
        "tombstones",
    }
)


class RetentionPolicyError(ValueError):
    """Raised when a retention-policy document is internally incoherent."""


class UnsignedRetentionPolicyError(ValueError):
    """Raised when a retention-policy document's signature does not verify."""


class RetentionPolicyDocument:
    """One tenant's retention defaults, as signed data.

    Same discipline as :class:`~evoruntime.tenancy.policy.TenantPolicyDocument`:
    canonical JSON bytes, a detached Ed25519 signature over those bytes,
    and construction-time validation that refuses incoherent documents —
    a retention policy that claims the evidence substrate is purgeable
    governs nothing.
    """

    def __init__(
        self,
        *,
        tenant_id: str,
        policy_id: str = SEED_RETENTION_POLICY_ID,
        policy_version: int = 1,
        trace_retention_days: int = TRACE_RETENTION_DAYS,
        payload_retention_days: int = PAYLOAD_RETENTION_DAYS,
        payload_retention_follows_lineage: bool = True,
        indefinite_retention_records: frozenset[str] | set[str] | tuple[str, ...] = (
            INDEFINITE_RETENTION_RECORDS
        ),
        derived_crypto_erasure_sla_hours: int = DERIVED_CRYPTO_ERASURE_SLA_HOURS,
        backup_crypto_erasure_days: int = BACKUP_CRYPTO_ERASURE_DAYS,
    ) -> None:
        self.tenant_id = tenant_id
        self.policy_id = policy_id
        self.policy_version = policy_version
        self.trace_retention_days = trace_retention_days
        self.payload_retention_days = payload_retention_days
        self.payload_retention_follows_lineage = payload_retention_follows_lineage
        self.indefinite_retention_records = frozenset(indefinite_retention_records)
        self.derived_crypto_erasure_sla_hours = derived_crypto_erasure_sla_hours
        self.backup_crypto_erasure_days = backup_crypto_erasure_days
        self._validate()

    def _validate(self) -> None:
        if not self.tenant_id:
            raise RetentionPolicyError("tenant_id must be a non-empty string")
        if self.trace_retention_days < 1:
            raise RetentionPolicyError(
                f"trace_retention_days must be >= 1, got {self.trace_retention_days}"
            )
        if self.payload_retention_days < 1:
            raise RetentionPolicyError(
                f"payload_retention_days must be >= 1, got {self.payload_retention_days}"
            )
        if self.derived_crypto_erasure_sla_hours < 1:
            raise RetentionPolicyError(
                "derived_crypto_erasure_sla_hours must be >= 1, got "
                f"{self.derived_crypto_erasure_sla_hours}"
            )
        if self.backup_crypto_erasure_days < 1:
            raise RetentionPolicyError(
                f"backup_crypto_erasure_days must be >= 1, got {self.backup_crypto_erasure_days}"
            )
        missing = INDEFINITE_RETENTION_RECORDS - self.indefinite_retention_records
        if missing:
            raise RetentionPolicyError(
                "the evidence substrate is never purgeable — a retention policy "
                f"missing {sorted(missing)} from its indefinite-retention set is "
                "refused (§21 decision 7)"
            )

    def payload_retention_days_for(self, *, lineage_referenced: bool) -> int | None:
        """The payload retention that applies to one payload.

        30 days for an unreferenced payload; ``None`` (retention follows
        the referencing lineage node's lifetime) when an active lineage
        node still points at it. ``None`` is the honest encoding of
        "no independent deadline" — the caller joins to the lineage node
        rather than this document inventing a number.
        """
        if lineage_referenced and self.payload_retention_follows_lineage:
            return None
        return self.payload_retention_days

    def to_dict(self) -> dict[str, Any]:
        """The document as plain data — the pre-canonical form."""
        return {
            "tenant_id": self.tenant_id,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "trace_retention_days": self.trace_retention_days,
            "payload_retention_days": self.payload_retention_days,
            "payload_retention_follows_lineage": self.payload_retention_follows_lineage,
            "indefinite_retention_records": sorted(self.indefinite_retention_records),
            "derived_crypto_erasure_sla_hours": self.derived_crypto_erasure_sla_hours,
            "backup_crypto_erasure_days": self.backup_crypto_erasure_days,
        }

    def canonical_bytes(self) -> bytes:
        """Canonical JSON bytes: sorted keys, no whitespace, UTF-8."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()

    def digest(self) -> str:
        import hashlib

        return "sha256:" + hashlib.sha256(self.canonical_bytes()).hexdigest()


class SignedRetentionPolicyDocument:
    """A retention policy document plus its detached signature."""

    def __init__(
        self,
        document: RetentionPolicyDocument,
        *,
        signature_b64: str,
        public_key_b64: str,
    ) -> None:
        self.document = document
        self.signature_b64 = signature_b64
        self.public_key_b64 = public_key_b64

    def verify(self) -> None:
        """Verify the detached signature over the document's canonical bytes."""
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(self.public_key_b64))
        signature = base64.b64decode(self.signature_b64)
        try:
            public_key.verify(signature, self.document.canonical_bytes())
        except Exception as exc:
            raise UnsignedRetentionPolicyError(
                f"retention policy {self.document.policy_id!r} for tenant "
                f"{self.document.tenant_id!r} failed signature verification — "
                "the document's bytes are not the ones the signature covers"
            ) from exc


def seed_retention_policy(tenant_id: str) -> RetentionPolicyDocument:
    """The shipped §21 decision-7 retention seed for one tenant."""
    return RetentionPolicyDocument(tenant_id=tenant_id)


def sign_retention_policy(
    document: RetentionPolicyDocument, private_key: Any
) -> SignedRetentionPolicyDocument:
    """Sign a retention-policy document over its canonical bytes."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RetentionPolicyError("retention policies are signed with an Ed25519 private key")
    signature = private_key.sign(document.canonical_bytes())
    return SignedRetentionPolicyDocument(
        document,
        signature_b64=base64.b64encode(signature).decode(),
        public_key_b64=base64.b64encode(private_key.public_key().public_bytes_raw()).decode(),
    )


def derived_erasure_sla_seconds(settings: LineageSettings | None = None) -> int:
    """The derived-payload crypto-erasure SLO, resolved from the D4 knob.

    The document declares 24 hours (§21 decision 7); the sweep consumes
    ``LineageSettings.derived_purge_sla_seconds``. Resolving through the
    knob — rather than hardcoding the constant at call sites — keeps the
    document and the sweep on one number.
    """
    resolved = (
        settings.derived_purge_sla_seconds
        if settings is not None
        else get_lineage_settings().derived_purge_sla_seconds
    )
    declared = DERIVED_CRYPTO_ERASURE_SLA_HOURS * 3600
    if resolved != declared:
        raise RetentionPolicyError(
            f"the derived-purge knob resolves to {resolved}s but the §21 decision-7 "
            f"retention policy declares {declared}s — the deployment's settings "
            "contradict its signed retention policy"
        )
    return resolved


def backup_age_out_policy() -> BackupAgeOutPolicy:
    """The backup age-out the §21 decision-7 policy resolves to.

    Feeds the ruling's 30-day backup crypto-erasure SLO through the
    existing ``BackupAgeOutPolicy`` knob the backup sweep already
    consumes; the primary age-out stays at its §17.3 row-3 value.
    """
    return BackupAgeOutPolicy(
        primary_age_out_days=7,
        backup_age_out_days=BACKUP_CRYPTO_ERASURE_DAYS,
    )


def record_retention_refusal(
    session: Session,
    *,
    tenant_id: str,
    reason: str,
    detail: dict[str, Any],
    actor: str = "",
) -> None:
    """Record an audited refusal of a retention-policy violation.

    Retention refusals ride the same append-only ledger as the scaffold
    boundaries — a purge that violated the retention policy is exactly
    the kind of action the audit trail must outlive. Uses the shared
    ``record_refusal`` helper with the RETENTION boundary.
    """
    from evoruntime.tenancy.audit import record_refusal
    from evoruntime.tenancy.boundaries import RefusalBoundary

    record_refusal(
        session,
        tenant_id=tenant_id,
        boundary=RefusalBoundary.RETENTION,
        reason=reason,
        detail=detail,
        actor=actor,
    )


__all__ = [
    "BACKUP_CRYPTO_ERASURE_DAYS",
    "DERIVED_CRYPTO_ERASURE_SLA_HOURS",
    "INDEFINITE_RETENTION_RECORDS",
    "PAYLOAD_RETENTION_DAYS",
    "SEED_RETENTION_POLICY_ID",
    "TRACE_RETENTION_DAYS",
    "RetentionPolicyDocument",
    "RetentionPolicyError",
    "SignedRetentionPolicyDocument",
    "UnsignedRetentionPolicyError",
    "backup_age_out_policy",
    "derived_erasure_sla_seconds",
    "record_retention_refusal",
    "seed_retention_policy",
    "sign_retention_policy",
]
