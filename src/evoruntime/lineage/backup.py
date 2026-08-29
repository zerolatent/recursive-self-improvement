"""Backup-tier age-out policy for payload deletion (§17.3 row 3, H8).

The spec's smallest honest version of the backup-tier story: a documented
age-out policy (7-day primary / 35-day backup, matching §17.3 row 3) plus
tombstone-coverage semantics proving a deleted payload cannot resurface
from any tier. Crypto-erasure for encrypted backups remains an open
question (spec §21) until a deployment requires it — this module is the
smallest honest version, not the final design.

The model, in three rules:

1. **Restore refuses tombstoned payloads.** From the moment a deletion is
   requested, a tombstone exists for ``(tenant_id, "payload", digest)``;
   any restore from any tier must consult that tombstone and refuse. This
   is the access-control half of "cannot resurface" and it holds for as
   long as the tombstone exists — regardless of whether the bytes are
   still in the backup tier.
2. **Age-out physically removes the bytes.** A backup copy is scheduled
   for deletion when the tombstone covers it: ``deletion requested +
   backup_age_out_days``. The sweep deletes entries past their deadline,
   so after age-out there are no bytes to restore from any tier.
3. **Coverage is auditable, and fails closed.** A backup copy whose
   payload has a tombstone but no age-out deadline is a resurfacing risk
   the audit reports; the tombstone-coverage test treats any such gap as
   a failure.

The reference ``InMemoryBackupTier`` stands in for the deployment's
encrypted object store: the policy and coverage semantics are what Phase 4
commits to, and they are tier-agnostic by construction (any ``BackupTier``
implementation inherits the same guarantees).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

#: §17.3 row 3: primary payloads age out after 7 days, backups after 35.
PRIMARY_AGE_OUT_DAYS = 7
BACKUP_AGE_OUT_DAYS = 35


class BackupTierError(RuntimeError):
    """A backup-tier operation violated the deletion policy."""


class TombstoneCoverageError(BackupTierError):
    """A tier holds a payload its tombstone does not fully cover."""


class RestoreRefusedError(BackupTierError):
    """A restore was refused because the payload is tombstoned."""


@dataclass(frozen=True)
class BackupAgeOutPolicy:
    """Documented age-out windows, anchored at the deletion request."""

    primary_age_out_days: int = PRIMARY_AGE_OUT_DAYS
    backup_age_out_days: int = BACKUP_AGE_OUT_DAYS

    def deadline_for(self, tier: str, deleted_at: datetime) -> datetime:
        """When a copy on ``tier`` must be physically gone after deletion."""
        days = self.primary_age_out_days if tier == "primary" else self.backup_age_out_days
        return deleted_at + timedelta(days=days)


@dataclass
class BackupEntry:
    """One payload copy held on one tier.

    ``age_out_at`` is ``None`` while the payload is live; the deletion
    flow sets it when the tombstone covers this copy.
    """

    tenant_id: str
    payload_digest: str
    tier: str
    stored_at: datetime
    content: bytes
    age_out_at: datetime | None = None


class BackupTier:
    """The tier protocol: put/get/delete/list, nothing else."""

    def put(self, entry: BackupEntry) -> None:
        raise NotImplementedError

    def get(self, *, tenant_id: str, payload_digest: str) -> BackupEntry | None:
        raise NotImplementedError

    def delete(self, *, tenant_id: str, payload_digest: str) -> bool:
        raise NotImplementedError

    def entries(self) -> tuple[BackupEntry, ...]:
        raise NotImplementedError


class InMemoryBackupTier(BackupTier):
    """Reference tier implementation for tests and ops drills.

    A real deployment swaps in an encrypted object store; the policy and
    audit semantics below are deliberately implementation-agnostic.
    """

    def __init__(self, name: str = "backup") -> None:
        self.name = name
        self._entries: dict[tuple[str, str], BackupEntry] = {}

    def put(self, entry: BackupEntry) -> None:
        self._entries[(entry.tenant_id, entry.payload_digest)] = entry

    def get(self, *, tenant_id: str, payload_digest: str) -> BackupEntry | None:
        return self._entries.get((tenant_id, payload_digest))

    def delete(self, *, tenant_id: str, payload_digest: str) -> bool:
        return self._entries.pop((tenant_id, payload_digest), None) is not None

    def entries(self) -> tuple[BackupEntry, ...]:
        return tuple(self._entries.values())


def schedule_age_out(
    tier: BackupTier,
    *,
    tenant_id: str,
    payload_digest: str,
    deleted_at: datetime,
    policy: BackupAgeOutPolicy,
) -> BackupEntry:
    """Mark the tier's copy of a tombstoned payload for age-out.

    Returns the updated entry. Raises ``TombstoneCoverageError`` if the
    tier holds no copy — scheduling age-out for a copy that does not
    exist would silently pretend coverage the tier does not have.
    """
    entry = tier.get(tenant_id=tenant_id, payload_digest=payload_digest)
    if entry is None:
        raise TombstoneCoverageError(
            f"tier holds no copy of {payload_digest!r} for {tenant_id!r}; "
            "cannot schedule age-out for a copy that does not exist"
        )
    entry.age_out_at = policy.deadline_for(entry.tier, deleted_at)
    return entry


def run_age_out_sweep(tier: BackupTier, *, now: datetime) -> tuple[str, ...]:
    """Delete every copy whose age-out deadline has passed.

    Returns the purged payload digests. Copies without a deadline are
    live payloads — never touched.
    """
    purged: list[str] = []
    for entry in tier.entries():
        if entry.age_out_at is not None and entry.age_out_at <= now:
            tier.delete(tenant_id=entry.tenant_id, payload_digest=entry.payload_digest)
            purged.append(entry.payload_digest)
    return tuple(purged)


def restore(
    tier: BackupTier,
    *,
    tenant_id: str,
    payload_digest: str,
    tombstone_exists: bool,
) -> bytes:
    """Restore payload bytes from a tier — refusing tombstoned payloads.

    This is the access half of "cannot resurface": while a tombstone
    exists for the payload, no tier may return its bytes, even if the
    backup copy has not aged out yet. After age-out there are no bytes
    left to refuse.
    """
    if tombstone_exists:
        raise RestoreRefusedError(
            f"payload {payload_digest!r} is tombstoned; restore from tier "
            f"{getattr(tier, 'name', tier)!r} is refused"
        )
    entry = tier.get(tenant_id=tenant_id, payload_digest=payload_digest)
    if entry is None:
        raise KeyError(f"no backup copy of {payload_digest!r} for {tenant_id!r}")
    return entry.content


def audit_tombstone_coverage(
    tier: BackupTier, *, tombstoned_digests: set[str]
) -> tuple[BackupEntry, ...]:
    """Return the tier's copies that a tombstone does not fully cover.

    A copy is fully covered when its payload has a tombstone *and* an
    age-out deadline has been scheduled. Any entry in the returned tuple
    is a resurfacing risk: bytes exist on the tier with deletion requested
    but no removal scheduled.
    """
    return tuple(
        entry
        for entry in tier.entries()
        if entry.payload_digest in tombstoned_digests and entry.age_out_at is None
    )
