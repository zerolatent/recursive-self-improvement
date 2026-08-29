"""H8 backup-tier tombstone coverage (§17.3 row 3).

Proves the payload-deletion backup-tier story: a deleted payload cannot
resurface from any tier. The policy (7-day primary / 35-day backup
age-out) plus tombstone-coverage semantics in
``evoruntime.lineage.backup`` are the smallest honest version; the
crypto-erase design remains an open question per the spec.

Three properties:

1. **Restore refuses tombstoned payloads** on every tier, even while the
   backup bytes still exist (the access half of "cannot resurface").
2. **Age-out physically removes the bytes** — after the sweep, no tier
   holds the payload, so there is nothing left to restore from.
3. **Coverage fails closed** — a tombstoned payload whose tier copy has
   no age-out deadline scheduled is reported by the audit, and the test
   treats any such gap as a failure.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from evoruntime.lineage.backup import (
    BACKUP_AGE_OUT_DAYS,
    PRIMARY_AGE_OUT_DAYS,
    BackupAgeOutPolicy,
    BackupEntry,
    InMemoryBackupTier,
    RestoreRefusedError,
    TombstoneCoverageError,
    audit_tombstone_coverage,
    restore,
    run_age_out_sweep,
    schedule_age_out,
)

TENANT_ID = "tnt_h8_backup"
DIGEST = "sha256:" + "cd" * 32
DELETED_AT = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
POLICY = BackupAgeOutPolicy()


def _entry(tier: str = "backup", digest: str = DIGEST) -> BackupEntry:
    return BackupEntry(
        tenant_id=TENANT_ID,
        payload_digest=digest,
        tier=tier,
        stored_at=DELETED_AT - timedelta(days=1),
        content=b"deleted payload bytes",
    )


def test_policy_windows_match_spec() -> None:
    """§17.3 row 3: 7-day primary / 35-day backup age-out, anchored at
    the deletion request."""
    assert POLICY.primary_age_out_days == PRIMARY_AGE_OUT_DAYS == 7
    assert POLICY.backup_age_out_days == BACKUP_AGE_OUT_DAYS == 35
    assert POLICY.deadline_for("primary", DELETED_AT) == DELETED_AT + timedelta(days=7)
    assert POLICY.deadline_for("backup", DELETED_AT) == DELETED_AT + timedelta(days=35)


def test_restore_refuses_tombstoned_payload_even_with_bytes_present() -> None:
    """The access half of 'cannot resurface': while a tombstone exists, no
    tier returns the bytes — even before age-out removes them."""
    tier = InMemoryBackupTier()
    tier.put(_entry())

    with pytest.raises(RestoreRefusedError):
        restore(tier, tenant_id=TENANT_ID, payload_digest=DIGEST, tombstone_exists=True)


def test_restore_serves_live_payload_without_tombstone() -> None:
    tier = InMemoryBackupTier()
    tier.put(_entry())

    assert restore(tier, tenant_id=TENANT_ID, payload_digest=DIGEST, tombstone_exists=False) == (
        b"deleted payload bytes"
    )


def test_age_out_sweep_physically_removes_backup_bytes() -> None:
    """After age-out there are no bytes on any tier — nothing to resurface."""
    tier = InMemoryBackupTier()
    tier.put(_entry())
    schedule_age_out(
        tier, tenant_id=TENANT_ID, payload_digest=DIGEST, deleted_at=DELETED_AT, policy=POLICY
    )

    # Before the deadline the copy is still on the tier (restore is what
    # refuses it), after the deadline the sweep removes it.
    before_deadline = POLICY.deadline_for("backup", DELETED_AT) - timedelta(seconds=1)
    assert run_age_out_sweep(tier, now=before_deadline) == ()
    assert tier.get(tenant_id=TENANT_ID, payload_digest=DIGEST) is not None

    after_deadline = POLICY.deadline_for("backup", DELETED_AT) + timedelta(seconds=1)
    assert run_age_out_sweep(tier, now=after_deadline) == (DIGEST,)
    assert tier.get(tenant_id=TENANT_ID, payload_digest=DIGEST) is None


def test_age_out_sweep_never_touches_live_payloads() -> None:
    """Copies without a scheduled deadline are live payloads — untouched."""
    tier = InMemoryBackupTier()
    live_digest = "sha256:" + "ef" * 32
    tier.put(_entry(digest=live_digest))

    assert run_age_out_sweep(tier, now=DELETED_AT + timedelta(days=365)) == ()
    assert tier.get(tenant_id=TENANT_ID, payload_digest=live_digest) is not None


def test_schedule_age_out_fails_closed_when_tier_holds_no_copy() -> None:
    """Scheduling age-out for a copy that does not exist would silently
    pretend coverage the tier does not have — refuse instead."""
    tier = InMemoryBackupTier()

    with pytest.raises(TombstoneCoverageError):
        schedule_age_out(
            tier, tenant_id=TENANT_ID, payload_digest=DIGEST, deleted_at=DELETED_AT, policy=POLICY
        )


def test_audit_reports_unscheduled_tombstoned_copies() -> None:
    """Coverage fails closed: a tombstoned payload whose tier copy has no
    age-out deadline is a resurfacing risk the audit reports."""
    tier = InMemoryBackupTier()
    covered_digest = "sha256:" + "11" * 32
    uncovered_digest = "sha256:" + "22" * 32
    tier.put(_entry(digest=covered_digest))
    tier.put(_entry(digest=uncovered_digest))
    schedule_age_out(
        tier,
        tenant_id=TENANT_ID,
        payload_digest=covered_digest,
        deleted_at=DELETED_AT,
        policy=POLICY,
    )

    gaps = audit_tombstone_coverage(tier, tombstoned_digests={covered_digest, uncovered_digest})

    assert [entry.payload_digest for entry in gaps] == [uncovered_digest]


def test_audit_clean_when_every_tombstoned_copy_is_scheduled() -> None:
    tier = InMemoryBackupTier()
    tier.put(_entry())
    schedule_age_out(
        tier, tenant_id=TENANT_ID, payload_digest=DIGEST, deleted_at=DELETED_AT, policy=POLICY
    )

    assert audit_tombstone_coverage(tier, tombstoned_digests={DIGEST}) == ()
