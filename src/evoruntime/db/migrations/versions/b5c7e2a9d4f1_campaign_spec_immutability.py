"""campaign spec immutability

Revision ID: b5c7e2a9d4f1
Revises: f9c0de1a7e55
Create Date: 2026-08-29 09:10:00.000000

Deliverable G3 (Phase 3): the pinned campaign preregistration is
tamper-evident at the storage layer.

The campaign spec's canonical bytes, digest, signature, and signer key are
the preregistration — with G3 the digest also binds the environment claim
and the pinned mutation classes. A stored spec that could be edited after
pinning would be a forgery wearing a signature's clothes, so the four
pinned columns get a `BEFORE UPDATE OR DELETE` trigger that refuses any
change to them. Lifecycle columns (`phase`, `resume_target`,
`updated_at`) stay mutable — the trigger compares OLD and NEW and only
fires when a pinned column differs. Like the lineage-store and holdout
ledger guards, this is deliberately a trigger, not a `REVOKE`: it fires
for every role, including the table owner and a superuser.
"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b5c7e2a9d4f1"
down_revision: str | Sequence[str] | None = "f9c0de1a7e55"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION evoruntime_forbid_spec_mutation() RETURNS trigger AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION
            'campaign %: the pinned spec is immutable — deleting it would orphan its log',
            OLD.campaign_id;
    END IF;
    IF NEW.spec_digest IS DISTINCT FROM OLD.spec_digest
       OR NEW.spec_canonical IS DISTINCT FROM OLD.spec_canonical
       OR NEW.spec_signature IS DISTINCT FROM OLD.spec_signature
       OR NEW.signer_public_key IS DISTINCT FROM OLD.signer_public_key THEN
        RAISE EXCEPTION
            'campaign %: pinned spec columns are immutable — an edited spec is a forgery',
            NEW.campaign_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

_GUARD_TRIGGER = """
CREATE TRIGGER trg_campaigns_spec_immutable
BEFORE UPDATE OR DELETE ON campaigns
FOR EACH ROW EXECUTE FUNCTION evoruntime_forbid_spec_mutation();
"""

_DROP_TRIGGER = "DROP TRIGGER IF EXISTS trg_campaigns_spec_immutable ON campaigns;"
_DROP_FUNCTION = "DROP FUNCTION IF EXISTS evoruntime_forbid_spec_mutation();"


def upgrade() -> None:
    """Guard the pinned spec columns of `campaigns` against mutation."""
    op.execute(_GUARD_FUNCTION)
    op.execute(_GUARD_TRIGGER)


def downgrade() -> None:
    """Remove the pinned-spec immutability guard."""
    op.execute(_DROP_TRIGGER)
    op.execute(_DROP_FUNCTION)
