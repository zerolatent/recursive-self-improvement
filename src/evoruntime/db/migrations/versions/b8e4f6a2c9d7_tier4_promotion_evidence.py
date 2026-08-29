"""tier-4 promotion requests: evidence columns, kind vocabulary, guard

Revision ID: b8e4f6a2c9d7
Revises: a7b3c9d4e2f1
Create Date: 2026-08-29 10:05:00.000000

Deliverable G7 (highest-risk approvals). Three changes, one migration:

1. The request-kind vocabulary widens: ``approval_requests.kind`` and
   ``admission_records.kind`` now admit ``tier4_promotion`` — the review
   board's scaffold-class promotion kind, judged on the full tier-4
   evidence chain.
2. ``approval_requests`` gains the two tier-4 evidence legs recorded when
   a request is opened: ``human_signoff`` and ``manually_initiated``
   (both NOT NULL, defaulting false — a pre-G7 row is simply a request
   that never claimed the tier-4 legs).
3. The evidence columns are made immutable *in the database*: a trigger
   refuses any UPDATE that changes a request's kind, tier, requester,
   target, or evidence legs, and refuses DELETE and TRUNCATE outright. The
   request row's ``status`` stays a mutable projection of its decisions
   (that is by design — the tamper-evident artifacts are the decision
   rows and the signed admission record), but the evidence a tier-4
   admission is judged on must not be editable after the fact: flipping
   ``human_signoff`` on a pending request would manufacture the exact
   evidence the gate is supposed to verify.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

REQUEST_KIND_CHECK_OLD = "kind IN ('privileged_admission', 'tier3_promotion')"
REQUEST_KIND_CHECK_NEW = "kind IN ('privileged_admission', 'tier3_promotion', 'tier4_promotion')"

EVIDENCE_GUARD_FUNCTION = """
CREATE OR REPLACE FUNCTION evoruntime_guard_request_evidence() RETURNS trigger AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'approval_requests is evidence-guarded: % is not permitted', TG_OP
            USING ERRCODE = 'restrict_violation';
    END IF;
    IF NEW.kind IS DISTINCT FROM OLD.kind
       OR NEW.tier IS DISTINCT FROM OLD.tier
       OR NEW.requested_by IS DISTINCT FROM OLD.requested_by
       OR NEW.campaign_id IS DISTINCT FROM OLD.campaign_id
       OR NEW.proposal_id IS DISTINCT FROM OLD.proposal_id
       OR NEW.plugin_id IS DISTINCT FROM OLD.plugin_id
       OR NEW.content_digest IS DISTINCT FROM OLD.content_digest
       OR NEW.privileged_role IS DISTINCT FROM OLD.privileged_role
       OR NEW.human_signoff IS DISTINCT FROM OLD.human_signoff
       OR NEW.manually_initiated IS DISTINCT FROM OLD.manually_initiated THEN
        RAISE EXCEPTION 'approval_requests evidence columns are immutable: % changed',
            TG_OP USING ERRCODE = 'restrict_violation';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
"""

EVIDENCE_GUARD_TRIGGER = """
CREATE TRIGGER trg_approval_requests_evidence_guard
BEFORE UPDATE OR DELETE ON approval_requests
FOR EACH ROW EXECUTE FUNCTION evoruntime_guard_request_evidence();
"""

TRUNCATE_GUARD_TRIGGER = """
CREATE TRIGGER trg_approval_requests_no_truncate
BEFORE TRUNCATE ON approval_requests
FOR EACH STATEMENT EXECUTE FUNCTION evoruntime_guard_request_evidence();
"""


# revision identifiers, used by Alembic.
revision: str = "b8e4f6a2c9d7"
down_revision: str | Sequence[str] | None = "d9c3e7a1f5b8"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # 1. Widen the kind vocabulary on both tables.
    op.drop_constraint("ck_approval_requests_kind", "approval_requests", type_="check")
    op.create_check_constraint(
        "ck_approval_requests_kind", "approval_requests", REQUEST_KIND_CHECK_NEW
    )
    op.drop_constraint("ck_admission_records_kind", "admission_records", type_="check")
    op.create_check_constraint(
        "ck_admission_records_kind", "admission_records", REQUEST_KIND_CHECK_NEW
    )
    # 2. The tier-4 evidence legs, recorded at request creation.
    op.add_column(
        "approval_requests",
        sa.Column("human_signoff", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "approval_requests",
        sa.Column("manually_initiated", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    # 3. The evidence guard: the legs are immutable once recorded.
    op.execute(EVIDENCE_GUARD_FUNCTION)
    op.execute(EVIDENCE_GUARD_TRIGGER)
    op.execute(TRUNCATE_GUARD_TRIGGER)


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("DROP TRIGGER IF EXISTS trg_approval_requests_evidence_guard ON approval_requests")
    op.execute("DROP TRIGGER IF EXISTS trg_approval_requests_no_truncate ON approval_requests")
    op.execute("DROP FUNCTION IF EXISTS evoruntime_guard_request_evidence()")
    # Purge tier-4 rows before narrowing the kind vocabulary back — the
    # old check constraints refuse the tier4_promotion kind, so a
    # downgrade with tier-4 rows still present would fail on the
    # constraint swap. admission_records is append-only by trigger, so
    # its guard is lifted for the purge and re-instated after (the same
    # statement the originating migration used). Decisions and admission
    # records go first (they reference requests by id, no DB-level FK,
    # but the request rows are the evidence the other tables hang off).
    op.execute("DROP TRIGGER IF EXISTS admission_records_forbid_mutation ON admission_records")
    op.execute("DELETE FROM admission_records WHERE kind = 'tier4_promotion'")
    op.execute(
        "CREATE TRIGGER admission_records_forbid_mutation "
        "BEFORE UPDATE OR DELETE ON admission_records "
        "FOR EACH ROW EXECUTE FUNCTION evoruntime_forbid_mutation();"
    )
    op.execute("DROP TRIGGER IF EXISTS approval_decisions_forbid_mutation ON approval_decisions")
    op.execute(
        "DELETE FROM approval_decisions WHERE request_id IN "
        "(SELECT request_id FROM approval_requests WHERE kind = 'tier4_promotion')"
    )
    op.execute(
        "CREATE TRIGGER approval_decisions_forbid_mutation "
        "BEFORE UPDATE OR DELETE ON approval_decisions "
        "FOR EACH ROW EXECUTE FUNCTION evoruntime_forbid_mutation();"
    )
    op.execute("DELETE FROM approval_requests WHERE kind = 'tier4_promotion'")
    op.drop_column("approval_requests", "manually_initiated")
    op.drop_column("approval_requests", "human_signoff")
    op.drop_constraint("ck_admission_records_kind", "admission_records", type_="check")
    op.create_check_constraint(
        "ck_admission_records_kind", "admission_records", REQUEST_KIND_CHECK_OLD
    )
    op.drop_constraint("ck_approval_requests_kind", "approval_requests", type_="check")
    op.create_check_constraint(
        "ck_approval_requests_kind", "approval_requests", REQUEST_KIND_CHECK_OLD
    )
