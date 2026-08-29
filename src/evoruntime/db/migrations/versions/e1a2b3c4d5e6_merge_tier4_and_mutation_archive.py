"""merge tier4_promotion_evidence and scaffold_mutation_archive heads

Revision ID: e1a2b3c4d5e6
Revises: b8e4f6a2c9d7, c8d5e2f4a7b9
Create Date: 2026-08-29

G11 integration fix: G7 (tier-4 promotion evidence) and G8/G9 (scaffold
mutation archive) each branched their migration off `d9c3e7a1f5b8`
(graduation_decisions), leaving the migration graph with two heads. Every
DB-backed test path runs `alembic upgrade head`, which refuses ambiguous
heads — so the integrated release could not migrate at all until the
branches were joined. This is a pure graph merge: no schema changes, no
data movement.
"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "e1a2b3c4d5e6"
down_revision: str | Sequence[str] | None = ("b8e4f6a2c9d7", "c8d5e2f4a7b9")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Join the two Phase 3 migration branches (no schema changes)."""


def downgrade() -> None:
    """Re-split into the two pre-merge heads (no schema changes)."""
