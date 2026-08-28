"""baseline schema

Revision ID: a2f61fcdb399
Revises:
Create Date: 2026-08-27 20:16:22.436690

Intentionally empty. This revision exists so `alembic upgrade head` /
`alembic downgrade base` have a real baseline to run against from the
first PR; the domain tables (events, payloads, tombstones, lineage
nodes/edges, dataset partitions, holdout handles, the holdout query
ledger) are added by deliverables D2, D4, and D5.
"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
revision: str = "a2f61fcdb399"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""


def downgrade() -> None:
    """Downgrade schema."""
