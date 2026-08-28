"""merge approval flows and proposal members heads

Revision ID: 03e74a197808
Revises: b3d8f2a7c541, d5e6f7a8b9c0
Create Date: 2026-08-28 23:37:26.965602

"""

from collections.abc import Sequence

# revision identifiers, used by Alembic.
# revision identifiers, used by Alembic.
revision: str = "03e74a197808"
down_revision: str | Sequence[str] | None = ("b3d8f2a7c541", "d5e6f7a8b9c0")
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
