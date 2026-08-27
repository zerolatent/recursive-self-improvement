"""Domain ORM models, imported for their side effect of registering tables
on `evoruntime.db.base.Base.metadata`.

Alembic autogenerate (see `db/migrations/env.py`) and `Base.metadata.create_all`
both need every model class imported somewhere before they run. Import the
per-deliverable modules here rather than in `env.py` directly so the
registration list has one obvious home as more domain models (events,
dataset partitions, holdout handles) land in later deliverables.
"""

from __future__ import annotations

from evoruntime.db.models import lineage as lineage  # noqa: F401
