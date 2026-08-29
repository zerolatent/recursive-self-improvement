"""Domain ORM models, imported for their side effect of registering tables
on `evoruntime.db.base.Base.metadata`.

Alembic autogenerate (see `db/migrations/env.py`) and `Base.metadata.create_all`
both need every model class imported somewhere before they run. Import the
per-deliverable modules here rather than in `env.py` directly so the
registration list has one obvious home as more domain models (events,
dataset partitions, holdout handles) land in later deliverables.
dataset partitions, holdout handles) land in later deliverables.
"""

from __future__ import annotations

from evoruntime.datasets import models as dataset_models  # noqa: F401
from evoruntime.db.models import analysis as analysis  # noqa: F401
from evoruntime.db.models import events as events  # noqa: F401
from evoruntime.db.models import graduation as graduation  # noqa: F401
from evoruntime.db.models import lineage as lineage  # noqa: F401
from evoruntime.db.models import memory as memory  # noqa: F401
from evoruntime.db.models import pareto_archive as pareto_archive  # noqa: F401
from evoruntime.db.models import productivity as productivity  # noqa: F401
from evoruntime.db.models import registry as registry  # noqa: F401
from evoruntime.db.models import tenancy as tenancy  # noqa: F401
