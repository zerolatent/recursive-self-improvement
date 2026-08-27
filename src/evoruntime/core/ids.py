"""Prefixed identifier generation.

Every EvoRuntime record carries a type-prefixed opaque id (`dsp_...`,
`hho_...`) so an id leaked into a log or a ledger row is self-describing
and cannot be confused with an id of another type.
"""

from __future__ import annotations

import uuid


def new_id(prefix: str) -> str:
    """Return a new opaque, type-prefixed identifier (e.g. `dsp_1f2c...`)."""
    return f"{prefix}_{uuid.uuid4().hex}"
