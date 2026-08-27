"""Fixture-side contract for the D8 seed evaluation suite.

This package is the fixture half of the harness/task-fixture contract
described in the Phase 0 spec's Interfaces section. D6 (the evaluation
harness) is being built concurrently against the same normative section
and may not be merged yet, so nothing in `fixtures/` imports from or
modifies `evoruntime.eval` — see `fixtures/README.md` for the full
reconciliation plan.
"""

from __future__ import annotations
