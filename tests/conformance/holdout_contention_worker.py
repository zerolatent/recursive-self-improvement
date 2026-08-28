"""Standalone holdout-resolution worker for `tests/conformance/test_holdout_concurrency.py`.

Runs as a genuine OS subprocess (spawned with `subprocess.Popen`, never
imported) so each worker owns its own database connections, session cache,
and process boundary — the point of the conformance test is that alpha
accounting holds across *processes*, not merely across threads sharing one
session. Deliberately depends on nothing from `tests/` (only `evoruntime` +
stdlib) so it needs no `PYTHONPATH` tricks when launched by file path.

Per attempt, resolves the handle via the real `HoldoutService.resolve` path
and records one JSON line to `--output-path`:

    {"attempt": 1, "outcome": "granted", "alpha_spent": "0.01"}
    {"attempt": 2, "outcome": "denied", "denial_reason": "alpha_budget_exhausted"}

Denials are expected, caught outcomes — not failures. Any other exception
propagates and fails the worker with a nonzero exit so the parent surfaces
its stderr instead of silently absorbing it as a missing attempt.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evoruntime.core.principal import Principal
from evoruntime.datasets.errors import HoldoutAccessDeniedError
from evoruntime.datasets.service import HoldoutService
from evoruntime.db.base import build_engine, build_session_factory
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--handle-uri", required=True)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--subject", required=True)
    parser.add_argument("--attempts", required=True, type=int)
    parser.add_argument("--output-path", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    principal = Principal(
        identity=WorkloadIdentity(role=WorkloadRole.EVALUATOR, subject=args.subject),
        tenant_id=args.tenant_id,
    )
    service = HoldoutService(build_session_factory(build_engine(args.database_url)))

    with args.output_path.open("w", encoding="utf-8") as output_file:
        for attempt in range(1, args.attempts + 1):
            try:
                content = service.resolve(
                    principal, args.handle_uri, purpose=f"conformance-{args.subject}-{attempt}"
                )
                record = {
                    "attempt": attempt,
                    "outcome": "granted",
                    "alpha_spent": str(content.alpha_budget.per_query),
                }
            except HoldoutAccessDeniedError as denied:
                record = {
                    "attempt": attempt,
                    "outcome": "denied",
                    "denial_reason": denied.reason.value,
                }
            output_file.write(json.dumps(record) + "\n")
        output_file.flush()

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
