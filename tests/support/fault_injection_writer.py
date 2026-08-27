"""Standalone ingest writer for `tests/test_fault_injection.py`.

Runs as a genuine OS subprocess (spawned with `subprocess.Popen`, never
imported) so the test can `SIGKILL` it exactly like an operator killing a
crashed ingest worker — no `finally`/`atexit` cleanup runs, only whatever
Postgres itself durably committed survives. Deliberately depends on nothing
from `tests/` (only `evoruntime` + stdlib) so it needs no `PYTHONPATH`
tricks when launched by file path from an arbitrary working directory.

Reads a JSONL fixture of raw envelopes and ingests them one at a time via
the real `ingest_envelope` path (one commit per event). After each event is
durably committed (or found to be a harmless duplicate from a prior,
crashed run), appends the 1-based count of events processed so far to
`--progress-path`, fsync'd immediately — this is the parent test's only
authoritative signal of how far the writer actually got before it died.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from evoruntime.core.events import parse_wire_envelope
from evoruntime.db.base import build_engine, build_session_factory, session_scope
from evoruntime.db.ingest import DuplicateEventError, ingest_envelope


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--fixture-path", required=True, type=Path)
    parser.add_argument("--progress-path", required=True, type=Path)
    return parser.parse_args(argv)


def _append_progress(progress_path: Path, processed_count: int) -> None:
    with progress_path.open("a", encoding="utf-8") as f:
        f.write(f"{processed_count}\n")
        f.flush()
        os.fsync(f.fileno())


def main(argv: list[str]) -> int:
    args = _parse_args(argv)
    session_factory = build_session_factory(build_engine(args.database_url))

    with args.fixture_path.open("r", encoding="utf-8") as fixture_file:
        raw_lines = fixture_file.readlines()

    for i, line in enumerate(raw_lines):
        envelope = parse_wire_envelope(json.loads(line))
        # `DuplicateEventError` must be caught *outside* `session_scope` so
        # its own except-clause runs `session.rollback()` first — the failed
        # flush leaves the session's transaction unusable, and suppressing
        # the error inside the block would make `session_scope` try to
        # `commit()` a poisoned transaction (raises `PendingRollbackError`).
        try:
            with session_scope(session_factory) as session:
                ingest_envelope(session, envelope)
        except DuplicateEventError:
            pass  # already committed by a prior (crashed) run — not loss
        _append_progress(args.progress_path, i + 1)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
