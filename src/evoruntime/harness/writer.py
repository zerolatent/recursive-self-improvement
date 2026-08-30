"""Standalone ingest writer subprocess for the H8 fault-injection runner.

Launched as ``python -m evoruntime.harness.writer`` so the runner can
``SIGKILL`` it exactly like an operator killing a crashed ingest worker —
no Python-level cleanup runs; only what Postgres durably committed
survives. Reads a JSONL fixture of raw envelopes and ingests them one at a
time via the real ``ingest_envelope`` path (one commit per event). After
each event is durably committed — or found to be a harmless duplicate from
a prior, killed run — appends the 1-based processed count to
``--progress-path``, fsync'd immediately. The parent runner's kill and
loss-rate accounting reads only that file.

Deliberately depends on nothing outside ``evoruntime`` + stdlib so it runs
from any working directory.
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

    processed = 0
    with args.fixture_path.open("r", encoding="utf-8") as fixture_file:
        for line in fixture_file:
            if not line.strip():
                continue
            envelope = parse_wire_envelope(json.loads(line))
            # Already durably committed by a prior, killed run —
            # idempotent resume, not data loss. The duplicate must
            # propagate out of session_scope so the poisoned session
            # is rolled back before the next event opens a fresh one.
            try:
                with session_scope(session_factory) as session:
                    ingest_envelope(session, envelope)
            except DuplicateEventError:
                pass
            processed += 1
            _append_progress(args.progress_path, processed)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
