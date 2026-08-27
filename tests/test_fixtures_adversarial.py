"""Execute every adversarial fixture: safe transcript scores safe, unsafe scores unsafe.

`evaluate_transcript` is a pure function over static JSON transcripts (no
live model call), so "determinism" here means literally the same thing as
the coding-fixture determinism test: same input, same verdict, twice.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fixtures.lib.runner import TranscriptVerdict, evaluate_transcript
from fixtures.lib.schema import discover_adversarial_fixtures, load_adversarial_manifest

FIXTURE_DIRS = discover_adversarial_fixtures()
FIXTURE_IDS = [d.name for d in FIXTURE_DIRS]


def _load_transcript(path: Path) -> list[dict[str, str]]:
    return json.loads(path.read_text())


@pytest.mark.parametrize("fixture_dir", FIXTURE_DIRS, ids=FIXTURE_IDS)
def test_safe_transcript_scores_safe(fixture_dir: Path) -> None:
    """The safe transcript (agent declines/deflects) must never trip a forbidden action."""
    manifest = load_adversarial_manifest(fixture_dir)
    transcript = _load_transcript(fixture_dir / manifest.safe_transcript_path)
    verdict = evaluate_transcript(manifest, transcript)
    assert verdict == TranscriptVerdict.SAFE, (
        f"{fixture_dir.name}: safe transcript was scored UNSAFE -- "
        f"either the transcript or forbidden_actions is misconfigured"
    )


@pytest.mark.parametrize("fixture_dir", FIXTURE_DIRS, ids=FIXTURE_IDS)
def test_unsafe_transcript_scores_unsafe(fixture_dir: Path) -> None:
    """The unsafe transcript (agent complies with the attack) must be caught."""
    manifest = load_adversarial_manifest(fixture_dir)
    transcript = _load_transcript(fixture_dir / manifest.unsafe_transcript_path)
    verdict = evaluate_transcript(manifest, transcript)
    assert verdict == TranscriptVerdict.UNSAFE, (
        f"{fixture_dir.name}: unsafe transcript was scored SAFE -- "
        f"forbidden_actions does not cover this fixture's attack"
    )


@pytest.mark.parametrize("fixture_dir", FIXTURE_DIRS, ids=FIXTURE_IDS)
def test_transcript_scoring_is_deterministic(fixture_dir: Path) -> None:
    """Same transcript -> same verdict, run twice (D8 determinism requirement)."""
    manifest = load_adversarial_manifest(fixture_dir)
    unsafe_transcript = _load_transcript(fixture_dir / manifest.unsafe_transcript_path)
    first = evaluate_transcript(manifest, unsafe_transcript)
    second = evaluate_transcript(manifest, unsafe_transcript)
    assert first == second == TranscriptVerdict.UNSAFE
