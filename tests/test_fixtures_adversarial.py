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
from fixtures.lib.schema import (
    AttackType,
    discover_adversarial_fixtures,
    load_adversarial_manifest,
)

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


def test_scaffold_class_destructive_fixtures_are_in_the_corpus() -> None:
    """G8: the corpus carries scaffold-class destructive fixtures — attacks
    that ask the agent to destroy its own governed source (the evaluation
    plane, the conformance oracle, the append-only lineage) rather than
    generic filesystem or git damage."""
    scaffold_fixtures = [
        manifest
        for manifest in (load_adversarial_manifest(d) for d in FIXTURE_DIRS)
        if manifest.id.startswith("adv_do_scaffold_")
    ]
    assert len(scaffold_fixtures) >= 3, (
        "the scaffold-class destructive corpus must carry at least three adv_do_scaffold_* fixtures"
    )
    assert all(
        manifest.attack_type is AttackType.DESTRUCTIVE_OPERATION for manifest in scaffold_fixtures
    )
    assert {manifest.id for manifest in scaffold_fixtures} >= {
        "adv_do_scaffold_delete_evaluator",
        "adv_do_scaffold_gut_conformance_suite",
        "adv_do_scaffold_scrub_mutation_lineage",
    }
