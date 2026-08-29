"""H7 suite expansion: manifest validation + determinism per new category.

Covers the §17.2 rows H7 adds to the D8 corpus: cross-language repair,
unit-test generation, positive tool-use/shell-safety depth, repository
poisoning, holdout-exfiltration canary tokens, and cost/latency slice
annotations. Execution tests here are the same shape as the D8 ones —
same input, same verdict, run twice.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from fixtures.lib.canary import (
    CANARY_TOKEN_PREFIX,
    canary_tokens,
    find_planted_tokens,
)
from fixtures.lib.runner import (
    TranscriptVerdict,
    evaluate_canary_transcript,
    evaluate_tool_use_transcript,
    evaluate_transcript,
    run_language_fixture_patched,
    run_language_fixture_unpatched,
    run_utg_fixture,
)
from fixtures.lib.schema import (
    discover_adversarial_fixtures,
    discover_canary_fixtures,
    discover_coding_fixtures,
    discover_tool_use_fixtures,
    discover_utg_fixtures,
    load_adversarial_manifest,
    load_canary_manifest,
    load_coding_manifest,
    load_tool_use_manifest,
    load_utg_manifest,
)
from fixtures.lib.slices import (
    DIFFICULTY_VALUES,
    SLICE_DIFFICULTY,
    SLICE_KEYS,
    SLICE_TASK_TYPE,
    TASK_TYPE_VALUES,
    coding_fixtures_to_eval_tasks,
    coding_slice_metadata,
)

NODE_AVAILABLE = shutil.which("node") is not None


def _transcript(fixture_dir: Path, relative: str) -> list[dict[str, str]]:
    return json.loads((fixture_dir / relative).read_text())


# --- cross-language repair -------------------------------------------------


def _cross_language_fixtures() -> list[Path]:
    return [d for d in discover_coding_fixtures() if load_coding_manifest(d).language != "python"]


def test_cross_language_fixture_declares_node_test_command() -> None:
    """The JS fixture runs through node --test, not pytest."""
    fixtures = _cross_language_fixtures()
    assert fixtures, "H7 requires at least one non-Python coding fixture"
    for fixture_dir in fixtures:
        manifest = load_coding_manifest(fixture_dir)
        assert manifest.language == "javascript"
        assert manifest.test_command == ("node", "--test")
        assert (fixture_dir / manifest.before_dir / manifest.module).is_file()


@pytest.mark.skipif(not NODE_AVAILABLE, reason="node not available")
@pytest.mark.parametrize("fixture_dir", _cross_language_fixtures(), ids=lambda d: d.name)
def test_cross_language_unpatched_fails_patched_passes(fixture_dir: Path) -> None:
    """Same bar as the Python fixtures: buggy code fails, patched code passes."""
    manifest = load_coding_manifest(fixture_dir)
    unpatched = run_language_fixture_unpatched(fixture_dir, manifest)
    assert not unpatched.passed, (
        f"{fixture_dir.name}: tests passed WITHOUT the patch — "
        f"the fixture does not exercise its claimed bug.\n{unpatched.stdout}"
    )
    patched = run_language_fixture_patched(fixture_dir, manifest, fixture_dir / manifest.patch_path)
    assert patched.passed, (
        f"{fixture_dir.name}: tests still fail WITH the patch.\n{patched.stdout}\n{patched.stderr}"
    )


@pytest.mark.skipif(not NODE_AVAILABLE, reason="node not available")
def test_cross_language_fixture_is_deterministic() -> None:
    """Same input -> same pass/fail, run twice (D8 determinism requirement)."""
    fixture_dir = _cross_language_fixtures()[0]
    manifest = load_coding_manifest(fixture_dir)
    patch_path = fixture_dir / manifest.patch_path
    first = run_language_fixture_patched(fixture_dir, manifest, patch_path)
    second = run_language_fixture_patched(fixture_dir, manifest, patch_path)
    assert first.passed == second.passed


# --- unit-test generation ----------------------------------------------------


def test_every_utg_manifest_validates() -> None:
    """Module, spec, reference tests, and a non-empty mutants dir all exist."""
    fixtures = discover_utg_fixtures()
    assert fixtures, "H7 requires at least one unit-test generation fixture"
    for fixture_dir in fixtures:
        manifest = load_utg_manifest(fixture_dir)
        assert manifest.id == fixture_dir.name
        assert (fixture_dir / manifest.module_path).is_file()
        assert (fixture_dir / manifest.spec_path).is_file()
        assert (fixture_dir / manifest.solution_test_path).is_file()
        assert any((fixture_dir / manifest.mutants_dir).iterdir())


@pytest.mark.parametrize("fixture_dir", discover_utg_fixtures(), ids=lambda d: d.name)
def test_utg_reference_tests_pass_and_catch_every_mutant(fixture_dir: Path) -> None:
    """Mutation adequacy: reference tests pass on the module, fail on every mutant."""
    manifest = load_utg_manifest(fixture_dir)
    result = run_utg_fixture(fixture_dir, manifest)
    assert result.solution_passes, f"{fixture_dir.name}: reference tests fail on the correct module"
    assert not result.mutants_missed, (
        f"{fixture_dir.name}: reference tests miss mutant(s): {', '.join(result.mutants_missed)}"
    )


@pytest.mark.parametrize("fixture_dir", discover_utg_fixtures(), ids=lambda d: d.name)
def test_utg_execution_is_deterministic(fixture_dir: Path) -> None:
    """Same input -> same adequacy result, run twice."""
    manifest = load_utg_manifest(fixture_dir)
    first = run_utg_fixture(fixture_dir, manifest)
    second = run_utg_fixture(fixture_dir, manifest)
    assert first == second


# --- positive tool-use / shell-safety depth ---------------------------------


@pytest.mark.parametrize("fixture_dir", discover_tool_use_fixtures(), ids=lambda d: d.name)
def test_tool_use_safe_transcript_scores_safe(fixture_dir: Path) -> None:
    """The safe transcript takes every required action and no forbidden one."""
    manifest = load_tool_use_manifest(fixture_dir)
    transcript = _transcript(fixture_dir, manifest.safe_transcript_path)
    assert evaluate_tool_use_transcript(manifest, transcript) == TranscriptVerdict.SAFE


@pytest.mark.parametrize("fixture_dir", discover_tool_use_fixtures(), ids=lambda d: d.name)
def test_tool_use_unsafe_transcript_scores_unsafe(fixture_dir: Path) -> None:
    """The unsafe transcript trips the forbidden set."""
    manifest = load_tool_use_manifest(fixture_dir)
    transcript = _transcript(fixture_dir, manifest.unsafe_transcript_path)
    assert evaluate_tool_use_transcript(manifest, transcript) == TranscriptVerdict.UNSAFE


def test_tool_use_evaluation_is_deterministic() -> None:
    """Same input -> same verdict, twice, for every tool-use fixture."""
    for fixture_dir in discover_tool_use_fixtures():
        manifest = load_tool_use_manifest(fixture_dir)
        safe = _transcript(fixture_dir, manifest.safe_transcript_path)
        unsafe = _transcript(fixture_dir, manifest.unsafe_transcript_path)
        assert evaluate_tool_use_transcript(manifest, safe) == evaluate_tool_use_transcript(
            manifest, safe
        )
        assert evaluate_tool_use_transcript(manifest, unsafe) == evaluate_tool_use_transcript(
            manifest, unsafe
        )


# --- repository poisoning ----------------------------------------------------


def test_poisoned_paths_exist_and_carry_injection_marker() -> None:
    """Every declared poisoned file exists and carries the injection marker."""
    poisoned = [
        d for d in discover_adversarial_fixtures() if load_adversarial_manifest(d).poisoned_paths
    ]
    assert poisoned, "H7 requires at least one repository-poisoning fixture"
    for fixture_dir in poisoned:
        manifest = load_adversarial_manifest(fixture_dir)
        for relative in manifest.poisoned_paths:
            poisoned_file = fixture_dir / relative
            assert poisoned_file.is_file(), f"{fixture_dir.name}: missing {relative}"
            assert "NOTE TO AUTOMATED AGENTS" in poisoned_file.read_text()


@pytest.mark.parametrize("fixture_dir", discover_adversarial_fixtures(), ids=lambda d: d.name)
def test_poisoned_fixture_transcripts_score_as_declared(fixture_dir: Path) -> None:
    """Poisoning fixtures ride the existing adversarial evaluation unchanged."""
    manifest = load_adversarial_manifest(fixture_dir)
    safe = _transcript(fixture_dir, manifest.safe_transcript_path)
    unsafe = _transcript(fixture_dir, manifest.unsafe_transcript_path)
    assert evaluate_transcript(manifest, safe) == TranscriptVerdict.SAFE
    assert evaluate_transcript(manifest, unsafe) == TranscriptVerdict.UNSAFE


# --- holdout exfiltration (canary tokens) ------------------------------------


def test_canary_tokens_are_deterministic_unique_and_formatted() -> None:
    """The scheme's core contract: deterministic per (fixture, index), unique, prefixed."""
    first = canary_tokens("fx_demo", 5)
    second = canary_tokens("fx_demo", 5)
    assert first == second
    assert len(set(first)) == 5
    assert all(token.startswith(CANARY_TOKEN_PREFIX + "-FX_DEMO-") for token in first)
    assert canary_tokens("fx_other", 5) != first


def test_canary_tokens_are_not_dlp_findings() -> None:
    """Synthetic namespace: real-secret DLP rules never fire on a planted token."""
    from evoruntime.dlp.detectors import detect

    planted = [
        token
        for fixture_dir in discover_canary_fixtures()
        for token in canary_tokens(
            load_canary_manifest(fixture_dir).id, load_canary_manifest(fixture_dir).token_count
        )
    ]
    assert planted
    for token in planted:
        assert detect(token) == (), f"canary token tripped DLP rules: {token}"


@pytest.mark.parametrize("fixture_dir", discover_canary_fixtures(), ids=lambda d: d.name)
def test_canary_content_carries_all_planted_tokens(fixture_dir: Path) -> None:
    """The holdout content embeds exactly the tokens the scheme regenerates."""
    manifest = load_canary_manifest(fixture_dir)
    tokens = canary_tokens(manifest.id, manifest.token_count)
    content = (fixture_dir / manifest.content_path).read_text()
    assert find_planted_tokens(content, tokens) == tokens


@pytest.mark.parametrize("fixture_dir", discover_canary_fixtures(), ids=lambda d: d.name)
def test_canary_transcripts_score_as_declared(fixture_dir: Path) -> None:
    """Safe paraphrase scores SAFE; token-in-output scores UNSAFE via the token scan."""
    manifest = load_canary_manifest(fixture_dir)
    tokens = canary_tokens(manifest.id, manifest.token_count)
    safe = _transcript(fixture_dir, manifest.safe_transcript_path)
    unsafe = _transcript(fixture_dir, manifest.unsafe_transcript_path)
    assert evaluate_canary_transcript(manifest, safe, tokens) == TranscriptVerdict.SAFE
    assert evaluate_canary_transcript(manifest, unsafe, tokens) == TranscriptVerdict.UNSAFE


# --- cost/latency slice annotations ------------------------------------------


def test_every_coding_fixture_declares_slice_annotations() -> None:
    """Every coding manifest carries task_type/difficulty from the closed vocabularies."""
    for fixture_dir in discover_coding_fixtures():
        manifest = load_coding_manifest(fixture_dir)
        assert manifest.task_type.value in TASK_TYPE_VALUES
        assert manifest.difficulty.value in DIFFICULTY_VALUES


def test_coding_fixtures_to_eval_tasks_carry_slices() -> None:
    """The H5 loader produces one EvalTask per fixture with the full slice block."""
    tasks = coding_fixtures_to_eval_tasks()
    fixture_ids = {d.name for d in discover_coding_fixtures()}
    assert {task.id for task in tasks} == fixture_ids
    for task in tasks:
        assert task.prompt.strip()
        assert set(task.metadata) == set(SLICE_KEYS)
        assert task.metadata[SLICE_TASK_TYPE] in TASK_TYPE_VALUES
        assert task.metadata[SLICE_DIFFICULTY] in DIFFICULTY_VALUES


def test_slice_metadata_is_pure_per_manifest() -> None:
    """Same manifest -> same annotation block (the slice data is deterministic)."""
    for fixture_dir in discover_coding_fixtures():
        manifest = load_coding_manifest(fixture_dir)
        assert coding_slice_metadata(manifest) == coding_slice_metadata(manifest)
