"""Execute every coding fixture: unpatched tests fail, patched tests pass.

Parametrized over `discover_coding_fixtures()` so every fixture directory
added under `fixtures/coding/` is picked up automatically -- no fixture id
needs to be hand-registered here.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fixtures.lib.runner import run_coding_fixture_patched, run_coding_fixture_unpatched
from fixtures.lib.schema import discover_coding_fixtures, load_coding_manifest

FIXTURE_DIRS = discover_coding_fixtures()
FIXTURE_IDS = [d.name for d in FIXTURE_DIRS]


@pytest.mark.parametrize("fixture_dir", FIXTURE_DIRS, ids=FIXTURE_IDS)
def test_unpatched_fixture_fails(fixture_dir: Path) -> None:
    """The bug described in issue.md must actually make the tests fail.

    A fixture whose unpatched tests pass is not testing anything -- this
    guards against that class of authoring mistake for every fixture.
    """
    result = run_coding_fixture_unpatched(fixture_dir)
    assert not result.passed, (
        f"{fixture_dir.name}: tests passed WITHOUT the patch applied -- "
        f"the fixture does not exercise its claimed bug.\n{result.stdout}"
    )


@pytest.mark.parametrize("fixture_dir", FIXTURE_DIRS, ids=FIXTURE_IDS)
def test_patched_fixture_passes(fixture_dir: Path) -> None:
    """Applying `fix.patch` over before/ must make the tests pass."""
    manifest = load_coding_manifest(fixture_dir)
    result = run_coding_fixture_patched(fixture_dir, fixture_dir / manifest.patch_path)
    assert result.passed, (
        f"{fixture_dir.name}: tests still fail WITH the patch applied.\n"
        f"{result.stdout}\n{result.stderr}"
    )


@pytest.mark.parametrize("fixture_dir", FIXTURE_DIRS, ids=FIXTURE_IDS)
def test_patched_fixture_is_deterministic(fixture_dir: Path) -> None:
    """Same input -> same pass/fail, run twice (D8 determinism requirement)."""
    manifest = load_coding_manifest(fixture_dir)
    patch_path = fixture_dir / manifest.patch_path
    first = run_coding_fixture_patched(fixture_dir, patch_path)
    second = run_coding_fixture_patched(fixture_dir, patch_path)
    assert first.passed, f"{fixture_dir.name}: first patched run failed"
    assert second.passed, f"{fixture_dir.name}: second patched run failed"
    assert first.passed == second.passed
