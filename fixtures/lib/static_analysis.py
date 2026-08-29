"""Static-analysis fixture corpus (Phase 2 F3) — models and loader.

Structured like the FR-018 admission corpus: each fixture directory under
``fixtures/static_analysis/<fixture_id>/`` carries a ``fixture.yaml``
validating against :class:`StaticAnalysisFixtureManifest`, and the test
suite runs every fixture through the same pure gate the runtime uses
(:func:`evoruntime.plugins.static_analysis.analyze_files`). Unlike the
admission corpus (metadata-only because the gate consumes metadata), these
fixtures carry real Python source — the gate is content-based, so the
corpus must ship the actual source an attack class looks like, in
miniature.

One fixture per violation class plus a clean control and a warning-class
control, so "blockers reject pre-execution" and "warnings never block"
are both corpus-covered, not anecdote-covered.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field

from evoruntime.core.schemas import EvoRuntimeBaseModel

FIXTURES_ROOT = Path(__file__).resolve().parent.parent
STATIC_ANALYSIS_ROOT = FIXTURES_ROOT / "static_analysis"


class StaticAnalysisCategory(StrEnum):
    """F3 violation taxonomy — one fixture per class, plus controls."""

    CLEAN = "clean"
    NETWORK_IMPORT = "network_import"
    SUBPROCESS_SPAWN = "subprocess_spawn"
    DYNAMIC_EXEC = "dynamic_exec"
    MASK_PATH_WRITE = "mask_path_write"
    OPAQUE_PATH_WRITE = "opaque_path_write"
    UNPARSEABLE_SOURCE = "unparseable_source"


class FileSpec(EvoRuntimeBaseModel):
    """One candidate file: its artifact path and its text content."""

    path: str
    content: str


class StaticAnalysisFixtureManifest(EvoRuntimeBaseModel):
    """One F3 static-analysis fixture.

    ``expected`` is the gate verdict the fixture must produce; for
    ``block`` fixtures ``expected_violation`` is the exact
    :class:`AnalysisViolationCode` the gate must emit, so a gate that
    rejects for the wrong reason fails the corpus too.
    """

    fixture_id: str
    category: StaticAnalysisCategory
    description: str
    expected: Literal["pass", "block"]
    expected_violation: str | None = None
    allowed_paths: tuple[str, ...] = Field(default=())
    files: tuple[FileSpec, ...] = Field(min_length=1)


def load_static_analysis_fixtures() -> list[StaticAnalysisFixtureManifest]:
    """Load and validate every fixture under ``fixtures/static_analysis/``."""
    fixtures: list[StaticAnalysisFixtureManifest] = []
    for fixture_dir in sorted(STATIC_ANALYSIS_ROOT.iterdir()):
        manifest_path = fixture_dir / "fixture.yaml"
        if not manifest_path.is_file():
            continue
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        # YAML yields strings and lists; validate lax so they coerce to the
        # strict StrEnum/tuple field types the frozen base model requires.
        fixtures.append(StaticAnalysisFixtureManifest.model_validate(raw, strict=False))
    return fixtures


def files_from_fixture(fixture: StaticAnalysisFixtureManifest) -> list[dict[str, Any]]:
    """Materialize a fixture's file specs into gate inputs (CandidateBundle.files shape)."""
    return [{"path": spec.path, "content": spec.content} for spec in fixture.files]


class _FixtureMask:
    """Minimal mask stand-in satisfying the gate's MaskLike protocol."""

    def __init__(self, allowed_paths: tuple[str, ...]) -> None:
        self._allowed_paths = allowed_paths

    @property
    def allowed_paths(self) -> tuple[str, ...]:
        return self._allowed_paths


def masks_from_fixture(fixture: StaticAnalysisFixtureManifest) -> tuple[_FixtureMask, ...]:
    """Build the mask tuple a fixture's ``allowed_paths`` declares."""
    return (_FixtureMask(fixture.allowed_paths),)
