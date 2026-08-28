"""Admission fixture corpus (FR-018) — manifest models and loader.

Structured like the D8 adversarial suite: each fixture directory under
``fixtures/admission/<fixture_id>/`` carries a ``fixture.yaml`` validating
against :class:`AdmissionFixtureManifest`, and the loader turns each
fixture into :class:`~evoruntime.plugins.admission.OutputEntry` metadata so
the test suite runs every attack through the same pure gate the runtime
uses. Entries are metadata-only by design — the gate is pure, so a fixture
describes the malicious output (a 4 GB uncompressed zip, a device node) as
declared statistics rather than shipping real bomb bytes into the repo.

Unlike the D8 lib (which could not import ``src/evoruntime`` because D6 was
being built concurrently), this corpus imports the admission gate directly:
E2's gate and its corpus land in the same PR, so "the fixtures test the
real gate" is a guarantee, not a reconciliation promise.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Literal

import yaml
from pydantic import Field

from evoruntime.core.schemas import EvoRuntimeBaseModel
from evoruntime.plugins.admission import ArchiveInfo, OutputEntry, OutputKind

FIXTURES_ROOT = Path(__file__).resolve().parent.parent
ADMISSION_ROOT = FIXTURES_ROOT / "admission"


class AdmissionAttackType(StrEnum):
    """FR-018 attack taxonomy — one fixture per rejection class, plus a control."""

    CLEAN = "clean_output"
    PATH_TRAVERSAL = "path_traversal"
    ABSOLUTE_PATH = "absolute_path"
    SYMLINK = "symlink"
    DEVICE_NODE = "device_node"
    ARCHIVE_BOMB = "archive_bomb"
    OVERSIZED_FILE = "oversized_file"
    SPARSE_FILE = "sparse_file"
    UNDECLARED_EXECUTABLE = "undeclared_executable"
    CONFUSABLE_PATH = "confusable_path"


class EntrySpec(EvoRuntimeBaseModel):
    """One output entry as declared in a fixture.yaml."""

    path: str
    kind: OutputKind = OutputKind.FILE
    size_bytes: int = Field(default=0, ge=0)
    executable: bool = False
    sparse: bool = False
    target: str | None = None
    archive: ArchiveInfo | None = None


class AdmissionFixtureManifest(EvoRuntimeBaseModel):
    """One FR-018 admission fixture.

    ``expected_violation`` is the exact :class:`ViolationCode` the gate must
    emit for rejection fixtures (``None`` for the clean control); the test
    suite asserts both the verdict and the code, so a gate that rejects for
    the wrong reason fails the corpus.
    """

    fixture_id: str
    category: AdmissionAttackType
    description: str
    expected: Literal["admit", "reject"]
    expected_violation: str | None = None
    declared_executables: tuple[str, ...] = ()
    entries: tuple[EntrySpec, ...] = Field(min_length=1)


def load_admission_fixtures() -> list[AdmissionFixtureManifest]:
    """Load and validate every fixture under ``fixtures/admission/``."""
    fixtures: list[AdmissionFixtureManifest] = []
    for fixture_dir in sorted(ADMISSION_ROOT.iterdir()):
        manifest_path = fixture_dir / "fixture.yaml"
        if not manifest_path.is_file():
            continue
        raw = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        # YAML yields strings and lists; validate lax so they coerce to the
        # strict StrEnum/tuple field types the frozen base model requires.
        fixtures.append(AdmissionFixtureManifest.model_validate(raw, strict=False))
    return fixtures


def entries_from_fixture(fixture: AdmissionFixtureManifest) -> list[OutputEntry]:
    """Materialize a fixture's entry specs into gate inputs."""
    return [
        OutputEntry(
            path=spec.path,
            kind=spec.kind,
            size_bytes=spec.size_bytes,
            executable=spec.executable,
            sparse=spec.sparse,
            target=spec.target,
            archive=spec.archive,
        )
        for spec in fixture.entries
    ]
