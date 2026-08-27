"""Fixture manifest models for the D8 seed evaluation suite.

Every fixture directory carries a `fixture.yaml` that validates against one
of the two manifests below. Both models reuse `EvoRuntimeBaseModel` (frozen,
`extra="forbid"`) so a malformed or drifted manifest fails validation loudly
instead of silently loading a fixture the harness never intended.

`partition` reuses D5's `PartitionKind` directly — the same enum the dataset
partition service enforces — so "loadable through the D5 partition model"
is a type-level guarantee, not a convention two modules could drift apart
on. See `fixtures/README.md` for the ambiguity this format resolves and why.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

import yaml

from evoruntime.core.schemas import EvoRuntimeBaseModel
from evoruntime.datasets.partitions import PartitionKind

FIXTURES_ROOT = Path(__file__).resolve().parent.parent


class DataClassification(StrEnum):
    """Values for the event envelope's `data_classification` field (spec §18.3).

    The spec's example envelope shows `"internal"` without enumerating the
    full value set. This suite narrows to the two values its fixtures need:
    ordinary coding fixtures are `internal` (same as the spec's example);
    adversarial fixtures are `restricted` since their content is
    attack material that should not be echoed into open telemetry or logs
    verbatim. Documented as a chosen interpretation, not a spec quote.
    """

    INTERNAL = "internal"
    RESTRICTED = "restricted"


class FailureCategory(StrEnum):
    """PRD §17.1 coding-fixture failure taxonomy (D8 acceptance row)."""

    LOCALIZATION = "localization"
    TEST_MISUNDERSTANDING = "test_misunderstanding"
    DEPENDENCY_MISUSE = "dependency_misuse"


class AttackType(StrEnum):
    """The three adversarial fixture families named in the D8 deliverable."""

    PROMPT_INJECTION = "prompt_injection"
    SECRET_EXFILTRATION = "secret_exfiltration"
    DESTRUCTIVE_OPERATION = "destructive_operation"


class CodingFixtureManifest(EvoRuntimeBaseModel):
    """A single issue -> patch -> executable-tests coding fixture.

    `before_dir` holds the buggy module *and* its pytest test file side by
    side (no separate `tests/` directory): pytest's default import mode
    inserts a test file's own directory onto `sys.path`, so keeping module
    and test together is what makes `from <module> import ...` resolve
    without a package layout or `PYTHONPATH` tricks in the runner.
    """

    id: str
    title: str
    failure_category: FailureCategory
    partition: PartitionKind
    dataset_id: str
    data_classification: DataClassification
    issue_path: str
    before_dir: str
    patch_path: str
    module: str


class AdversarialFixtureManifest(EvoRuntimeBaseModel):
    """A prompt-injection, exfiltration, or destructive-operation attack fixture.

    `forbidden_actions` and the two transcripts are the "defined safe/fail
    behavior the harness can assert" required by the D8 deliverable: a
    transcript is a static, deterministic list of actions a (real or
    scripted) agent took, and the verdict is a pure function of whether any
    forbidden action appears in it. See `fixtures/lib/runner.py`.
    """

    id: str
    title: str
    attack_type: AttackType
    partition: PartitionKind
    dataset_id: str
    data_classification: DataClassification
    content_path: str
    forbidden_actions: tuple[str, ...]
    safe_transcript_path: str
    unsafe_transcript_path: str
    expected_behavior: str


def _coerce_str_enum_fields(
    raw: dict[str, object], fields: dict[str, type[StrEnum]]
) -> dict[str, object]:
    """Convert plain YAML strings into their declared `StrEnum` types.

    `EvoRuntimeBaseModel` sets `strict=True` so a malformed field fails
    validation instead of silently coercing -- but that same strictness
    means `model_validate` (python-mode) rejects a bare `str` for an enum
    field, which is exactly what `yaml.safe_load` produces. Enum
    construction still raises `ValueError` on any value the enum doesn't
    define, so this is not a strictness bypass: it just moves the
    str -> enum step before validation instead of relying on pydantic's
    json-mode coercion, which would apply silently to every enum field
    including ones added later.
    """
    coerced = dict(raw)
    for field_name, enum_cls in fields.items():
        if field_name in coerced:
            coerced[field_name] = enum_cls(coerced[field_name])
    return coerced


def load_coding_manifest(fixture_dir: Path) -> CodingFixtureManifest:
    """Parse and validate `fixture_dir/fixture.yaml` as a coding fixture."""
    raw = yaml.safe_load((fixture_dir / "fixture.yaml").read_text())
    raw = _coerce_str_enum_fields(
        raw,
        {
            "failure_category": FailureCategory,
            "partition": PartitionKind,
            "data_classification": DataClassification,
        },
    )
    return CodingFixtureManifest.model_validate(raw)


def load_adversarial_manifest(fixture_dir: Path) -> AdversarialFixtureManifest:
    """Parse and validate `fixture_dir/fixture.yaml` as an adversarial fixture."""
    raw = yaml.safe_load((fixture_dir / "fixture.yaml").read_text())
    raw = _coerce_str_enum_fields(
        raw,
        {
            "attack_type": AttackType,
            "partition": PartitionKind,
            "data_classification": DataClassification,
        },
    )
    if "forbidden_actions" in raw:
        # Same strictness gap as the enum fields: YAML has no tuple type, so
        # `forbidden_actions: tuple[str, ...]` needs a real tuple before it
        # reaches strict-mode validation.
        raw["forbidden_actions"] = tuple(raw["forbidden_actions"])
    return AdversarialFixtureManifest.model_validate(raw)


def discover_coding_fixtures(root: Path = FIXTURES_ROOT) -> list[Path]:
    """Every coding fixture directory under `root/coding/`, sorted for determinism."""
    return sorted(p.parent for p in root.glob("coding/*/fixture.yaml"))


def discover_adversarial_fixtures(root: Path = FIXTURES_ROOT) -> list[Path]:
    """Every adversarial fixture directory under `root/adversarial/`, sorted for determinism."""
    return sorted(p.parent for p in root.glob("adversarial/*/fixture.yaml"))
