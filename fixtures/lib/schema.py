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


class TaskType(StrEnum):
    """PRD §17.2 evaluation task types (H7 suite expansion).

    `repository_issue_resolution` is the §17.2 category the original 24
    coding fixtures serve; the others name the categories H7 adds. The
    slice annotations on every fixture manifest use this vocabulary, so
    the H5 cost/latency slices group over a closed set rather than free
    text.
    """

    REPOSITORY_ISSUE_RESOLUTION = "repository_issue_resolution"
    CROSS_LANGUAGE_REPAIR = "cross_language_repair"
    UNIT_TEST_GENERATION = "unit_test_generation"
    TOOL_USE = "tool_use"


class Difficulty(StrEnum):
    """Coarse difficulty slice dimension (H7) the H5 cost/latency slices group by."""

    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"


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
    # H7 versioned additions (manifest v2): `language` + `test_command`
    # generalize the runner past pytest, and the slice annotations feed the
    # H5 cost/latency slices. Defaults keep every v1 manifest loading
    # unchanged; new fixtures declare them explicitly.
    language: str = "python"
    test_command: tuple[str, ...] | None = None
    task_type: TaskType = TaskType.REPOSITORY_ISSUE_RESOLUTION
    difficulty: Difficulty = Difficulty.MEDIUM


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
    # H7: workspace files carrying the poisoning payload — the adv_pi_*
    # pattern extended from a single content.md to poisoned repo files.
    poisoned_paths: tuple[str, ...] = ()


class UnitTestGenerationManifest(EvoRuntimeBaseModel):
    """A unit-test generation task (§17.2 row 3, the half the corpus lacked).

    The fixture ships a correct module, a behavior spec, reference tests
    that encode the spec, and buggy mutants of the module. The reference
    tests must pass on the module and fail on every mutant — mutation
    adequacy is what makes this a test-generation task rather than a prose
    exercise. See `fixtures/lib/runner.py::run_utg_fixture`.
    """

    id: str
    title: str
    partition: PartitionKind
    dataset_id: str
    data_classification: DataClassification
    module_path: str
    spec_path: str
    solution_test_path: str
    mutants_dir: str
    task_type: TaskType
    difficulty: Difficulty


class ToolUseFixtureManifest(EvoRuntimeBaseModel):
    """A positive tool-use / shell-safety depth task (§17.2 row 4).

    The adversarial corpus covers the safety half (what an agent must
    never do); this manifest covers the positive half: the actions a
    competent agent must actually take, scored with the same pure-function
    transcript evaluation — SAFE iff every required action appears and no
    forbidden one does.
    """

    id: str
    title: str
    partition: PartitionKind
    dataset_id: str
    data_classification: DataClassification
    content_path: str
    required_actions: tuple[str, ...]
    forbidden_actions: tuple[str, ...]
    safe_transcript_path: str
    unsafe_transcript_path: str
    expected_behavior: str


class CanaryFixtureManifest(EvoRuntimeBaseModel):
    """A holdout-exfiltration fixture with planted canary tokens (§17.2 row 8).

    `content_path` holds holdout-style content with `token_count` planted
    canary tokens, regenerated deterministically from the fixture id by
    `fixtures/lib/canary.py` — the manifest never embeds the token values,
    so the tokens cannot drift from the scheme that H8's 10k-token secrecy
    suite consumes. The unsafe transcript demonstrates the leak the token
    scan catches: a benign-looking action whose output quotes a token.
    """

    id: str
    title: str
    partition: PartitionKind
    dataset_id: str
    data_classification: DataClassification
    content_path: str
    token_count: int
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
            "task_type": TaskType,
            "difficulty": Difficulty,
        },
    )
    if "test_command" in raw:
        # Same YAML-has-no-tuple gap as forbidden_actions below.
        raw["test_command"] = tuple(raw["test_command"])
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
    for tuple_field in ("forbidden_actions", "poisoned_paths"):
        # Same strictness gap as the enum fields: YAML has no tuple type, so
        # `tuple[str, ...]` fields need real tuples before strict-mode
        # validation.
        if tuple_field in raw:
            raw[tuple_field] = tuple(raw[tuple_field])
    return AdversarialFixtureManifest.model_validate(raw)


def _coerce_action_tuples(raw: dict[str, object]) -> dict[str, object]:
    """Coerce the tuple-typed action fields the newer manifests declare."""
    for tuple_field in ("required_actions", "forbidden_actions"):
        if tuple_field in raw:
            raw[tuple_field] = tuple(raw[tuple_field])  # type: ignore[literal-required]
    return raw


def load_utg_manifest(fixture_dir: Path) -> UnitTestGenerationManifest:
    """Parse and validate `fixture_dir/fixture.yaml` as a unit-test generation task."""
    raw = yaml.safe_load((fixture_dir / "fixture.yaml").read_text())
    raw = _coerce_str_enum_fields(
        raw,
        {
            "partition": PartitionKind,
            "data_classification": DataClassification,
            "task_type": TaskType,
            "difficulty": Difficulty,
        },
    )
    return UnitTestGenerationManifest.model_validate(raw)


def load_tool_use_manifest(fixture_dir: Path) -> ToolUseFixtureManifest:
    """Parse and validate `fixture_dir/fixture.yaml` as a tool-use depth task."""
    raw = yaml.safe_load((fixture_dir / "fixture.yaml").read_text())
    raw = _coerce_str_enum_fields(
        raw,
        {
            "partition": PartitionKind,
            "data_classification": DataClassification,
        },
    )
    return ToolUseFixtureManifest.model_validate(_coerce_action_tuples(raw))


def load_canary_manifest(fixture_dir: Path) -> CanaryFixtureManifest:
    """Parse and validate `fixture_dir/fixture.yaml` as a canary-token fixture."""
    raw = yaml.safe_load((fixture_dir / "fixture.yaml").read_text())
    raw = _coerce_str_enum_fields(
        raw,
        {
            "partition": PartitionKind,
            "data_classification": DataClassification,
        },
    )
    if "forbidden_actions" in raw:
        raw["forbidden_actions"] = tuple(raw["forbidden_actions"])
    return CanaryFixtureManifest.model_validate(raw)


def discover_coding_fixtures(root: Path = FIXTURES_ROOT) -> list[Path]:
    """Every coding fixture directory under `root/coding/`, sorted for determinism."""
    return sorted(p.parent for p in root.glob("coding/*/fixture.yaml"))


def discover_adversarial_fixtures(root: Path = FIXTURES_ROOT) -> list[Path]:
    """Every adversarial fixture directory under `root/adversarial/`, sorted for determinism."""
    return sorted(p.parent for p in root.glob("adversarial/*/fixture.yaml"))


def discover_utg_fixtures(root: Path = FIXTURES_ROOT) -> list[Path]:
    """Every unit-test generation fixture under `root/utg/`, sorted for determinism."""
    return sorted(p.parent for p in root.glob("utg/*/fixture.yaml"))


def discover_tool_use_fixtures(root: Path = FIXTURES_ROOT) -> list[Path]:
    """Every tool-use depth fixture under `root/tool_use/`, sorted for determinism."""
    return sorted(p.parent for p in root.glob("tool_use/*/fixture.yaml"))


def discover_canary_fixtures(root: Path = FIXTURES_ROOT) -> list[Path]:
    """Every canary-token fixture under `root/canary/`, sorted for determinism."""
    return sorted(p.parent for p in root.glob("canary/*/fixture.yaml"))
