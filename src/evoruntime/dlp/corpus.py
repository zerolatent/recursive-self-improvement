"""Versioned, labeled, content-addressed DLP corpus (FR-015).

The corpus drives the redaction pipeline's evaluation (§17.3 DLP row):
credentials/secrets, PII, and prompt-injection positives plus clean
negatives, all synthetic. It is content-addressed the same way the D8
fixtures and the lineage payload store are: every example carries a
`sha256:` digest over its content, verified at load time, and the corpus
carries an aggregate digest over the sorted per-example digests — so any
hand-edit to a labeled example fails the load instead of silently
shifting the recall numbers a threshold gate depends on.

The loader is pure: it takes a path, validates, and returns a frozen
model. It never runs detectors — labeling is decided by the corpus
author, and the evaluation harness (`evoruntime.dlp.metrics`) measures
detectors against those labels. Letting the loader consult the detectors
would make the corpus unable to prove anything about them.
"""

from __future__ import annotations

import base64
import hashlib
from enum import StrEnum
from pathlib import Path
from typing import Literal

import yaml

from evoruntime.core.schemas import EvoRuntimeBaseModel
from evoruntime.dlp.errors import CorpusIntegrityError

# Same digest shape the trace envelope and payload store use.
SHA256_DIGEST_PREFIX = "sha256:"


class DlpCategory(StrEnum):
    """The three sensitive-content categories FR-015 names, plus `clean`.

    `CLEAN` is the negative class: examples that must produce zero
    findings. It is a corpus label, not something a detector emits.
    """

    SECRETS = "secrets"
    PII = "pii"
    PROMPT_INJECTION = "prompt_injection"
    CLEAN = "clean"


class CorpusExample(EvoRuntimeBaseModel):
    """One labeled corpus entry.

    `expected` maps category -> how many distinct instances of that
    category the content contains. Positive examples must declare at
    least one; clean (negative) examples must declare none. Instance
    counts (not just "contains some") are what make recall an
    instance-level measurement instead of an example-level one that a
    single lucky match could satisfy.
    """

    id: str
    label: Literal["positive", "negative"]
    content: str
    content_digest: str
    expected: dict[DlpCategory, int]


class LabeledCorpus(EvoRuntimeBaseModel):
    """A versioned, synthetic-only DLP corpus."""

    corpus_id: str
    version: int
    description: str
    synthetic_only: bool
    corpus_digest: str
    examples: tuple[CorpusExample, ...]

    @property
    def positives(self) -> tuple[CorpusExample, ...]:
        return tuple(e for e in self.examples if e.label == "positive")

    @property
    def negatives(self) -> tuple[CorpusExample, ...]:
        return tuple(e for e in self.examples if e.label == "negative")


def content_digest(content: str) -> str:
    """Digest a corpus example's content the same way payloads are addressed."""
    return SHA256_DIGEST_PREFIX + hashlib.sha256(content.encode("utf-8")).hexdigest()


def corpus_digest_for(examples: tuple[CorpusExample, ...]) -> str:
    """Aggregate digest over the sorted per-example `(id, digest)` lines.

    Sorted so the digest is independent of file order; any edit to any
    example's content (or its id) changes the aggregate.
    """
    lines = sorted(f"{e.id} {e.content_digest}" for e in examples)
    return SHA256_DIGEST_PREFIX + hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def _coerce_expected(raw: dict[str, object]) -> dict[DlpCategory, int]:
    """Convert YAML's plain-string keys into `DlpCategory` members.

    `EvoRuntimeBaseModel` is strict, so `model_validate` would reject the
    bare strings `yaml.safe_load` produces for enum-keyed maps. Enum
    construction still raises on any value the enum does not define, so
    this moves the str -> enum step before validation rather than
    loosening it (same pattern as `fixtures/lib/schema.py`).
    """
    coerced: dict[DlpCategory, int] = {}
    for key, count in raw.items():
        if not isinstance(count, int) or isinstance(count, bool):
            raise CorpusIntegrityError(
                f"expected count for '{key}' must be an integer, got {count!r}"
            )
        coerced[DlpCategory(key)] = count
    return coerced


def _decode_content(path: Path, example_id: str, raw_example: dict[str, object]) -> str:
    """Resolve an example's content from `content` or `content_b64`.

    `content_b64` exists so examples can carry token-shaped strings
    (Stripe-style live keys, Slack tokens) without the raw corpus file
    tripping GitHub push protection: the file stores base64, the loader
    decodes it, and the content digest — computed over the decoded
    string — is unchanged, so integrity guarantees are identical.
    """
    has_content = "content" in raw_example
    has_b64 = "content_b64" in raw_example
    if has_content == has_b64:
        raise CorpusIntegrityError(
            f"{path}:{example_id}: exactly one of 'content' or 'content_b64' is required"
        )
    if has_content:
        content = raw_example["content"]
        if not isinstance(content, str):
            raise CorpusIntegrityError(f"{path}:{example_id}: 'content' must be a string")
        return content
    encoded = raw_example["content_b64"]
    if not isinstance(encoded, str):
        raise CorpusIntegrityError(f"{path}:{example_id}: 'content_b64' must be a string")
    try:
        return base64.b64decode(encoded, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise CorpusIntegrityError(f"{path}:{example_id}: invalid 'content_b64' payload") from exc


def load_corpus(path: Path) -> LabeledCorpus:
    """Load and integrity-check a corpus YAML file.

    Raises `CorpusIntegrityError` on: a digest mismatch (the content was
    edited without re-addressing it), a duplicate example id, a positive
    example with no expected instances, a negative example that declares
    any, a corpus that does not declare itself synthetic-only, or an
    aggregate digest that does not match the examples.
    """
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise CorpusIntegrityError(f"{path}: corpus document must be a mapping")

    required_keys = (
        "corpus_id",
        "version",
        "description",
        "synthetic_only",
        "corpus_digest",
        "examples",
    )
    for key in required_keys:
        if key not in raw:
            raise CorpusIntegrityError(f"{path}: corpus document is missing required key '{key}'")
    if raw["synthetic_only"] is not True:
        raise CorpusIntegrityError(f"{path}: corpus must declare synthetic_only: true")

    examples: list[CorpusExample] = []
    seen: set[str] = set()
    for i, raw_example in enumerate(raw["examples"]):
        example_id = raw_example.get("id", f"<index {i}>")
        expected = _coerce_expected(raw_example.get("expected", {}))
        label = raw_example.get("label")
        if label == "positive" and not expected:
            raise CorpusIntegrityError(
                f"{path}:{example_id}: positive example declares no expected instances"
            )
        if label == "negative" and expected:
            raise CorpusIntegrityError(
                f"{path}:{example_id}: negative example declares expected instances"
            )

        content = _decode_content(path, example_id, raw_example)
        declared = raw_example.get("content_digest")
        computed = content_digest(content)
        if declared != computed:
            raise CorpusIntegrityError(
                f"{path}:{example_id}: content digest mismatch "
                f"(declared {declared}, computed {computed}) — "
                "content was edited without re-addressing it"
            )
        if example_id in seen:
            raise CorpusIntegrityError(f"{path}: duplicate example id '{example_id}'")
        seen.add(example_id)

        examples.append(
            CorpusExample(
                id=example_id,
                label=label,
                content=content,
                content_digest=declared,
                expected=expected,
            )
        )

    corpus = LabeledCorpus(
        corpus_id=raw["corpus_id"],
        version=int(raw["version"]),
        description=raw["description"],
        synthetic_only=True,
        corpus_digest=raw["corpus_digest"],
        examples=tuple(examples),
    )
    computed_aggregate = corpus_digest_for(corpus.examples)
    if corpus.corpus_digest != computed_aggregate:
        raise CorpusIntegrityError(
            f"{path}: corpus digest mismatch (declared {corpus.corpus_digest}, "
            f"computed {computed_aggregate}) — the example set changed without re-addressing it"
        )
    return corpus
