"""Corpus evaluation harness: per-category recall and false-positive rate (FR-015).

Measures the detector pipeline against the labeled corpus and checks the
§17.3 DLP thresholds: >=99.5% recall on secrets, >=99.0% on PII, <=5%
false-positive rate. Definitions, stated once and used consistently:

* **Recall (per category)** — instance-level. For every positive example,
  the number of *distinct* detected spans of an expected category is
  capped at the expected count (`min`), summed across the corpus, and
  divided by the total expected instances. Instance-level counting is
  what stops one lucky match from crediting an example that contains
  three secrets.
* **False-positive rate** — the fraction of clean (negative) examples on
  which the pipeline produces any finding. A clean example is content a
  reviewer has labeled as safe to ship to a plugin; redacting any of it
  is a false positive. Findings of a *non-expected* category inside a
  positive example are counted separately as cross-category findings and
  reported, not folded into the FP rate — they are over-labeling, not
  redaction of safe content.
* **Misses** — every expected instance the pipeline failed to find is a
  `Miss` record; every finding on a clean example is a
  `FalsePositiveHit`. Both are logged (JSONL, one record per line) so
  the §17.3 requirement "all misses reviewed before production" has an
  artifact to review rather than a promise.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from evoruntime.dlp.corpus import DlpCategory, LabeledCorpus
from evoruntime.dlp.detectors import DEFAULT_RULES, DetectionRule, Finding, detect


@dataclass(frozen=True)
class Thresholds:
    """The numeric gates a corpus evaluation must clear (§17.3 DLP row).

    Injection recall is measured and reported but not gated — the spec
    sets numeric gates for secrets, PII, and false positives only.
    """

    min_secret_recall: float = 0.995
    min_pii_recall: float = 0.99
    max_false_positive_rate: float = 0.05

    def min_recall_for(self, category: DlpCategory) -> float | None:
        return {
            DlpCategory.SECRETS: self.min_secret_recall,
            DlpCategory.PII: self.min_pii_recall,
        }.get(category)


@dataclass(frozen=True)
class CategoryMetrics:
    """Recall for one category, instance-level."""

    category: DlpCategory
    expected_instances: int
    detected_instances: int

    @property
    def recall(self) -> float:
        if self.expected_instances == 0:
            return 1.0
        return self.detected_instances / self.expected_instances


@dataclass(frozen=True)
class Miss:
    """An expected instance the pipeline did not find."""

    example_id: str
    category: DlpCategory
    expected: int
    detected: int
    content_digest: str


@dataclass(frozen=True)
class FalsePositiveHit:
    """A finding on a clean example — content redacted that should not be."""

    example_id: str
    category: DlpCategory
    rule_id: str
    matched_text: str
    content_digest: str


@dataclass(frozen=True)
class CorpusEvaluation:
    """The full measurement of a detector pipeline against a corpus."""

    corpus_id: str
    corpus_version: int
    per_category: dict[DlpCategory, CategoryMetrics]
    clean_examples: int
    flagged_clean_examples: int
    false_positive_rate: float
    cross_category_findings: int
    misses: tuple[Miss, ...]
    false_positives: tuple[FalsePositiveHit, ...]

    def passes(self, thresholds: Thresholds | None = None) -> bool:
        """True when every §17.3 gate clears and no miss or FP exists.

        The thresholds have slack (e.g. one missed secret in two hundred
        still clears 99.5%), but "all misses reviewed before production"
        means a passing score with outstanding misses is not a pass —
        the gate requires zero unexplained misses and zero false
        positives on the current corpus.
        """
        thresholds = thresholds or Thresholds()
        if self.misses or self.false_positives:
            return False
        if self.false_positive_rate > thresholds.max_false_positive_rate:
            return False
        for category, metrics in self.per_category.items():
            minimum = thresholds.min_recall_for(category)
            if minimum is not None and metrics.recall < minimum:
                return False
        return True


def _distinct_span_count(findings: tuple[Finding, ...], category: DlpCategory) -> int:
    """Count detected spans of one category, merging only same-rule overlaps.

    Overlaps between *different* rules are kept separate: two rules
    catching two overlapping-but-distinct expected instances (e.g. a
    role-hijack phrase and an obey-command phrase in one sentence) are
    two detections, while a JWT nested inside a Bearer header inflates
    the count only up to the expected cap (`min` in the caller), so
    double-matching never credits more instances than exist.
    """
    by_rule: dict[str, list[tuple[int, int]]] = {}
    for finding in findings:
        if finding.category != category:
            continue
        spans = by_rule.setdefault(finding.rule_id, [])
        if spans and finding.start <= spans[-1][1]:
            spans[-1] = (spans[-1][0], max(spans[-1][1], finding.end))
        else:
            spans.append((finding.start, finding.end))
    return sum(len(spans) for spans in by_rule.values())


def evaluate_corpus(
    corpus: LabeledCorpus,
    rules: tuple[DetectionRule, ...] = DEFAULT_RULES,
) -> CorpusEvaluation:
    """Run the pipeline over every corpus example and score the results."""
    expected_totals: dict[DlpCategory, int] = {}
    detected_totals: dict[DlpCategory, int] = {}
    misses: list[Miss] = []
    false_positives: list[FalsePositiveHit] = []
    cross_category = 0

    for example in corpus.examples:
        findings = detect(example.content, rules)
        if example.label == "negative":
            for finding in findings:
                false_positives.append(
                    FalsePositiveHit(
                        example_id=example.id,
                        category=finding.category,
                        rule_id=finding.rule_id,
                        matched_text=finding.matched_text,
                        content_digest=example.content_digest,
                    )
                )
            continue

        for category, expected in example.expected.items():
            detected = _distinct_span_count(findings, category)
            expected_totals[category] = expected_totals.get(category, 0) + expected
            detected_totals[category] = detected_totals.get(category, 0) + min(detected, expected)
            if detected < expected:
                misses.append(
                    Miss(
                        example_id=example.id,
                        category=category,
                        expected=expected,
                        detected=detected,
                        content_digest=example.content_digest,
                    )
                )
        expected_categories = set(example.expected)
        cross_category += sum(1 for f in findings if f.category not in expected_categories)

    per_category = {
        category: CategoryMetrics(
            category=category,
            expected_instances=expected_totals.get(category, 0),
            detected_instances=detected_totals.get(category, 0),
        )
        for category in sorted(expected_totals, key=lambda c: c.value)
    }

    clean = len(corpus.negatives)
    flagged = len({fp.example_id for fp in false_positives})
    return CorpusEvaluation(
        corpus_id=corpus.corpus_id,
        corpus_version=corpus.version,
        per_category=per_category,
        clean_examples=clean,
        flagged_clean_examples=flagged,
        false_positive_rate=flagged / clean if clean else 0.0,
        cross_category_findings=cross_category,
        misses=tuple(misses),
        false_positives=tuple(false_positives),
    )


def miss_log_records(evaluation: CorpusEvaluation) -> list[dict[str, Any]]:
    """One JSON-serializable record per miss and per false positive.

    These are the review artifacts §17.3 requires: a production gate that
    logged nothing would be unverifiable by construction.
    """
    records: list[dict[str, Any]] = []
    for miss in evaluation.misses:
        records.append(
            {
                "kind": "miss",
                "corpus_id": evaluation.corpus_id,
                "corpus_version": evaluation.corpus_version,
                "example_id": miss.example_id,
                "category": miss.category.value,
                "expected": miss.expected,
                "detected": miss.detected,
                "content_digest": miss.content_digest,
            }
        )
    for fp in evaluation.false_positives:
        records.append(
            {
                "kind": "false_positive",
                "corpus_id": evaluation.corpus_id,
                "corpus_version": evaluation.corpus_version,
                "example_id": fp.example_id,
                "category": fp.category.value,
                "rule_id": fp.rule_id,
                "matched_text": fp.matched_text,
                "content_digest": fp.content_digest,
            }
        )
    return records


def write_miss_log(path: Path, evaluation: CorpusEvaluation) -> int:
    """Write the miss log as JSONL; returns the number of records written."""
    records = miss_log_records(evaluation)
    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, sort_keys=True) + "\n")
    return len(records)
