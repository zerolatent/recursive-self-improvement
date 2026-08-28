"""Redaction pipeline and the RedactedEvidenceBundle gate (FR-015).

This module is the evidence-bundle boundary the Phase 1 spec names: raw
trace content goes in through `build_redacted_evidence_bundle`, and what
comes out is a frozen `RedactedEvidenceBundle` whose items have already
been through the detector pipeline. The campaign orchestrator (E3) and
the reference plugins (E7) consume the bundle type from here — the
module is standalone and pure (no DB, no network, no runtime imports)
so both can depend on it without pulling in anything else.

The structural invariant is "no plugin ever sees unredacted trace
content" (§17.3 DLP row):

1. `EvidenceItem.redacted_content` is only ever produced by `redact_text`
   — the bundle constructor is the single sanctioned path from raw
   content to a bundle.
2. `assert_fully_redacted` re-runs the detectors over bundle content and
   raises `UnredactedContentError` if anything still fires. E3 calls
   this immediately before handing a bundle to a plugin process, so the
   invariant is checked at the hand-off, not assumed at build time.

Redaction replaces each detected span with a stable marker
(`[REDACTED:secrets]`, ...). Markers are chosen so no detector matches
them, which is what makes redaction idempotent — a property the test
suite asserts, because a pipeline that is not idempotent cannot be
retried safely after a crash mid-bundle.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

from evoruntime.core.schemas import EvoRuntimeBaseModel
from evoruntime.dlp.corpus import DlpCategory
from evoruntime.dlp.detectors import DEFAULT_RULES, DetectionRule, Finding, detect
from evoruntime.dlp.errors import UnredactedContentError

BUNDLE_SCHEMA_VERSION = 1

REDACT_MARKER_TEMPLATE = "[REDACTED:{category}]"


def redaction_marker(category: DlpCategory) -> str:
    """The stable replacement marker for a category."""
    return REDACT_MARKER_TEMPLATE.format(category=category.value)


def redaction_profile_digest(rules: tuple[DetectionRule, ...] = DEFAULT_RULES) -> str:
    """Content-address the active rule set.

    The bundle records which redaction profile produced it, so an audit
    can answer "what was this bundle's content screened against?" from
    the bundle alone. Two rule sets with the same id/category/pattern
    triples are the same profile regardless of tuple order.
    """
    lines = sorted(f"{r.rule_id}|{r.category}|{r.pattern.pattern}" for r in rules)
    return "sha256:" + hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


def _merge_overlapping(findings: tuple[Finding, ...]) -> list[tuple[int, int, DlpCategory]]:
    """Merge overlapping/adjacent findings into disjoint redaction spans.

    A merged span keeps the category of its longest constituent, so a
    connection-string finding is not mislabeled by a smaller IP finding
    nested inside it. Sorting is by (start, end) so the merge is a single
    linear pass.
    """
    if not findings:
        return []
    ordered = sorted(findings, key=lambda f: (f.start, f.end))
    # (start, end, category, longest-constituent-length) per merged span.
    merged: list[tuple[int, int, DlpCategory, int]] = []
    for finding in ordered:
        if merged and finding.start <= merged[-1][1]:
            start, end, category, length = merged[-1]
            constituent_len = finding.end - finding.start
            merged[-1] = (
                start,
                max(end, finding.end),
                finding.category if constituent_len > length else category,
                max(length, constituent_len),
            )
        else:
            merged.append(
                (finding.start, finding.end, finding.category, finding.end - finding.start)
            )
    return [(start, end, category) for start, end, category, _ in merged]


class RedactionResult:
    """Outcome of redacting one piece of content."""

    __slots__ = ("redacted", "findings", "redaction_counts")

    def __init__(
        self,
        redacted: str,
        findings: tuple[Finding, ...],
        redaction_counts: dict[DlpCategory, int],
    ) -> None:
        self.redacted = redacted
        self.findings = findings
        self.redaction_counts = redaction_counts


def redact_text(content: str, rules: tuple[DetectionRule, ...] = DEFAULT_RULES) -> RedactionResult:
    """Detect sensitive spans in `content` and replace them with markers.

    Pure and idempotent: the markers are built so no detector matches
    them, so `redact_text(result.redacted)` returns the same string with
    zero findings.
    """
    findings = detect(content, rules)
    spans = _merge_overlapping(findings)

    parts: list[str] = []
    cursor = 0
    counts: dict[DlpCategory, int] = {}
    for start, end, category in spans:
        parts.append(content[cursor:start])
        parts.append(redaction_marker(category))
        counts[category] = counts.get(category, 0) + 1
        cursor = end
    parts.append(content[cursor:])

    return RedactionResult(redacted="".join(parts), findings=findings, redaction_counts=counts)


class RawEvidence(EvoRuntimeBaseModel):
    """Unredacted trace content, as it exists before the DLP gate.

    This model exists only on the *input* side of
    `build_redacted_evidence_bundle`; nothing downstream of the gate
    accepts it.
    """

    trace_id: str
    content: str


class EvidenceItem(EvoRuntimeBaseModel):
    """One redacted trace item, safe for plugin consumption."""

    trace_id: str
    redacted_content: str


class RedactedEvidenceBundle(EvoRuntimeBaseModel):
    """The evidence surface strategies (E2 `propose`) receive.

    Frozen, like every EvoRuntime contract model. `redaction_profile`
    records the rule-set digest that produced it, and
    `redaction_counts` summarizes how much was removed per category —
    the numbers a reviewer of a miss log starts from.
    """

    schema_version: int
    campaign_id: str
    redaction_profile: str
    items: tuple[EvidenceItem, ...]
    redaction_counts: dict[str, int]


def build_redacted_evidence_bundle(
    campaign_id: str,
    raw_items: Sequence[RawEvidence],
    rules: tuple[DetectionRule, ...] = DEFAULT_RULES,
) -> RedactedEvidenceBundle:
    """The single sanctioned path from raw trace content to a bundle.

    Every item is redacted here, at the boundary, before any plugin
    surface can observe it. There is no code path that wraps raw
    content in an `EvidenceItem` — that is the point of the type.
    """
    items: list[EvidenceItem] = []
    counts: dict[str, int] = {}
    for raw in raw_items:
        result = redact_text(raw.content, rules)
        items.append(EvidenceItem(trace_id=raw.trace_id, redacted_content=result.redacted))
        for category, count in result.redaction_counts.items():
            counts[category.value] = counts.get(category.value, 0) + count

    return RedactedEvidenceBundle(
        schema_version=BUNDLE_SCHEMA_VERSION,
        campaign_id=campaign_id,
        redaction_profile=redaction_profile_digest(rules),
        items=tuple(items),
        redaction_counts=counts,
    )


def assert_fully_redacted(content: str, rules: tuple[DetectionRule, ...] = DEFAULT_RULES) -> None:
    """Raise `UnredactedContentError` if any detector fires on `content`."""
    findings = detect(content, rules)
    if findings:
        detail = ", ".join(f"{f.rule_id}:{f.matched_text!r}" for f in findings[:5])
        raise UnredactedContentError(
            f"content claimed to be redacted still trips {len(findings)} detector(s): {detail}"
        )


def assert_bundle_fully_redacted(
    bundle: RedactedEvidenceBundle,
    rules: tuple[DetectionRule, ...] = DEFAULT_RULES,
) -> None:
    """Verify every item in `bundle` is detector-clean.

    E3 calls this immediately before passing a bundle to a strategy
    plugin — the last check on the path between the evidence store and
    untrusted code.
    """
    for item in bundle.items:
        assert_fully_redacted(item.redacted_content, rules)
