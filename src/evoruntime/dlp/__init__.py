"""DLP redaction — the gate between raw trace content and any plugin (FR-015).

Public surface:

* `load_corpus` / `LabeledCorpus` / `DlpCategory` — the versioned,
  content-addressed evaluation corpus (data lives in `fixtures/dlp/`).
* `detect` / `Finding` / `DetectionRule` — the pure detector rule sets.
* `redact_text` / `RedactionResult` — the redaction pipeline.
* `RedactedEvidenceBundle` / `build_redacted_evidence_bundle` /
  `assert_bundle_fully_redacted` — the evidence-bundle boundary. The
  campaign orchestrator (E3) builds bundles here and re-verifies them
  here before any plugin observes their content; the reference plugins
  (E7) only ever see the bundle type.
* `evaluate_corpus` / `Thresholds` / `write_miss_log` — the §17.3
  threshold harness (>=99.5% secret recall, >=99.0% PII recall, <=5%
  false-positive rate, all misses logged for review).

The package is standalone and pure: no database, no network, no runtime
process imports. Anything that needs to redact can depend on it.
"""

from evoruntime.dlp.corpus import (
    CorpusExample,
    DlpCategory,
    LabeledCorpus,
    content_digest,
    corpus_digest_for,
    load_corpus,
)
from evoruntime.dlp.detectors import (
    DEFAULT_RULES,
    DetectionRule,
    Finding,
    detect,
)
from evoruntime.dlp.errors import CorpusIntegrityError, DlpError, UnredactedContentError
from evoruntime.dlp.metrics import (
    CategoryMetrics,
    CorpusEvaluation,
    FalsePositiveHit,
    Miss,
    Thresholds,
    evaluate_corpus,
    miss_log_records,
    write_miss_log,
)
from evoruntime.dlp.redaction import (
    BUNDLE_SCHEMA_VERSION,
    EvidenceItem,
    RawEvidence,
    RedactedEvidenceBundle,
    RedactionResult,
    assert_bundle_fully_redacted,
    assert_fully_redacted,
    build_redacted_evidence_bundle,
    redact_text,
    redaction_marker,
    redaction_profile_digest,
)

__all__ = [
    "BUNDLE_SCHEMA_VERSION",
    "DEFAULT_RULES",
    "CorpusExample",
    "CorpusIntegrityError",
    "CategoryMetrics",
    "CorpusEvaluation",
    "DlpCategory",
    "DlpError",
    "DetectionRule",
    "EvidenceItem",
    "FalsePositiveHit",
    "Finding",
    "LabeledCorpus",
    "Miss",
    "RawEvidence",
    "RedactedEvidenceBundle",
    "RedactionResult",
    "Thresholds",
    "UnredactedContentError",
    "assert_bundle_fully_redacted",
    "assert_fully_redacted",
    "build_redacted_evidence_bundle",
    "content_digest",
    "corpus_digest_for",
    "detect",
    "evaluate_corpus",
    "load_corpus",
    "miss_log_records",
    "redact_text",
    "redaction_marker",
    "redaction_profile_digest",
    "write_miss_log",
]
