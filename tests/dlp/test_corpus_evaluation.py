"""Corpus evaluation harness tests (FR-015, §17.3 DLP row).

The headline test is the acceptance gate itself: the shipped detector
pipeline must clear the §17.3 thresholds against the shipped corpus —
>=99.5% secret recall, >=99.0% PII recall, <=5% false-positive rate —
with zero unexplained misses and zero false positives. Everything else
pins the measurement machinery: integrity enforcement, miss-log
emission, and the semantics of the counting rules.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from evoruntime.dlp.corpus import DlpCategory, content_digest, load_corpus
from evoruntime.dlp.detectors import DEFAULT_RULES
from evoruntime.dlp.errors import CorpusIntegrityError
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

REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = REPO_ROOT / "fixtures" / "dlp" / "corpus.yaml"


@pytest.fixture(scope="module")
def corpus():  # noqa: ANN201 - LabeledCorpus, kept loose to avoid import cycle in fixtures
    return load_corpus(CORPUS_PATH)


class TestCorpusIntegrity:
    def test_corpus_is_versioned_and_labeled(self, corpus) -> None:  # noqa: ANN001
        assert corpus.corpus_id == "dlp_corpus_v1"
        assert corpus.version == 1
        assert len(corpus.examples) >= 200
        assert len(corpus.negatives) >= 50

    def test_all_examples_synthetic_only(self, corpus) -> None:  # noqa: ANN001
        # Structural guarantee: the corpus file declares synthetic-only and
        # every example is content-addressed, so nothing unreviewed ships.
        assert corpus.synthetic_only is True
        for example in corpus.examples:
            assert example.content_digest.startswith("sha256:")

    def test_covers_all_three_categories(self, corpus) -> None:  # noqa: ANN001
        seen = {category for ex in corpus.examples for category in ex.expected}
        # CLEAN is a corpus label for negatives, not a detection target.
        assert seen == set(DlpCategory) - {DlpCategory.CLEAN}

    def test_base64_entries_decode_to_digested_content(self, corpus) -> None:  # noqa: ANN001
        # Token-shaped examples are stored base64 in the file (push-protection
        # hygiene); the loader must decode them and digest the decoded text.
        b64_examples = [
            e for e in corpus.examples if "sk_live_" in e.content or "rk_live_" in e.content
        ]
        assert len(b64_examples) >= 4
        for example in b64_examples:
            assert example.content_digest == content_digest(example.content)

    def test_content_xor_content_b64_is_enforced(self, tmp_path: Path) -> None:
        import yaml

        raw = yaml.safe_load(CORPUS_PATH.read_text())
        raw["examples"][0]["content_b64"] = "aGVsbG8="  # both fields present
        bad = tmp_path / "corpus.yaml"
        bad.write_text(yaml.safe_dump(raw, sort_keys=False))
        with pytest.raises(CorpusIntegrityError, match="exactly one of"):
            load_corpus(bad)

    def test_invalid_base64_is_rejected(self, tmp_path: Path) -> None:
        import yaml

        raw = yaml.safe_load(CORPUS_PATH.read_text())
        del raw["examples"][0]["content"]
        raw["examples"][0]["content_b64"] = "!!!not base64!!!"
        bad = tmp_path / "corpus.yaml"
        bad.write_text(yaml.safe_dump(raw, sort_keys=False))
        with pytest.raises(CorpusIntegrityError, match="invalid 'content_b64'"):
            load_corpus(bad)

    def test_tampered_content_is_rejected(self, tmp_path: Path) -> None:
        import yaml

        raw = yaml.safe_load(CORPUS_PATH.read_text())
        raw["examples"][0]["content"] = raw["examples"][0]["content"] + " tampered"
        tampered = tmp_path / "corpus.yaml"
        tampered.write_text(yaml.safe_dump(raw, sort_keys=False))
        with pytest.raises(CorpusIntegrityError, match="digest mismatch"):
            load_corpus(tampered)


class TestThresholdGates:
    def test_secret_recall_meets_threshold(self, corpus) -> None:  # noqa: ANN001
        evaluation = evaluate_corpus(corpus, DEFAULT_RULES)
        metrics = evaluation.per_category[DlpCategory.SECRETS]
        assert metrics.recall >= Thresholds().min_secret_recall

    def test_pii_recall_meets_threshold(self, corpus) -> None:  # noqa: ANN001
        evaluation = evaluate_corpus(corpus, DEFAULT_RULES)
        metrics = evaluation.per_category[DlpCategory.PII]
        assert metrics.recall >= Thresholds().min_pii_recall

    def test_false_positive_rate_meets_threshold(self, corpus) -> None:  # noqa: ANN001
        evaluation = evaluate_corpus(corpus, DEFAULT_RULES)
        assert evaluation.false_positive_rate <= Thresholds().max_false_positive_rate

    def test_acceptance_gate_passes(self, corpus) -> None:  # noqa: ANN001
        evaluation = evaluate_corpus(corpus, DEFAULT_RULES)
        assert evaluation.passes(), (
            f"misses={[m.example_id for m in evaluation.misses]}, "
            f"fps={[(fp.example_id, fp.rule_id) for fp in evaluation.false_positives]}"
        )

    def test_zero_misses_and_zero_false_positives(self, corpus) -> None:  # noqa: ANN001
        evaluation = evaluate_corpus(corpus, DEFAULT_RULES)
        assert evaluation.misses == ()
        assert evaluation.false_positives == ()


class TestMeasurementSemantics:
    def test_miss_blocks_pass_even_with_slack(self) -> None:
        evaluation = CorpusEvaluation(
            corpus_id="x",
            corpus_version=1,
            per_category={
                DlpCategory.SECRETS: CategoryMetrics(
                    category=DlpCategory.SECRETS, expected_instances=200, detected_instances=199
                )
            },
            clean_examples=60,
            flagged_clean_examples=0,
            false_positive_rate=0.0,
            cross_category_findings=0,
            misses=(
                Miss(
                    example_id="e1",
                    category=DlpCategory.SECRETS,
                    expected=1,
                    detected=0,
                    content_digest="sha256:x",
                ),
            ),
            false_positives=(),
        )
        # 199/200 = 99.5% clears the numeric threshold, but an unexplained
        # miss means the gate is not passed — §17.3 requires review first.
        assert not evaluation.passes()

    def test_fp_rate_counts_flagged_examples_not_findings(self, corpus) -> None:  # noqa: ANN001
        evaluation = evaluate_corpus(corpus, DEFAULT_RULES)
        assert evaluation.flagged_clean_examples <= evaluation.clean_examples
        assert evaluation.false_positive_rate == (
            evaluation.flagged_clean_examples / evaluation.clean_examples
        )


class TestMissLog:
    def test_miss_log_written_as_jsonl(self, corpus, tmp_path: Path) -> None:  # noqa: ANN001
        evaluation = evaluate_corpus(corpus, DEFAULT_RULES)
        log_path = tmp_path / "misses.jsonl"
        count = write_miss_log(log_path, evaluation)
        assert count == 0  # current corpus: nothing to review
        assert log_path.read_text() == ""

    def test_miss_log_records_misses_and_fps(self, tmp_path: Path) -> None:
        evaluation = CorpusEvaluation(
            corpus_id="x",
            corpus_version=1,
            per_category={},
            clean_examples=1,
            flagged_clean_examples=1,
            false_positive_rate=1.0,
            cross_category_findings=0,
            misses=(
                Miss(
                    example_id="m1",
                    category=DlpCategory.SECRETS,
                    expected=2,
                    detected=1,
                    content_digest="sha256:m",
                ),
            ),
            false_positives=(
                FalsePositiveHit(
                    example_id="c1",
                    category=DlpCategory.PII,
                    rule_id="email",
                    matched_text="a@b.co",
                    content_digest="sha256:c",
                ),
            ),
        )
        records = miss_log_records(evaluation)
        assert len(records) == 2
        kinds = {r["kind"] for r in records}
        assert kinds == {"miss", "false_positive"}

        log_path = tmp_path / "misses.jsonl"
        assert write_miss_log(log_path, evaluation) == 2
        lines = [json.loads(line) for line in log_path.read_text().splitlines()]
        assert {line["kind"] for line in lines} == {"miss", "false_positive"}
        assert lines[0]["corpus_id"] == "x"
