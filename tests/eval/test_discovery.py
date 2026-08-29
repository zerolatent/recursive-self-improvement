"""Unit tests for the pure failure-clustering module (deliverable H3).

No database: clustering is a pure function over `DiscoveredTrace` inputs,
so these tests pin the determinism contract (same inputs → byte-identical
canonical bytes → identical report digest), the D8 classification rules,
representative selection, and the detached-signature verification path
directly.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

from evoruntime.eval.discovery import (
    EVENT_OUTCOME_CLAIMED,
    EVENT_TOOL_COMPLETED,
    EVENT_TRACE_ENDED,
    FAILURE_CATEGORY_NAMES,
    DiscoveredTrace,
    TraceEventSignal,
    cluster_failures,
    validate_taxonomy,
    verify_discovery_report,
)
from evoruntime.security.signing import generate_signing_key, sign

REPO_ROOT = Path(__file__).resolve().parents[2]


def _trace(
    trace_id: str,
    *,
    task_id: str = "tsk_1",
    events: tuple[TraceEventSignal, ...] = (),
    campaign_id: str | None = "cmp_x",
) -> DiscoveredTrace:
    return DiscoveredTrace(
        trace_id=trace_id,
        task_id=task_id,
        agent_id="agt_x",
        release_id="rel_x",
        campaign_id=campaign_id,
        events=events,
    )


def _failed_tool(name: str) -> TraceEventSignal:
    return TraceEventSignal(event_type=EVENT_TOOL_COMPLETED, details={"name": name, "ok": False})


def _successful_tool(name: str) -> TraceEventSignal:
    return TraceEventSignal(event_type=EVENT_TOOL_COMPLETED, details={"name": name, "ok": True})


def _failed_trace(
    trace_id: str, *, tools: tuple[str, ...], task_id: str = "tsk_1"
) -> DiscoveredTrace:
    """A trace that failed: the named tools failed and the trace ended not-ok."""
    return _trace(
        trace_id,
        task_id=task_id,
        events=tuple(_failed_tool(tool) for tool in tools)
        + (TraceEventSignal(event_type=EVENT_TRACE_ENDED, details={"ok": False}),),
    )


# ----------------------------------------------------------------------
# Determinism
# ----------------------------------------------------------------------


def _seeded_traces() -> list[DiscoveredTrace]:
    """A fixed population covering every classification path."""
    return [
        _failed_trace("trc_a", tools=("shell",), task_id="tsk_dep"),
        _failed_trace("trc_b", tools=("shell",), task_id="tsk_dep"),
        _failed_trace("trc_c", tools=("run_tests",), task_id="tsk_test"),
        _failed_trace("trc_d", tools=("edit",), task_id="tsk_loc"),
        _trace(
            "trc_e",
            task_id="tsk_none",
            events=(
                _failed_tool("grep"),
                TraceEventSignal(event_type=EVENT_TRACE_ENDED, details={"ok": False}),
            ),
        ),
        _trace(
            "trc_f",
            task_id="tsk_ok",
            events=(
                _successful_tool("edit"),
                TraceEventSignal(event_type=EVENT_TRACE_ENDED, details={"ok": True}),
            ),
        ),
        _trace("trc_g", task_id="tsk_signalless"),  # no outcome signal at all
    ]


def test_same_inputs_produce_identical_digest() -> None:
    first = cluster_failures(_seeded_traces())
    second = cluster_failures(_seeded_traces())
    assert first.report_digest == second.report_digest
    assert first.canonical_bytes() == second.canonical_bytes()


def test_input_order_does_not_change_the_report() -> None:
    forward = cluster_failures(_seeded_traces())
    backward = cluster_failures(list(reversed(_seeded_traces())))
    assert forward.report_digest == backward.report_digest


# ----------------------------------------------------------------------
# D8 classification rules
# ----------------------------------------------------------------------


def test_failed_shell_classifies_dependency_misuse() -> None:
    report = cluster_failures([_failed_trace("trc_a", tools=("shell",))])
    assert len(report.clusters) == 1
    assert report.clusters[0].category == "dependency_misuse"
    assert report.clusters[0].failure_signature == "shell"


def test_failed_run_tests_classifies_test_misunderstanding() -> None:
    report = cluster_failures([_failed_trace("trc_a", tools=("run_tests",))])
    assert report.clusters[0].category == "test_misunderstanding"


def test_failed_edit_classifies_localization() -> None:
    report = cluster_failures([_failed_trace("trc_a", tools=("edit",))])
    assert report.clusters[0].category == "localization"


def test_reads_without_a_successful_edit_classify_localization() -> None:
    # The agent read files but never localized an edit — the documented
    # read-without-edit fallback.
    trace = _trace(
        "trc_read",
        events=(
            _successful_tool("read_file"),
            TraceEventSignal(event_type=EVENT_TRACE_ENDED, details={"ok": False}),
        ),
    )
    report = cluster_failures([trace])
    assert report.clusters[0].category == "localization"


def test_explicit_taxonomy_overrides_the_signal_rules() -> None:
    # A failed shell call would read as dependency_misuse by signal, but the
    # explicit task mapping wins — first match in the documented order.
    report = cluster_failures(
        [_failed_trace("trc_a", tools=("shell",), task_id="tsk_dep")],
        taxonomy={"tsk_dep": "test_misunderstanding"},
    )
    assert report.clusters[0].category == "test_misunderstanding"


def test_unknown_taxonomy_category_raises() -> None:
    taxonomy: dict[str, str] = {"tsk_x": "not_a_category"}
    with pytest.raises(ValueError, match="unknown failure category"):
        cluster_failures([], taxonomy=taxonomy)  # type: ignore[arg-type]


def test_validate_taxonomy_rejects_unknown_category() -> None:
    with pytest.raises(ValueError, match="tsk_x"):
        validate_taxonomy({"tsk_x": "hallucination"})


def test_unclassified_failures_land_in_the_unclassified_bucket() -> None:
    # A failing tool that matches no signal rule: reported, never dropped.
    report = cluster_failures([_failed_trace("trc_a", tools=("grep",))])
    assert len(report.clusters) == 1
    assert report.clusters[0].category is None
    assert report.unclassified_count == 1
    assert report.failure_count == 1


def test_successes_and_signalless_traces_do_not_cluster() -> None:
    report = cluster_failures(_seeded_traces())
    clustered_ids = {tid for cluster in report.clusters for tid in cluster.trace_ids}
    # trc_f succeeded; trc_g carries no outcome signal — neither is failure input.
    assert "trc_f" not in clustered_ids
    assert "trc_g" not in clustered_ids


def test_claimed_outcome_is_the_clustering_signal() -> None:
    # The claimed outcome (untrusted by construction) drives clustering the
    # same way the trace.ended fallback does.
    trace = _trace(
        "trc_claim",
        events=(
            _failed_tool("shell"),
            TraceEventSignal(event_type=EVENT_OUTCOME_CLAIMED, details={"claimed_success": False}),
        ),
    )
    report = cluster_failures([trace])
    assert report.clusters[0].category == "dependency_misuse"


# ----------------------------------------------------------------------
# Report shape
# ----------------------------------------------------------------------


def test_unresolved_events_are_counted_not_fatal() -> None:
    trace = _trace(
        "trc_u",
        events=(
            TraceEventSignal(event_type=EVENT_TOOL_COMPLETED, details={}, body_resolved=False),
            TraceEventSignal(event_type=EVENT_TRACE_ENDED, details={"ok": False}),
        ),
    )
    report = cluster_failures([trace])
    assert report.unresolved_events == 1
    assert report.failure_count == 1


def test_representatives_are_capped_and_sorted() -> None:
    traces = [_failed_trace(f"trc_{i}", tools=("shell",)) for i in range(7)]
    report = cluster_failures(traces, max_representatives=3)
    cluster = report.clusters[0]
    assert cluster.count == 7
    assert cluster.representative_trace_ids == cluster.trace_ids[:3]
    assert len(cluster.representative_trace_ids) == 3


def test_categories_hit_is_sorted_and_deduplicated() -> None:
    traces = [
        _failed_trace("trc_a", tools=("shell",)),
        _failed_trace("trc_b", tools=("shell",)),
        _failed_trace("trc_c", tools=("edit",)),
    ]
    report = cluster_failures(traces)
    assert report.categories_hit == ("dependency_misuse", "localization")


def test_clusters_are_ordered_deterministically() -> None:
    report = cluster_failures(_seeded_traces())
    keys = [(cluster.category or "", cluster.failure_signature) for cluster in report.clusters]
    assert keys == sorted(keys)


def test_empty_input_yields_an_empty_report() -> None:
    report = cluster_failures([])
    assert report.traces_scanned == 0
    assert report.clusters == ()
    assert report.failure_count == 0
    assert report.categories_hit == ()


# ----------------------------------------------------------------------
# Signature verification
# ----------------------------------------------------------------------


def test_signature_roundtrip_and_tamper_detection() -> None:
    report = cluster_failures(_seeded_traces())
    detached = sign(generate_signing_key(), report.canonical_bytes())
    assert verify_discovery_report(
        report, signature=detached.signature, public_key=detached.public_key
    )

    # Any change to the signed body — here a mutated scan count — must fail
    # verification against the original signature.
    tampered: dict[str, Any] = {"traces_scanned": report.traces_scanned + 1}
    assert not verify_discovery_report(
        report.model_copy(update=tampered),
        signature=detached.signature,
        public_key=detached.public_key,
    )


# ----------------------------------------------------------------------
# Drift guard: the pinned Literal vs the D8 fixture taxonomy
# ----------------------------------------------------------------------


def test_pinned_categories_match_the_d8_fixture_taxonomy() -> None:
    """The module pins FailureCategory by value because fixtures/ is not an
    installed package; this guard fails loudly if the two drift apart."""
    fixtures_path = str(REPO_ROOT / "fixtures" / "lib")
    sys.path.insert(0, fixtures_path)
    try:
        from schema import FailureCategory  # noqa: PLC0415  (path-dependent import)
    finally:
        sys.path.remove(fixtures_path)

    assert {member.value for member in FailureCategory} == FAILURE_CATEGORY_NAMES
