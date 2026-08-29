"""Discovery — failure clustering over trace reads (deliverable H3, PRD §17.1 step 3).

§17.1 step 3: *discovery clusters failures*. The lifecycle machine always had
the ``DISCOVER`` phase; nothing implemented it. This module is the pure
clustering core the Phase 4 survey's extension-point note called for, and it
stays pure by construction:

* input is plain data — resolved trace reads (:class:`DiscoveredTrace`), not
  sessions or routers — so the same clustering runs over the HTTP read
  surface, a batch export, or a test fixture and is trivially reproducible;
* classification keys on the D8 failure taxonomy
  (``fixtures/lib/schema.py::FailureCategory``: localization,
  test_misunderstanding, dependency_misuse). The category names are pinned
  here as a ``Literal`` because the fixtures package is not part of the
  installed ``evoruntime`` distribution, so ``src/`` cannot import it;
  ``tests/eval/test_discovery.py`` carries a drift guard asserting the two
  stay in lockstep.
* output is a :class:`DiscoveryReport` whose canonical bytes are exactly
  what the evaluation plane signs and persists — the same tamper-evidence
  pattern as every other signed record, riding the analysis-report path
  (``db/models/analysis.py``) with no new authoritative table.

Determinism contract: the same input traces always produce byte-identical
canonical bytes. Traces are sorted by ``(task_id, trace_id)`` before
clustering, clusters are ordered by ``(category, failure_signature)``, cluster
membership is sorted, nothing time-derived enters the signed body, and no
randomness is used anywhere — a re-run over unchanged traces re-signs the
same digest.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Literal

from evoruntime.core.schemas import EvoRuntimeBaseModel
from evoruntime.sdk.adapter import (
    EVENT_OUTCOME_CLAIMED,
    EVENT_TOOL_COMPLETED,
    EVENT_TRACE_ENDED,
)
from evoruntime.sdk.records import DetailValue
from evoruntime.security.signing import DetachedSignature, verify

#: Schema id baked into the canonical bytes, exactly as the F3 verdict does.
DISCOVERY_SCHEMA_ID = "evoruntime.discovery_report/v1"

#: The ``artifact_type`` value discovery reports carry in the
#: ``analysis_reports`` row — how readers on the shared path dispatch.
DISCOVERY_ARTIFACT_TYPE = "discovery_report"

#: Marker key inside the row's JSONB payload column, so a reader can tell a
#: discovery-report body from F3 violation entries at a glance.
DISCOVERY_REPORT_KIND = "discovery_report"

DIGEST_PREFIX = "sha256:"

#: The D8 failure taxonomy (``fixtures/lib/schema.py::FailureCategory``),
#: pinned by value; see the module docstring for why this is a Literal here.
FailureCategoryName = Literal["localization", "test_misunderstanding", "dependency_misuse"]

FAILURE_CATEGORY_NAMES: frozenset[str] = frozenset(
    {"localization", "test_misunderstanding", "dependency_misuse"}
)

# Tool-name conventions the signal fallback reads. These are the names the
# fixture agent (H1) records through ``Trace.tool_call``; the rules below are
# a chosen, documented interpretation of which failing tool indicates which
# D8 category — not a spec quote.
SHELL_TOOL = "shell"
TEST_TOOL = "run_tests"
EDIT_TOOL = "edit"


@dataclass(frozen=True, slots=True)
class TraceEventSignal:
    """One trace event reduced to what classification may look at.

    ``details`` is the event's out-of-line detail body (the bytes the
    envelope's ``payload_digest`` commits to), resolved by the caller. A body
    that was never registered — or was tombstoned — degrades to an empty
    mapping with ``body_resolved=False``: discovery counts it and moves on
    rather than failing the whole run over one unresolvable event.
    """

    event_type: str
    details: Mapping[str, DetailValue] = field(default_factory=dict)
    body_resolved: bool = True


@dataclass(frozen=True, slots=True)
class DiscoveredTrace:
    """One trace as discovery consumes it: identity plus resolved event signals."""

    trace_id: str
    task_id: str
    agent_id: str
    release_id: str
    campaign_id: str | None
    events: tuple[TraceEventSignal, ...]


def validate_taxonomy(
    taxonomy: Mapping[str, str] | None,
) -> dict[str, FailureCategoryName]:
    """Validate a task-id → category mapping against the D8 taxonomy.

    Raises ``ValueError`` naming the offending value — a typo'd category in a
    taxonomy mapping must fail loudly, not silently cluster into the
    unclassified bucket.
    """
    resolved: dict[str, FailureCategoryName] = {}
    for task_id, category in (taxonomy or {}).items():
        if category not in FAILURE_CATEGORY_NAMES:
            raise ValueError(
                f"unknown failure category {category!r} for task {task_id!r}; "
                f"expected one of {sorted(FAILURE_CATEGORY_NAMES)}"
            )
        resolved[task_id] = category  # type: ignore[assignment]
    return resolved


def outcome_of(trace: DiscoveredTrace) -> bool | None:
    """The trace's outcome signal, or None when no event carries one.

    The claimed outcome is untrusted by construction (the adapter SDK says
    so at the emit site); discovery treats it the same way — it is the
    *clustering* signal, never an authoritative result. Falls back to the
    ``trace.ended`` body's ``ok`` when no outcome was claimed.
    """
    for event in reversed(trace.events):
        if event.event_type == EVENT_OUTCOME_CLAIMED:
            claimed = event.details.get("claimed_success")
            return claimed if isinstance(claimed, bool) else None
    for event in reversed(trace.events):
        if event.event_type == EVENT_TRACE_ENDED:
            ok = event.details.get("ok")
            return ok if isinstance(ok, bool) else None
    return None


def _tool_names(trace: DiscoveredTrace, *, ok: bool) -> frozenset[str]:
    """Names of the trace's tool calls whose ``ok`` flag matches."""
    names: set[str] = set()
    for event in trace.events:
        if event.event_type != EVENT_TOOL_COMPLETED:
            continue
        name = event.details.get("name")
        if event.details.get("ok") is ok and isinstance(name, str):
            names.add(name)
    return frozenset(names)


def failure_signature_of(trace: DiscoveredTrace) -> str:
    """A deterministic per-trace signature: the sorted failing tool names."""
    failed = sorted(_tool_names(trace, ok=False))
    return ",".join(failed) if failed else "no_failed_tool"


def classify_failure(
    trace: DiscoveredTrace,
    taxonomy: Mapping[str, FailureCategoryName],
) -> FailureCategoryName | None:
    """Map one failed trace onto the D8 taxonomy, or None when it matches no rule.

    Resolution order — first match wins, and the order is fixed so the same
    trace always classifies the same way:

    1. the explicit taxonomy mapping (task id → category, e.g. derived from
       the D8 fixture manifests, whose ``failure_category`` is ground truth
       for seeded runs);
    2. the failing-tool signal fallback, in a documented order: a failed
       ``shell`` call reads as dependency misuse (environment/dependency
       failures surface as shell errors), a failed ``run_tests`` call as test
       misunderstanding, and a failed edit — or reads with no successful edit
       at all — as localization (the agent looked but never localized the
       change);
    3. otherwise None: the trace lands in the report's unclassified bucket
       rather than being forced into a category it does not fit.
    """
    explicit = taxonomy.get(trace.task_id)
    if explicit is not None:
        return explicit
    failed = _tool_names(trace, ok=False)
    if SHELL_TOOL in failed:
        return "dependency_misuse"
    if TEST_TOOL in failed:
        return "test_misunderstanding"
    if EDIT_TOOL in failed:
        return "localization"
    succeeded = _tool_names(trace, ok=True)
    touched = succeeded | failed
    if EDIT_TOOL not in succeeded and any(name.startswith("read") for name in touched):
        return "localization"
    return None


class DiscoveryCluster(EvoRuntimeBaseModel):
    """One failure cluster: a taxonomy category plus a failure signature.

    ``category=None`` is the unclassified bucket — failures that matched no
    taxonomy entry and no signal rule. They are reported, never dropped: a
    failure discovery silently ignores is exactly the invisible gap this
    deliverable exists to close.
    """

    category: FailureCategoryName | None
    failure_signature: str
    trace_ids: tuple[str, ...]
    representative_trace_ids: tuple[str, ...]

    @property
    def count(self) -> int:
        """Membership size — derived, so it never rides the signed bytes."""
        return len(self.trace_ids)


class DiscoveryReport(EvoRuntimeBaseModel):
    """The signed discovery report body.

    Everything in here is input-derived and deterministic; derived
    aggregates (``failure_count``, ``categories_hit``, the digest itself)
    are properties outside the canonical bytes, mirroring how the F3
    verdict keeps its derived ``outcome`` out of its signed body.
    """

    campaign_id: str | None = None
    agent_id: str | None = None
    release_id: str | None = None
    traces_scanned: int = 0
    unresolved_events: int = 0
    clusters: tuple[DiscoveryCluster, ...] = ()

    @property
    def failure_count(self) -> int:
        """Total failed traces across every cluster, unclassified included."""
        return sum(cluster.count for cluster in self.clusters)

    @property
    def unclassified_count(self) -> int:
        """Failures in the unclassified bucket (0 when there is none)."""
        for cluster in self.clusters:
            if cluster.category is None:
                return cluster.count
        return 0

    @property
    def categories_hit(self) -> tuple[str, ...]:
        """The D8 taxonomy categories this run actually hit, sorted."""
        return tuple(
            sorted({cluster.category for cluster in self.clusters if cluster.category is not None})
        )

    def canonical_bytes(self) -> bytes:
        """Canonical JSON of the report body — the bytes a digest/signature covers.

        Excludes everything derived (aggregates, the digest itself) so the
        signed body is exactly what the clustering produced, in a
        byte-stable form.
        """
        body = {
            "schema_id": DISCOVERY_SCHEMA_ID,
            "campaign_id": self.campaign_id,
            "agent_id": self.agent_id,
            "release_id": self.release_id,
            "traces_scanned": self.traces_scanned,
            "unresolved_events": self.unresolved_events,
            "clusters": [cluster.model_dump(mode="json") for cluster in self.clusters],
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @property
    def report_digest(self) -> str:
        """Content address of the canonical report bytes."""
        return DIGEST_PREFIX + hashlib.sha256(self.canonical_bytes()).hexdigest()


def cluster_failures(
    traces: Iterable[DiscoveredTrace],
    *,
    taxonomy: Mapping[str, FailureCategoryName] | None = None,
    campaign_id: str | None = None,
    agent_id: str | None = None,
    release_id: str | None = None,
    max_representatives: int = 5,
) -> DiscoveryReport:
    """Cluster failed traces against the D8 taxonomy into a discovery report.

    Deterministic by construction: input order does not matter (traces are
    sorted by ``(task_id, trace_id)`` first), clusters are ordered by
    ``(category, failure_signature)`` with the unclassified bucket (``None``)
    sorting first, and representatives are the first ``max_representatives``
    member ids in sorted order.
    """
    resolved_taxonomy = validate_taxonomy(taxonomy or {})
    grouped: dict[tuple[FailureCategoryName | None, str], list[str]] = {}
    scanned = 0
    unresolved = 0
    for trace in sorted(traces, key=lambda t: (t.task_id, t.trace_id)):
        scanned += 1
        unresolved += sum(1 for event in trace.events if not event.body_resolved)
        if outcome_of(trace) is not False:
            # Successes — and traces with no outcome signal at all — are not
            # discovery input; only failures cluster.
            continue
        key = (
            classify_failure(trace, resolved_taxonomy),
            failure_signature_of(trace),
        )
        grouped.setdefault(key, []).append(trace.trace_id)

    clusters = tuple(
        DiscoveryCluster(
            category=category,
            failure_signature=signature,
            trace_ids=tuple(members),
            representative_trace_ids=tuple(members[:max_representatives]),
        )
        for (category, signature), members in sorted(
            grouped.items(), key=lambda item: ((item[0][0] or ""), item[0][1])
        )
    )
    return DiscoveryReport(
        campaign_id=campaign_id,
        agent_id=agent_id,
        release_id=release_id,
        traces_scanned=scanned,
        unresolved_events=unresolved,
        clusters=clusters,
    )


def verify_discovery_report(
    report: DiscoveryReport, *, signature: bytes, public_key: bytes
) -> bool:
    """Verify a detached signature over the report's canonical bytes.

    The public key travels with the signature (the analysis-report row
    stores both), so a verifier needs no evaluator key access — the same
    property every other signed record's verification has.
    """
    return verify(
        DetachedSignature(signature=signature, public_key=public_key),
        report.canonical_bytes(),
    )


__all__ = [
    "DISCOVERY_ARTIFACT_TYPE",
    "DISCOVERY_REPORT_KIND",
    "DISCOVERY_SCHEMA_ID",
    "DIGEST_PREFIX",
    "FAILURE_CATEGORY_NAMES",
    "DiscoveredTrace",
    "DiscoveryCluster",
    "DiscoveryReport",
    "FailureCategoryName",
    "TraceEventSignal",
    "classify_failure",
    "cluster_failures",
    "failure_signature_of",
    "outcome_of",
    "validate_taxonomy",
    "verify_discovery_report",
]
