"""F3 gate ordering: the PROPOSE→DEV_EVALUATE edge consults the gate before anything runs.

The orchestrator's contract: when an ExecutionGate is installed, a
transition from PROPOSE to DEV_EVALUATE calls the gate *first*. A gate
that raises leaves the campaign in PROPOSE with no transition appended —
and, as the ordering spy proves, nothing downstream of the edge (the
execution plane) ever runs for a blocked candidate.
"""

from __future__ import annotations

import pytest

from evoruntime.campaign.machine import CampaignOrchestrator, CampaignPhase
from evoruntime.plugins.static_analysis import (
    AnalysisViolationCode,
    StaticAnalysisBlockedError,
    StaticAnalysisGate,
    StaticAnalysisReport,
    analyze_files,
)
from tests.campaign.conftest import InMemoryCheckpointStore, make_pinned_spec

BLOCKED_FILES = ({"path": "scripts/apply.py", "content": "import socket\n"},)
CLEAN_FILES = ({"path": "scripts/apply.py", "content": "RULES = {}\n"},)
MASK_PATHS = ("scripts/apply.py",)


class _Mask:
    def __init__(self, allowed_paths: tuple[str, ...]) -> None:
        self._allowed_paths = allowed_paths

    @property
    def allowed_paths(self) -> tuple[str, ...]:
        return self._allowed_paths


def _analyze(files: tuple[dict[str, str], ...]) -> StaticAnalysisReport:
    return analyze_files(
        files,
        masks=(_Mask(MASK_PATHS),),
        artifact_type="prompt_bundle",
        candidate_digest="sha256:" + "0" * 64,
    )


class _OrderSpy:
    """Records the order gate/executor fire in, and whether execution ran."""

    def __init__(self) -> None:
        self.events: list[str] = []
        self.executed = False
        self._report: StaticAnalysisReport | None = None

    def gate(self) -> StaticAnalysisReport:
        self.events.append("analysis")
        assert self._report is not None
        return self._report

    def execute(self) -> None:
        self.events.append("execute")
        self.executed = True

    def attach(self, report: StaticAnalysisReport) -> StaticAnalysisGate:
        self._report = report
        return StaticAnalysisGate(self.gate)


def _orchestrator_at_propose(gate: StaticAnalysisGate) -> CampaignOrchestrator:
    """An orchestrator driven to PROPOSE with the given gate installed."""
    orchestrator = CampaignOrchestrator(
        make_pinned_spec(),
        checkpoints=InMemoryCheckpointStore(),
        execution_gate=gate,
    )
    orchestrator.transition(CampaignPhase.PLAN)
    orchestrator.transition(CampaignPhase.PROPOSE)
    return orchestrator


def test_blocked_candidate_never_reaches_execution() -> None:
    spy = _OrderSpy()
    orchestrator = _orchestrator_at_propose(spy.attach(_analyze(BLOCKED_FILES)))

    with pytest.raises(StaticAnalysisBlockedError) as excinfo:
        orchestrator.transition(CampaignPhase.DEV_EVALUATE)

    # Pre-execution refusal: the campaign never left PROPOSE, nothing was
    # recorded, and the violation payload names the offending class.
    assert orchestrator.phase is CampaignPhase.PROPOSE
    assert orchestrator.transitions[-1].to_phase is CampaignPhase.PROPOSE
    assert not spy.executed
    assert any(
        v.code is AnalysisViolationCode.NETWORK_IMPORT for v in excinfo.value.report.violations
    )


def test_gate_runs_before_any_execution_on_clean_candidate() -> None:
    spy = _OrderSpy()
    orchestrator = _orchestrator_at_propose(spy.attach(_analyze(CLEAN_FILES)))

    orchestrator.transition(CampaignPhase.DEV_EVALUATE)
    spy.execute()  # the execution plane, downstream of the edge

    # Ordering proof: analysis ran before execution, and the transition
    # was recorded only after the gate approved.
    assert spy.events == ["analysis", "execute"]
    assert orchestrator.phase is CampaignPhase.DEV_EVALUATE
    assert orchestrator.transitions[-1].to_phase is CampaignPhase.DEV_EVALUATE


def test_gate_is_consulted_only_on_the_propose_edge() -> None:
    """Other transitions are untouched — the gate is scoped to PROPOSE→DEV_EVALUATE."""
    calls: list[str] = []

    class _CountingGate:
        def approve_execution(self) -> None:
            calls.append("gate")

    orchestrator = CampaignOrchestrator(
        make_pinned_spec(),
        checkpoints=InMemoryCheckpointStore(),
        execution_gate=_CountingGate(),  # type: ignore[arg-type]
    )
    orchestrator.transition(CampaignPhase.PLAN)
    orchestrator.transition(CampaignPhase.PROPOSE)
    assert calls == []
    orchestrator.transition(CampaignPhase.DEV_EVALUATE)
    assert calls == ["gate"]


def test_reconstruction_preserves_the_gate() -> None:
    spy = _OrderSpy()
    checkpoints = InMemoryCheckpointStore()
    orchestrator = CampaignOrchestrator(
        make_pinned_spec(),
        checkpoints=checkpoints,
        execution_gate=spy.attach(_analyze(BLOCKED_FILES)),
    )
    orchestrator.transition(CampaignPhase.PLAN)
    orchestrator.transition(CampaignPhase.PROPOSE)
    digest = orchestrator.checkpoint()

    rebuilt = CampaignOrchestrator.reconstruct(
        make_pinned_spec(),
        checkpoints,
        digest,
        execution_gate=spy.attach(_analyze(BLOCKED_FILES)),
    )
    with pytest.raises(StaticAnalysisBlockedError):
        rebuilt.transition(CampaignPhase.DEV_EVALUATE)
    assert rebuilt.phase is CampaignPhase.PROPOSE
