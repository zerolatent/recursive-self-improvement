"""G8 acceptance: the severity-1 destructive-operation drill (release plane).

A scaffold campaign's destructive mutation trips a severity-1 guardrail
event during the canary. The drill proves the four claims the spec pins:

1. **Compensations execute in declared order** — the CAS
   ``restore_scaffold_source`` (plan position 0) completes, digest-verified,
   before the requires-execution ``rerun_conformance_suite`` (position 1)
   runs; the rerun's suite runner captures the tree content at run time,
   proving it judged *restored* source, not the mutated tree.
2. **The pointer rolls back** — the release controller's CAS returns the
   active release to the incumbent manifest.
3. **Refusal restores the incumbent** — promotion is refused while the
   conformance rerun is unexecuted, and the refusal leaves the incumbent
   release live.
4. **Evidence lands** — the execution sink carries the rerun's record and
   the restore record names every restored module with its verified pin.

The drill orchestrates the rollback the way the campaign machine does:
the CAS restore rides the rollback path (invoked in the plan's declared
position, before the requires-execution walk), then the canary's
compensation walk executes the rerun and the controller CASes the pointer.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.release.conftest import make_manifest

from evoruntime.campaign.compensation import (
    CAS_MODE,
    REQUIRES_EXECUTION_MODE,
    InMemoryExecutionSink,
    sign_compensation_plan,
)
from evoruntime.campaign.errors import UnexecutedCompensationError
from evoruntime.campaign.scaffold_compensation import (
    ConformanceRerunExecutor,
    ScaffoldSourceRestorer,
)
from evoruntime.eval.conformance import SuiteRunResult
from evoruntime.plugins.scaffold import (
    module_canonical_bytes,
    module_digest,
    scaffold_canonical_bytes,
    scaffold_digest,
    scaffold_file_map_from_sources,
)
from evoruntime.release import (
    CanaryConfig,
    CanaryHarness,
    CanaryOutcome,
    CompressedClock,
    GuardrailEvent,
    InProcessFleetSimulator,
    ReleaseController,
    SignedReleaseManifest,
)

_INCUMBENT_SOURCES = {
    "src/agent/__init__.py": "",
    "src/agent/planner.py": "def plan(): ...",
    "src/agent/tools.py": "def tool(): ...",
}
_ENTRYPOINTS = ("src/agent/__init__.py",)
_SUITE = "conformance/self-edit@sha256:" + "2b" * 32
_MUTATED_PLANNER = "import os\n\n\ndef plan():\n    os.system('rm -rf /')\n"


class _RegistryReader:
    """Digest-keyed stand-in for RegistryService.read_artifact — the
    registered scaffold artifacts the rollback restores from."""

    def __init__(self, blobs: dict[str, bytes]) -> None:
        self._blobs = blobs

    def read_artifact(self, *, tenant_id: str, digest: str) -> bytes:
        return self._blobs[digest]


class _TreeInspectingRunner:
    """Returns a canned suite result and captures the tree state at run
    time — the drill reads the capture to prove the rerun executed against
    restored source (declared order: restore at position 0 first)."""

    def __init__(self, result: SuiteRunResult, tree_root: Path, probe: str) -> None:
        self._result = result
        self._tree_root = tree_root
        self._probe = probe
        self.captured_planner_content: str | None = None

    def run(self, command: tuple[str, ...]) -> SuiteRunResult:
        self.captured_planner_content = (self._tree_root / self._probe).read_text(encoding="utf-8")
        return self._result


def _register_scaffold(sources: dict[str, str]) -> tuple[dict[str, bytes], Any]:
    """Digest-keyed registry blobs for a scaffold over ``sources``."""
    file_map = scaffold_file_map_from_sources(
        sources, entrypoints=_ENTRYPOINTS, conformance_suite=_SUITE
    )
    blobs: dict[str, bytes] = {scaffold_digest(file_map): scaffold_canonical_bytes(file_map)}
    for path, content in sources.items():
        blobs[module_digest(path, content)] = module_canonical_bytes(path, content)
    return blobs, file_map


def _candidate_scaffold_digest(
    candidate_blobs: dict[str, bytes], incumbent_blobs: dict[str, bytes]
) -> str:
    """The candidate scaffold's content address — the one blob the
    incumbent registry does not carry."""
    return next(d for d in candidate_blobs if d not in incumbent_blobs)


def _scaffold_plan(plan_id: str, scaffold_digest_value: str) -> Any:
    """The G8 scaffold rollback plan: restore the source (CAS), then
    re-verify the oracle (requires-execution) — declared order."""
    return sign_compensation_plan(
        plan_id=plan_id,
        campaign_id="campaign-g8-drill",
        manifest_digest=None,
        actions=[
            {
                "artifact_digest": scaffold_digest_value,
                "action": "restore_scaffold_source",
                "mode": CAS_MODE,
                "executed": False,
            },
            {
                "artifact_digest": scaffold_digest_value,
                "action": "rerun_conformance_suite",
                "mode": REQUIRES_EXECUTION_MODE,
                "executed": False,
            },
        ],
        private_key=Ed25519PrivateKey.generate(),
    )


def _harness(
    controller: ReleaseController,
    fleet: InProcessFleetSimulator,
    clock: CompressedClock,
    signing_key: Ed25519PrivateKey,
    *,
    incumbent_digests: list[str],
    candidate_digests: list[str],
    plan: Any,
    executions: InMemoryExecutionSink,
    executor: ConformanceRerunExecutor,
) -> tuple[SignedReleaseManifest, SignedReleaseManifest, CanaryHarness]:
    incumbent = make_manifest(signing_key, artifact_digests=incumbent_digests)
    controller.activate(incumbent)
    candidate = make_manifest(
        signing_key,
        artifact_digests=candidate_digests,
        prior_release_digest=incumbent.manifest_digest,
    )
    harness = CanaryHarness(
        config=CanaryConfig(),
        controller=controller,
        fleet=fleet,
        clock=clock,
        compensation_plan=plan,
        compensation_executions=executions,
        compensation_executor=executor,
    )
    return incumbent, candidate, harness


def test_severity_1_drill_compensates_in_order_rolls_back_and_evidences(
    controller: ReleaseController,
    fleet: InProcessFleetSimulator,
    clock: CompressedClock,
    signing_key: Ed25519PrivateKey,
    tmp_path: Path,
) -> None:
    """The full drill: destructive mutation live in the tree, severity-1
    event fires, the rollback path restores the incumbent source (CAS),
    re-proves it against its own pinned suite (evidenced), and the pointer
    returns to the incumbent release."""
    incumbent_blobs, incumbent_map = _register_scaffold(_INCUMBENT_SOURCES)
    incumbent_scaffold_digest = scaffold_digest(incumbent_map)
    candidate_blobs, _ = _register_scaffold(
        dict(_INCUMBENT_SOURCES, **{"src/agent/planner.py": _MUTATED_PLANNER})
    )
    candidate_scaffold_digest = _candidate_scaffold_digest(candidate_blobs, incumbent_blobs)

    # The destructive mutation executed: the working tree now carries the
    # candidate's rm-rf planner instead of the incumbent's.
    (tmp_path / "src" / "agent").mkdir(parents=True)
    (tmp_path / "src" / "agent" / "planner.py").write_text(_MUTATED_PLANNER, encoding="utf-8")

    plan = _scaffold_plan("plan-g8-drill", incumbent_scaffold_digest)
    sink = InMemoryExecutionSink()
    runner = _TreeInspectingRunner(
        SuiteRunResult(returncode=0, stdout="118 passed in 2.31s"),
        tree_root=tmp_path,
        probe="src/agent/planner.py",
    )
    executor = ConformanceRerunExecutor(
        reader=_RegistryReader(incumbent_blobs), tenant_id="tenant-g8", runner=runner
    )
    incumbent, candidate, harness = _harness(
        controller,
        fleet,
        clock,
        signing_key,
        incumbent_digests=[incumbent_scaffold_digest],
        candidate_digests=[candidate_scaffold_digest],
        plan=plan,
        executions=sink,
        executor=executor,
    )

    # Rollback path, in the plan's declared order: the CAS restore
    # (position 0) rides the rollback — digest-verified, no execution
    # record — before the requires-execution walk (position 1) runs.
    restore_record = ScaffoldSourceRestorer(
        reader=_RegistryReader(incumbent_blobs), tenant_id="tenant-g8"
    ).restore(scaffold_digest=incumbent_scaffold_digest, tree_root=tmp_path)
    result = harness.run(
        candidate,
        guardrail_events=(GuardrailEvent(severity=1, kind="unsafe-edit", task_index=5),),
    )

    # (1) Compensations executed in declared order: the rerun (position 1)
    # judged restored source — the runner captured the incumbent planner,
    # not the mutation.
    assert result.outcome is CanaryOutcome.ROLLED_BACK
    assert runner.captured_planner_content == _INCUMBENT_SOURCES["src/agent/planner.py"]
    assert [record.action_index for record in sink.all()] == [1]
    assert all(record.plan_id == plan.plan_id for record in sink.all())
    # The CAS restore's evidence: every incumbent module restored with its
    # verified pin, and the tree bytes match the pins.
    assert restore_record.scaffold_digest == incumbent_scaffold_digest
    assert {module.path for module in restore_record.modules} == set(_INCUMBENT_SOURCES)
    for path, content in _INCUMBENT_SOURCES.items():
        assert (tmp_path / path).read_text(encoding="utf-8") == content
    # (2) The pointer rolled back through the controller's CAS.
    assert controller.active_digest() == incumbent.manifest_digest
    assert result.rolled_back_to == incumbent.manifest_digest


def test_promotion_refusal_restores_the_incumbent(
    controller: ReleaseController,
    fleet: InProcessFleetSimulator,
    clock: CompressedClock,
    signing_key: Ed25519PrivateKey,
) -> None:
    """The rerun is declared but unexecuted: promotion is refused, the
    refusal rolls the candidate back, and the incumbent stays live."""
    incumbent_blobs, incumbent_map = _register_scaffold(_INCUMBENT_SOURCES)
    incumbent_scaffold_digest = scaffold_digest(incumbent_map)
    candidate_blobs, _ = _register_scaffold(
        dict(_INCUMBENT_SOURCES, **{"src/agent/planner.py": _MUTATED_PLANNER})
    )
    candidate_scaffold_digest = _candidate_scaffold_digest(candidate_blobs, incumbent_blobs)

    plan = _scaffold_plan("plan-g8-refusal", incumbent_scaffold_digest)
    sink = InMemoryExecutionSink()
    runner = _TreeInspectingRunner(
        SuiteRunResult(returncode=0, stdout="118 passed in 2.31s"),
        tree_root=Path("/nonexistent"),
        probe="src/agent/planner.py",
    )
    executor = ConformanceRerunExecutor(
        reader=_RegistryReader(incumbent_blobs), tenant_id="tenant-g8", runner=runner
    )
    incumbent, candidate, harness = _harness(
        controller,
        fleet,
        clock,
        signing_key,
        incumbent_digests=[incumbent_scaffold_digest],
        candidate_digests=[candidate_scaffold_digest],
        plan=plan,
        executions=sink,
        executor=executor,
    )

    with pytest.raises(UnexecutedCompensationError):
        harness.run(candidate)
    # The refusal restored the incumbent: the pointer never left it.
    assert controller.active_digest() == incumbent.manifest_digest
    # No execution evidence was fabricated: the sink is empty and the
    # suite never ran.
    assert sink.all() == ()
    assert runner.captured_planner_content is None


def test_conformance_rerun_failure_leaves_plan_undischarged(
    controller: ReleaseController,
    fleet: InProcessFleetSimulator,
    clock: CompressedClock,
    signing_key: Ed25519PrivateKey,
    tmp_path: Path,
) -> None:
    """A rerun that cannot prove zero regressions aborts the compensation
    walk: the failing action keeps no execution record, and the promotion
    check keeps refusing."""
    incumbent_blobs, incumbent_map = _register_scaffold(_INCUMBENT_SOURCES)
    incumbent_scaffold_digest = scaffold_digest(incumbent_map)
    candidate_blobs, _ = _register_scaffold(
        dict(_INCUMBENT_SOURCES, **{"src/agent/planner.py": _MUTATED_PLANNER})
    )
    candidate_scaffold_digest = _candidate_scaffold_digest(candidate_blobs, incumbent_blobs)

    plan = _scaffold_plan("plan-g8-regressing", incumbent_scaffold_digest)
    sink = InMemoryExecutionSink()
    runner = _TreeInspectingRunner(
        SuiteRunResult(returncode=1, stdout="1 failed, 117 passed in 2.31s"),
        tree_root=tmp_path,
        probe="src/agent/planner.py",
    )
    executor = ConformanceRerunExecutor(
        reader=_RegistryReader(incumbent_blobs), tenant_id="tenant-g8", runner=runner
    )
    _, candidate, harness = _harness(
        controller,
        fleet,
        clock,
        signing_key,
        incumbent_digests=[incumbent_scaffold_digest],
        candidate_digests=[candidate_scaffold_digest],
        plan=plan,
        executions=sink,
        executor=executor,
    )

    # Rollback path: the CAS restore succeeds, then the rerun fails to
    # prove zero regressions — the plan stays undischarged.
    ScaffoldSourceRestorer(reader=_RegistryReader(incumbent_blobs), tenant_id="tenant-g8").restore(
        scaffold_digest=incumbent_scaffold_digest, tree_root=tmp_path
    )
    with pytest.raises(Exception, match="zero regressions"):
        harness.run(
            candidate,
            guardrail_events=(GuardrailEvent(severity=1, kind="unsafe-edit", task_index=5),),
        )
    assert sink.all() == ()
