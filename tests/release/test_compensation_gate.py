"""F5 release-plane compensation enforcement (canary harness).

The acceptance matrix, exercised at the release plane:

- **Promotion refused** while a requires-execution compensation is declared
  and unexecuted — the refusal happens before anything is activated, so the
  incumbent release stays live.
- **Rollback of a multi-artifact release executes declared compensations in
  order** — a severity-1 guardrail event triggers the rollback path, the
  plan's requires-execution actions run in declared order (CAS actions ride
  the controller's pointer rollback), and the evidence lands in the sink.
- **Plan tamper refused** — a plan whose bytes no longer verify refuses to
  gate promotion.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.release.conftest import digest, make_manifest

from evoruntime.campaign.compensation import (
    CAS_MODE,
    REQUIRES_EXECUTION_MODE,
    InMemoryExecutionSink,
    sign_compensation_plan,
)
from evoruntime.campaign.errors import (
    CompensationPlanTamperedError,
    UnexecutedCompensationError,
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


class _RecordingExecutor:
    """Executes compensations by recording the call order."""

    def __init__(self) -> None:
        self.calls: list[tuple[int, str]] = []

    def execute(self, action_index: int, action: dict[str, Any]) -> None:
        self.calls.append((action_index, str(action.get("action", ""))))


def _mixed_plan(plan_id: str = "plan-canary-1") -> Any:
    """A multi-artifact plan: hook on artifact 3, CAS revoke on artifact 4."""
    return sign_compensation_plan(
        plan_id=plan_id,
        campaign_id="campaign-canary",
        manifest_digest=None,
        actions=[
            {
                "artifact_digest": digest(3),
                "action": "run_compensation_hook",
                "mode": REQUIRES_EXECUTION_MODE,
                "executed": False,
            },
            {
                "artifact_digest": digest(4),
                "action": "revoke_artifact",
                "mode": CAS_MODE,
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
    plan: Any = None,
    executions: InMemoryExecutionSink | None = None,
    executor: Any = None,
) -> tuple[SignedReleaseManifest, SignedReleaseManifest, CanaryHarness]:
    incumbent = make_manifest(signing_key, artifact_digests=[digest(1), digest(2)])
    controller.activate(incumbent)
    candidate = make_manifest(
        signing_key,
        artifact_digests=[digest(3), digest(4)],
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


def test_promotion_refused_while_requires_execution_compensation_unexecuted(
    controller: ReleaseController,
    fleet: InProcessFleetSimulator,
    clock: CompressedClock,
    signing_key: Ed25519PrivateKey,
) -> None:
    incumbent, candidate, harness = _harness(
        controller, fleet, clock, signing_key, plan=_mixed_plan()
    )
    with pytest.raises(UnexecutedCompensationError):
        harness.run(candidate)
    # The refusal happened before activation: the incumbent is still live.
    assert controller.active_digest() == incumbent.manifest_digest


def test_severity_1_rollback_executes_declared_compensations_in_order(
    controller: ReleaseController,
    fleet: InProcessFleetSimulator,
    clock: CompressedClock,
    signing_key: Ed25519PrivateKey,
) -> None:
    plan = _mixed_plan()
    sink = InMemoryExecutionSink()
    executor = _RecordingExecutor()
    incumbent, candidate, harness = _harness(
        controller,
        fleet,
        clock,
        signing_key,
        plan=plan,
        executions=sink,
        executor=executor,
    )
    result = harness.run(
        candidate,
        guardrail_events=(GuardrailEvent(severity=1, kind="error_rate", task_index=5),),
    )
    assert result.outcome is CanaryOutcome.ROLLED_BACK
    # Declared order, CAS action skipped: only the hook (position 0) ran.
    assert executor.calls == [(0, "run_compensation_hook")]
    assert [record.action_index for record in sink.all()] == [0]
    assert all(record.plan_id == plan.plan_id for record in sink.all())
    # The pointer rollback still landed through the controller's CAS.
    assert controller.active_digest() == incumbent.manifest_digest


def test_all_cas_plan_promotes_without_execution_evidence(
    controller: ReleaseController,
    fleet: InProcessFleetSimulator,
    clock: CompressedClock,
    signing_key: Ed25519PrivateKey,
) -> None:
    plan = sign_compensation_plan(
        plan_id="plan-all-cas",
        campaign_id="campaign-canary",
        manifest_digest=None,
        actions=[
            {
                "artifact_digest": digest(3),
                "action": "restore_prior_release_pointer",
                "mode": CAS_MODE,
                "executed": False,
            }
        ],
        private_key=Ed25519PrivateKey.generate(),
    )
    _, candidate, harness = _harness(controller, fleet, clock, signing_key, plan=plan)
    result = harness.run(candidate)
    assert result.outcome is CanaryOutcome.COMPLETED


def test_tampered_plan_refuses_to_gate_promotion(
    controller: ReleaseController,
    fleet: InProcessFleetSimulator,
    clock: CompressedClock,
    signing_key: Ed25519PrivateKey,
) -> None:
    plan = _mixed_plan()
    # Splice reordered actions under the original digest and signature: the
    # body no longer matches what was signed.
    forged = type(plan)(
        plan_id=plan.plan_id,
        campaign_id=plan.campaign_id,
        manifest_digest=plan.manifest_digest,
        actions=tuple([dict(action) for action in plan.actions][::-1]),
        plan_digest=plan.plan_digest,
        signature=plan.signature,
        signer_public_key=plan.signer_public_key,
    )
    assert forged.verify() is False
    _, candidate, harness = _harness(controller, fleet, clock, signing_key, plan=forged)
    with pytest.raises(CompensationPlanTamperedError):
        harness.run(candidate)
