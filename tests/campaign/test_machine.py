"""Lifecycle state-machine tests (FR-005): transitions, control states,
content-addressed checkpoints, and kill/resume fault injection.

The fault-injection tests simulate process death the way it actually
happens — mid-flight, between transitions — and assert that a
reconstructed orchestrator is the *same* campaign: same phase, same
resume target, same complete transition history.
"""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evoruntime.campaign.errors import (
    CampaignCheckpointError,
    InvalidTransitionError,
    SpecTamperedError,
)
from evoruntime.campaign.machine import (
    CampaignOrchestrator,
    CampaignPhase,
    CampaignTransition,
    InMemoryTransitionSink,
    allowed_transitions,
    can_cancel,
    can_pause,
    is_terminal,
)
from evoruntime.campaign.spec import PinnedCampaignSpec, pin_and_sign
from tests.campaign.conftest import InMemoryCheckpointStore, make_spec


class TestTransitionTable:
    """The transition table is the contract — test it directly."""

    def test_happy_path_walks_the_full_lifecycle(self) -> None:
        """Discover→…→Learn is walkable one legal edge at a time."""
        path = [
            CampaignPhase.DISCOVER,
            CampaignPhase.PLAN,
            CampaignPhase.PROPOSE,
            CampaignPhase.DEV_EVALUATE,
            CampaignPhase.SELECT_FREEZE,
            CampaignPhase.HOLDOUT,
            CampaignPhase.APPROVE,
            CampaignPhase.CANARY,
            CampaignPhase.PROMOTED,
            CampaignPhase.LEARN,
        ]
        for current, nxt in zip(path, path[1:], strict=False):
            assert nxt in allowed_transitions(current), f"{current} → {nxt} missing"

    def test_rollback_path_exists_from_approve_and_canary(self) -> None:
        """Both approve and canary can roll back to the incumbent release."""
        assert CampaignPhase.ROLLED_BACK in allowed_transitions(CampaignPhase.APPROVE)
        assert CampaignPhase.ROLLED_BACK in allowed_transitions(CampaignPhase.CANARY)

    def test_rolled_back_still_owes_learn(self) -> None:
        """Rollback is not terminal — the campaign still learns from failure."""
        assert CampaignPhase.LEARN in allowed_transitions(CampaignPhase.ROLLED_BACK)
        assert not is_terminal(CampaignPhase.ROLLED_BACK)

    def test_terminal_phases_have_no_outgoing_edges(self) -> None:
        assert allowed_transitions(CampaignPhase.LEARN) == frozenset()
        assert allowed_transitions(CampaignPhase.CANCELLED) == frozenset()
        assert is_terminal(CampaignPhase.LEARN)
        assert is_terminal(CampaignPhase.CANCELLED)

    def test_holdout_feedback_cannot_reenter_propose(self) -> None:
        """The revise loop is dev-only: holdout results never feed proposals."""
        assert CampaignPhase.PROPOSE not in allowed_transitions(CampaignPhase.HOLDOUT)
        assert CampaignPhase.PROPOSE in allowed_transitions(CampaignPhase.DEV_EVALUATE)


class TestOrchestratorTransitions:
    def test_legal_transition_persists_a_record(self, orchestrator: CampaignOrchestrator) -> None:
        transition = orchestrator.transition(CampaignPhase.PLAN, reason="spec pinned")
        assert orchestrator.phase is CampaignPhase.PLAN
        assert transition.sequence == 0
        assert transition.from_phase is CampaignPhase.DISCOVER
        assert transition.reason == "spec pinned"
        assert orchestrator.transitions == (transition,)

    def test_sequences_are_gapless_and_append_only(
        self, orchestrator: CampaignOrchestrator
    ) -> None:
        orchestrator.transition(CampaignPhase.PLAN)
        orchestrator.transition(CampaignPhase.PROPOSE)
        assert [t.sequence for t in orchestrator.transitions] == [0, 1]

    def test_illegal_transition_raises_and_records_nothing(
        self, orchestrator: CampaignOrchestrator
    ) -> None:
        with pytest.raises(InvalidTransitionError) as excinfo:
            orchestrator.transition(CampaignPhase.HOLDOUT)
        # DISCOVER's only legal successor is PLAN — the error says so.
        assert excinfo.value.allowed == ("plan",)
        assert orchestrator.phase is CampaignPhase.DISCOVER
        assert orchestrator.transitions == ()

    def test_dev_evaluate_can_loop_back_to_propose(
        self, orchestrator: CampaignOrchestrator
    ) -> None:
        for phase in (CampaignPhase.PLAN, CampaignPhase.PROPOSE, CampaignPhase.DEV_EVALUATE):
            orchestrator.transition(phase)
        transition = orchestrator.transition(CampaignPhase.PROPOSE, reason="dev feedback")
        assert transition.from_phase is CampaignPhase.DEV_EVALUATE
        assert orchestrator.phase is CampaignPhase.PROPOSE


class TestPauseResumeCancel:
    def test_pause_remembers_the_resume_target(self, orchestrator: CampaignOrchestrator) -> None:
        orchestrator.transition(CampaignPhase.PLAN)
        orchestrator.transition(CampaignPhase.PROPOSE)
        orchestrator.pause(reason="operator request")
        assert orchestrator.phase is CampaignPhase.PAUSED
        assert orchestrator.resume_target is CampaignPhase.PROPOSE

    def test_resume_returns_to_the_paused_phase(self, orchestrator: CampaignOrchestrator) -> None:
        orchestrator.transition(CampaignPhase.PLAN)
        orchestrator.pause()
        orchestrator.resume()
        assert orchestrator.phase is CampaignPhase.PLAN
        assert orchestrator.resume_target is None

    def test_double_pause_is_a_refusal_not_a_noop(self, orchestrator: CampaignOrchestrator) -> None:
        orchestrator.pause()
        with pytest.raises(InvalidTransitionError):
            orchestrator.pause()
        # The resume target still points at the original phase.
        assert orchestrator.resume_target is CampaignPhase.DISCOVER

    def test_resume_without_pause_is_a_refusal(self, orchestrator: CampaignOrchestrator) -> None:
        with pytest.raises(InvalidTransitionError):
            orchestrator.resume()

    def test_cancel_is_possible_from_any_nonterminal_phase(
        self, orchestrator: CampaignOrchestrator
    ) -> None:
        assert can_cancel(CampaignPhase.DISCOVER)
        assert can_cancel(CampaignPhase.CANARY)
        assert not can_cancel(CampaignPhase.LEARN)
        orchestrator.cancel(reason="budget reprioritized")
        assert orchestrator.phase is CampaignPhase.CANCELLED
        assert orchestrator.resume_target is None

    def test_cancelled_campaign_cannot_resume(self, orchestrator: CampaignOrchestrator) -> None:
        orchestrator.pause()
        orchestrator.cancel()
        with pytest.raises(InvalidTransitionError):
            orchestrator.resume()

    def test_terminal_phase_cannot_pause(self, orchestrator: CampaignOrchestrator) -> None:
        for phase in (
            CampaignPhase.PLAN,
            CampaignPhase.PROPOSE,
            CampaignPhase.DEV_EVALUATE,
            CampaignPhase.SELECT_FREEZE,
            CampaignPhase.HOLDOUT,
            CampaignPhase.APPROVE,
            CampaignPhase.CANARY,
            CampaignPhase.PROMOTED,
            CampaignPhase.LEARN,
        ):
            orchestrator.transition(phase)
        assert not can_pause(CampaignPhase.LEARN)
        with pytest.raises(InvalidTransitionError):
            orchestrator.pause()


class TestCheckpoints:
    def test_checkpoint_round_trip_preserves_full_state(
        self,
        pinned_spec: PinnedCampaignSpec,
        checkpoint_store: InMemoryCheckpointStore,
    ) -> None:
        orchestrator = CampaignOrchestrator(pinned_spec, checkpoints=checkpoint_store)
        orchestrator.transition(CampaignPhase.PLAN)
        orchestrator.transition(CampaignPhase.PROPOSE)
        orchestrator.pause(reason="maintenance")

        digest = orchestrator.checkpoint()
        revived = CampaignOrchestrator.reconstruct(pinned_spec, checkpoint_store, digest)

        assert revived.phase is CampaignPhase.PAUSED
        assert revived.resume_target is CampaignPhase.PROPOSE
        assert revived.transitions == orchestrator.transitions

    def test_reconstructed_campaign_continues_legally(
        self,
        pinned_spec: PinnedCampaignSpec,
        checkpoint_store: InMemoryCheckpointStore,
    ) -> None:
        orchestrator = CampaignOrchestrator(pinned_spec, checkpoints=checkpoint_store)
        orchestrator.transition(CampaignPhase.PLAN)
        digest = orchestrator.checkpoint()

        revived = CampaignOrchestrator.reconstruct(pinned_spec, checkpoint_store, digest)
        transition = revived.transition(CampaignPhase.PROPOSE)
        # The history continues the original campaign's — the new transition
        # appends after the persisted log (sequence 1), it does not restart.
        assert transition.sequence == 1
        assert transition.from_phase is CampaignPhase.PLAN

    def test_tampered_checkpoint_is_refused(
        self,
        pinned_spec: PinnedCampaignSpec,
        checkpoint_store: InMemoryCheckpointStore,
    ) -> None:
        orchestrator = CampaignOrchestrator(pinned_spec, checkpoints=checkpoint_store)
        orchestrator.transition(CampaignPhase.PLAN)
        digest = orchestrator.checkpoint()

        # Fault injection: the stored bytes no longer hash to their address.
        checkpoint_store.corrupt(digest, b'{"schema_id": "forged"}')
        with pytest.raises(CampaignCheckpointError, match="content address"):
            CampaignOrchestrator.reconstruct(pinned_spec, checkpoint_store, digest)

    def test_checkpoint_from_a_different_spec_is_refused(
        self, checkpoint_store: InMemoryCheckpointStore
    ) -> None:
        first = pin_and_sign(make_spec(), Ed25519PrivateKey.generate())
        # A different spec: digests are content-addressed, so the second
        # campaign must differ in content, not just in signing key.
        second = pin_and_sign(
            replace(make_spec(), name="other-campaign"), Ed25519PrivateKey.generate()
        )
        assert second.digest != first.digest
        orchestrator = CampaignOrchestrator(first, checkpoints=checkpoint_store)
        digest = orchestrator.checkpoint()

        with pytest.raises(CampaignCheckpointError, match="different campaign spec"):
            CampaignOrchestrator.reconstruct(second, checkpoint_store, digest)

    def test_malformed_snapshot_bytes_are_refused(
        self,
        pinned_spec: PinnedCampaignSpec,
        checkpoint_store: InMemoryCheckpointStore,
    ) -> None:
        digest = checkpoint_store.store(b"not json at all", schema_id="bogus")
        with pytest.raises(CampaignCheckpointError, match="not valid JSON"):
            CampaignOrchestrator.reconstruct(pinned_spec, checkpoint_store, digest)

    def test_snapshot_missing_a_field_is_refused(
        self,
        pinned_spec: PinnedCampaignSpec,
        checkpoint_store: InMemoryCheckpointStore,
    ) -> None:
        digest = checkpoint_store.store(
            json.dumps({"schema_id": "x", "phase": "plan"}).encode(), schema_id="x"
        )
        with pytest.raises(CampaignCheckpointError, match="missing"):
            CampaignOrchestrator.reconstruct(pinned_spec, checkpoint_store, digest)


class TestKillResumeFaultInjection:
    """FR-005's fault model: the process dies mid-flight, work resumes."""

    def test_kill_during_dev_loop_resumes_with_intact_history(
        self,
        pinned_spec: PinnedCampaignSpec,
        checkpoint_store: InMemoryCheckpointStore,
    ) -> None:
        survivor = CampaignOrchestrator(pinned_spec, checkpoints=checkpoint_store)
        survivor.transition(CampaignPhase.PLAN)
        survivor.transition(CampaignPhase.PROPOSE)
        survivor.transition(CampaignPhase.DEV_EVALUATE)
        digest = survivor.checkpoint()

        # --- process death: everything after this line is a new process ---
        revived = CampaignOrchestrator.reconstruct(pinned_spec, checkpoint_store, digest)
        assert revived.phase is CampaignPhase.DEV_EVALUATE

        # The revise loop still works: dev feedback returns to propose.
        revived.transition(CampaignPhase.PROPOSE, reason="resumed revise loop")
        assert revived.phase is CampaignPhase.PROPOSE
        assert [t.sequence for t in revived.transitions] == [0, 1, 2, 3]

    def test_kill_while_paused_resumes_paused(
        self,
        pinned_spec: PinnedCampaignSpec,
        checkpoint_store: InMemoryCheckpointStore,
    ) -> None:
        paused = CampaignOrchestrator(pinned_spec, checkpoints=checkpoint_store)
        paused.transition(CampaignPhase.PLAN)
        paused.pause(reason="infra maintenance")
        digest = paused.checkpoint()

        revived = CampaignOrchestrator.reconstruct(pinned_spec, checkpoint_store, digest)
        assert revived.phase is CampaignPhase.PAUSED
        revived.resume()
        assert revived.phase is CampaignPhase.PLAN

    def test_reconstruction_replays_history_into_a_fresh_sink(
        self,
        pinned_spec: PinnedCampaignSpec,
        checkpoint_store: InMemoryCheckpointStore,
    ) -> None:
        original = CampaignOrchestrator(pinned_spec, checkpoints=checkpoint_store)
        original.transition(CampaignPhase.PLAN, reason="planned")
        digest = original.checkpoint()

        sink = InMemoryTransitionSink()
        revived = CampaignOrchestrator.reconstruct(pinned_spec, checkpoint_store, digest, sink=sink)
        # The persisted log landed in the injected sink, replayable.
        assert len(sink.all()) == 1
        assert sink.all()[0].reason == "planned"
        assert revived.transitions == sink.all()

    def test_transitions_round_trip_through_canonical_dicts(self) -> None:
        transition = CampaignTransition(
            sequence=3,
            from_phase=CampaignPhase.CANARY,
            to_phase=CampaignPhase.ROLLED_BACK,
            reason="canary regression",
            at=1234.5,
        )
        assert CampaignTransition.from_canonical_dict(transition.to_canonical_dict()) == (
            transition
        )


class TestPinnedSpecGate:
    def test_orchestrator_refuses_a_tampered_spec(
        self, checkpoint_store: InMemoryCheckpointStore
    ) -> None:
        spec = make_spec()
        pinned = pin_and_sign(spec, Ed25519PrivateKey.generate())
        # Fault injection: edit the spec after pinning — a forged preregistration.
        tampered = PinnedCampaignSpec(
            spec=replace(spec, name="renamed-campaign"),
            digest=pinned.digest,
            signature=pinned.signature,
        )
        with pytest.raises(SpecTamperedError, match="digest or signature"):
            CampaignOrchestrator(tampered, checkpoints=checkpoint_store)
