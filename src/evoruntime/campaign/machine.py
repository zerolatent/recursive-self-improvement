"""The §11 campaign lifecycle state machine and its orchestrator (FR-005).

The lifecycle is a fixed graph — Discover→Plan→Propose→DevEvaluate→
Select/Freeze→Holdout→Approve→Canary→Promote/Rollback→Learn — with one
revision edge (DevEvaluate→Propose, the strategy's dev-feedback loop) and
two control states (Paused, Cancelled) that are not phases of the search
but states of the *campaign record*.

Three properties the machine guarantees, because a lifecycle that can be
paused and reconstructed is only trustworthy if its history is:

**Persisted transitions.** Every transition is an immutable record
appended to a sink. The log is the campaign's history; the current phase
is derivable from it, never stored as independent truth.

**Content-addressed checkpoints.** `checkpoint()` serializes the full
state — phase, resume target, transition log — into bytes, hashes them,
and stores them under that digest. `reconstruct()` reloads, re-verifies
the digest, and rebuilds an orchestrator. A killed process (the fault
injection the tests exercise) resumes from the checkpoint with an intact
history, because the history *is* the checkpoint.

**A pinned spec or no campaign.** The orchestrator refuses to construct
from anything but a `PinnedCampaignSpec` whose digest and signature still
verify — pin + sign happens before search begins, and the machine holds
that line on every construction, including reconstruction.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from evoruntime.campaign.errors import (
    CampaignCheckpointError,
    InvalidTransitionError,
    SpecTamperedError,
)
from evoruntime.campaign.spec import PinnedCampaignSpec
from evoruntime.eval.budgets import Clock

_SNAPSHOT_SCHEMA_ID = "evoruntime.campaign.snapshot/v1"
"""Schema id for campaign snapshot bytes stored in a checkpoint store."""

_DIGEST_PREFIX = "sha256:"


class CampaignPhase(StrEnum):
    """The §11 lifecycle phases plus the two control states."""

    DISCOVER = "discover"
    """New traces and feedback are collected; nothing is proposed yet."""

    PLAN = "plan"
    """The spec is pinned, budgets resolved, arms and datasets bound."""

    PROPOSE = "propose"
    """The strategy proposes candidates from redacted evidence."""

    DEV_EVALUATE = "dev_evaluate"
    """Candidates run on the dev partition; feedback feeds the revise loop."""

    SELECT_FREEZE = "select_freeze"
    """The trusted selector freezes one nominee per arm (E4's gate)."""

    HOLDOUT = "holdout"
    """Sealed holdout evaluation under the alpha budget, via the D5 ledger."""

    APPROVE = "approve"
    """Tier gates and the preregistered promotion policy are applied."""

    CANARY = "canary"
    """The signed release canaries at a fixed horizon (E5's gate)."""

    PROMOTED = "promoted"
    """The candidate release is now active; rollback remains possible."""

    ROLLED_BACK = "rolled_back"
    """The incumbent release was restored atomically."""

    LEARN = "learn"
    """Terminal: outcomes feed the next campaign's discovery phase."""

    PAUSED = "paused"
    """Control state: the campaign is suspended, resumable to its prior phase."""

    CANCELLED = "cancelled"
    """Control state: the campaign is stopped for good."""


_FORWARD_EDGES: dict[CampaignPhase, frozenset[CampaignPhase]] = {
    CampaignPhase.DISCOVER: frozenset({CampaignPhase.PLAN}),
    CampaignPhase.PLAN: frozenset({CampaignPhase.PROPOSE}),
    CampaignPhase.PROPOSE: frozenset({CampaignPhase.DEV_EVALUATE}),
    # The revise loop: dev feedback (never holdout feedback) returns the
    # campaign to proposing.
    CampaignPhase.DEV_EVALUATE: frozenset({CampaignPhase.PROPOSE, CampaignPhase.SELECT_FREEZE}),
    CampaignPhase.SELECT_FREEZE: frozenset({CampaignPhase.HOLDOUT}),
    CampaignPhase.HOLDOUT: frozenset({CampaignPhase.APPROVE}),
    CampaignPhase.APPROVE: frozenset({CampaignPhase.CANARY, CampaignPhase.ROLLED_BACK}),
    CampaignPhase.CANARY: frozenset({CampaignPhase.PROMOTED, CampaignPhase.ROLLED_BACK}),
    CampaignPhase.PROMOTED: frozenset({CampaignPhase.LEARN}),
    CampaignPhase.ROLLED_BACK: frozenset({CampaignPhase.LEARN}),
    CampaignPhase.LEARN: frozenset(),
    CampaignPhase.PAUSED: frozenset(),
    CampaignPhase.CANCELLED: frozenset(),
}
"""The transition table. One source of truth for the machine, the tests,
and the error messages — an edge that exists nowhere else cannot drift."""

_TERMINAL_PHASES: frozenset[CampaignPhase] = frozenset(
    {CampaignPhase.LEARN, CampaignPhase.CANCELLED}
)
"""Phases with no outgoing edges. LEARN is the lifecycle's end; CANCELLED
is the operator's. PROMOTED and ROLLED_BACK are *not* terminal — both
still owe the campaign a LEARN transition."""


def allowed_transitions(phase: CampaignPhase) -> frozenset[CampaignPhase]:
    """Phases reachable in one legal transition from `phase`."""
    return _FORWARD_EDGES[phase]


def is_terminal(phase: CampaignPhase) -> bool:
    """True when the campaign can take no further transition."""
    return phase in _TERMINAL_PHASES


def can_pause(phase: CampaignPhase) -> bool:
    """True when the campaign may be suspended from this phase.

    Terminal phases cannot pause (there is nothing to resume), and PAUSED
    cannot pause again — pause is idempotent by refusal, not by no-op, so
    a double-pause is a caller bug that surfaces instead of hiding.
    """
    return not is_terminal(phase) and phase is not CampaignPhase.PAUSED


def can_cancel(phase: CampaignPhase) -> bool:
    """True when the campaign may be cancelled from this phase."""
    return not is_terminal(phase)


@dataclass(frozen=True, slots=True)
class CampaignTransition:
    """One persisted lifecycle transition.

    `sequence` is the transition's index in the campaign's history —
    append-only, gapless, replayable. `at` comes from the injected clock
    so tests are deterministic.
    """

    sequence: int
    from_phase: CampaignPhase
    to_phase: CampaignPhase
    reason: str
    at: float

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form of this transition."""
        return {
            "sequence": self.sequence,
            "from_phase": self.from_phase.value,
            "to_phase": self.to_phase.value,
            "reason": self.reason,
            "at": self.at,
        }

    @classmethod
    def from_canonical_dict(cls, raw: dict[str, Any]) -> CampaignTransition:
        """Rebuild a transition from its canonical form."""
        return cls(
            sequence=int(raw["sequence"]),
            from_phase=CampaignPhase(raw["from_phase"]),
            to_phase=CampaignPhase(raw["to_phase"]),
            reason=str(raw["reason"]),
            at=float(raw["at"]),
        )


class TransitionSink(Protocol):
    """Where persisted transitions go. A DB table in production; memory in tests."""

    def append(self, transition: CampaignTransition) -> None: ...

    def all(self) -> tuple[CampaignTransition, ...]: ...


class InMemoryTransitionSink:
    """Append-only in-memory transition log (tests and tools)."""

    def __init__(self) -> None:
        self._transitions: list[CampaignTransition] = []

    def append(self, transition: CampaignTransition) -> None:
        """Append one transition to the log."""
        self._transitions.append(transition)

    def all(self) -> tuple[CampaignTransition, ...]:
        """Every transition, in append order."""
        return tuple(self._transitions)


class CheckpointStore(Protocol):
    """Content-addressed byte store (store + load by digest)."""

    def store(self, data: bytes, *, schema_id: str) -> str: ...

    def load(self, digest: str) -> bytes: ...


class CampaignOrchestrator:
    """Drives one campaign through the §11 lifecycle.

    Holds the pinned spec (verified at every construction), the current
    phase, the resume target for pause/resume, and the persisted
    transition log. Checkpointing and reconstruction are how the
    orchestrator survives process death: the checkpoint bytes carry the
    full history, so a reconstructed campaign is the same campaign, not a
    lookalike.
    """

    def __init__(
        self,
        pinned_spec: PinnedCampaignSpec,
        *,
        checkpoints: CheckpointStore,
        sink: TransitionSink | None = None,
        clock: Clock | None = None,
        initial_phase: CampaignPhase = CampaignPhase.DISCOVER,
        resume_target: CampaignPhase | None = None,
        transitions: tuple[CampaignTransition, ...] = (),
    ) -> None:
        if not pinned_spec.verify():
            raise SpecTamperedError(
                "campaign spec failed digest or signature verification — refusing to run"
            )
        self._pinned_spec = pinned_spec
        self._checkpoints = checkpoints
        self._sink = sink if sink is not None else InMemoryTransitionSink()
        self._clock = clock
        self._phase = initial_phase
        self._resume_target = resume_target
        for transition in transitions:
            self._sink.append(transition)

    # -- state --------------------------------------------------------------

    @property
    def pinned_spec(self) -> PinnedCampaignSpec:
        """The verified, signed spec this campaign runs under."""
        return self._pinned_spec

    @property
    def phase(self) -> CampaignPhase:
        """The campaign's current phase."""
        return self._phase

    @property
    def resume_target(self) -> CampaignPhase | None:
        """The phase a paused campaign returns to (None unless paused)."""
        return self._resume_target

    @property
    def transitions(self) -> tuple[CampaignTransition, ...]:
        """The persisted transition history, in append order."""
        return self._sink.all()

    def _now(self) -> float:
        return self._clock.now() if self._clock is not None else 0.0

    # -- transitions ----------------------------------------------------------

    def transition(self, to_phase: CampaignPhase, *, reason: str = "") -> CampaignTransition:
        """Move the campaign one legal edge forward, persisting the record.

        Raises:
            InvalidTransitionError: the edge does not exist in the
                transition table. Nothing is recorded.
        """
        allowed = _FORWARD_EDGES[self._phase]
        if to_phase not in allowed:
            raise InvalidTransitionError(
                self._phase.value, to_phase.value, tuple(p.value for p in sorted(allowed))
            )
        return self._record(self._phase, to_phase, reason)

    def pause(self, *, reason: str = "") -> CampaignTransition:
        """Suspend the campaign, remembering where it resumes to.

        Raises:
            InvalidTransitionError: the campaign is terminal or already
                paused.
        """
        if not can_pause(self._phase):
            raise InvalidTransitionError(
                self._phase.value,
                CampaignPhase.PAUSED.value,
                ("nothing — terminal phase" if is_terminal(self._phase) else "already paused",),
            )
        self._resume_target = self._phase
        return self._record(self._phase, CampaignPhase.PAUSED, reason)

    def resume(self, *, reason: str = "") -> CampaignTransition:
        """Wake a paused campaign at the phase it paused in.

        Raises:
            InvalidTransitionError: the campaign is not paused.
        """
        if self._phase is not CampaignPhase.PAUSED or self._resume_target is None:
            raise InvalidTransitionError(self._phase.value, "resume", ("nothing — not paused",))
        target = self._resume_target
        self._resume_target = None
        return self._record(CampaignPhase.PAUSED, target, reason)

    def cancel(self, *, reason: str = "") -> CampaignTransition:
        """Stop the campaign for good.

        Raises:
            InvalidTransitionError: the campaign is already terminal.
        """
        if not can_cancel(self._phase):
            raise InvalidTransitionError(
                self._phase.value, CampaignPhase.CANCELLED.value, ("nothing — terminal phase",)
            )
        self._resume_target = None
        return self._record(self._phase, CampaignPhase.CANCELLED, reason)

    def _record(
        self, from_phase: CampaignPhase, to_phase: CampaignPhase, reason: str
    ) -> CampaignTransition:
        transition = CampaignTransition(
            sequence=len(self._sink.all()),
            from_phase=from_phase,
            to_phase=to_phase,
            reason=reason,
            at=self._now(),
        )
        self._sink.append(transition)
        self._phase = to_phase
        return transition

    # -- checkpointing (FR-005) ---------------------------------------------

    def checkpoint(self) -> str:
        """Serialize full campaign state to a content-addressed checkpoint.

        The snapshot carries the spec digest, current phase, resume
        target, and the complete transition log — everything
        `reconstruct` needs to rebuild an identical orchestrator. Returns
        the content digest the snapshot is stored under.
        """
        payload = {
            "schema_id": _SNAPSHOT_SCHEMA_ID,
            "spec_digest": self._pinned_spec.digest,
            "phase": self._phase.value,
            "resume_target": self._resume_target.value if self._resume_target else None,
            "transitions": [t.to_canonical_dict() for t in self.transitions],
        }
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self._checkpoints.store(data, schema_id=_SNAPSHOT_SCHEMA_ID)

    @classmethod
    def reconstruct(
        cls,
        pinned_spec: PinnedCampaignSpec,
        checkpoints: CheckpointStore,
        digest: str,
        *,
        sink: TransitionSink | None = None,
        clock: Clock | None = None,
    ) -> CampaignOrchestrator:
        """Rebuild an orchestrator from a content-addressed checkpoint.

        The digest is verified against the loaded bytes before anything is
        parsed — a checkpoint that does not hash to its own address is
        refused, not resumed (FR-005's integrity half).

        Raises:
            CampaignCheckpointError: the digest does not match the stored
                bytes, or the snapshot is malformed or names a different
                spec.
            SpecTamperedError: the pinned spec no longer verifies.
        """
        data = checkpoints.load(digest)
        actual = _DIGEST_PREFIX + hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise CampaignCheckpointError(
                f"checkpoint {digest} does not hash to its content address "
                f"(stored bytes hash to {actual})"
            )
        payload = _parse_snapshot(data)
        if payload["spec_digest"] != pinned_spec.digest:
            raise CampaignCheckpointError(
                "checkpoint belongs to a different campaign spec "
                f"({payload['spec_digest']}, expected {pinned_spec.digest})"
            )
        return cls(
            pinned_spec,
            checkpoints=checkpoints,
            sink=sink,
            clock=clock,
            initial_phase=CampaignPhase(payload["phase"]),
            resume_target=(
                CampaignPhase(payload["resume_target"])
                if payload["resume_target"] is not None
                else None
            ),
            transitions=tuple(
                CampaignTransition.from_canonical_dict(raw) for raw in payload["transitions"]
            ),
        )


def _parse_snapshot(data: bytes) -> dict[str, Any]:
    """Parse and shape-check snapshot bytes."""
    try:
        payload = json.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise CampaignCheckpointError(f"checkpoint bytes are not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise CampaignCheckpointError("checkpoint payload is not an object")
    for key in ("spec_digest", "phase", "resume_target", "transitions"):
        if key not in payload:
            raise CampaignCheckpointError(f"checkpoint payload is missing {key!r}")
    if not isinstance(payload["transitions"], list):
        raise CampaignCheckpointError("checkpoint transitions must be a list")
    return payload


__all__ = [
    "CampaignOrchestrator",
    "CampaignPhase",
    "CampaignTransition",
    "CheckpointStore",
    "InMemoryTransitionSink",
    "TransitionSink",
    "allowed_transitions",
    "can_cancel",
    "can_pause",
    "is_terminal",
]
