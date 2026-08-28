"""Compensation planning (Phase 2, F5) — the transaction half of rollback.

A multi-artifact release can leave external state mutated in ways the
pointer rollback cannot undo: a tool registered with an external service,
a workflow hook that already fired. The campaign spec therefore declares a
:class:`CompensationPlanSection` — per-artifact compensating actions, each
classified at authoring time:

- **CAS actions** — ``restore_prior_release_pointer`` and
  ``revoke_artifact``. They need *no extra execution*: the pointer
  restore *is* the release controller's existing atomic rollback CAS,
  and a revoked artifact is undone by the pointer move alone. The
  release controller (E5) remains the only identity that can CAS the
  active release pointer — this module adds no second CAS path.
- **Requires-execution actions** — ``run_compensation_hook``. These run
  an externally declared, digest-pinned hook and must be *evidenced*:
  an unexecuted one blocks promotion.

Three disciplines this module enforces:

**Signed, content-addressed plan records.** ``sign_compensation_plan``
digests and signs the plan's canonical bytes (the same body the F10
``compensation_plans`` table signs); :class:`CompensationPlanStore`
persists them through the checkpoint pattern — stored under their content
address, re-verified on load. A plan whose bytes no longer hash to their
address, or whose signature no longer verifies, is refused, not trusted.

**Execution is evidence, not a flag.** The plan is immutable — the
append-only record cannot be edited to mark an action executed. Executing
a compensation appends a :class:`CompensationExecutionRecord` to an
:class:`ExecutionSink`; the promotion check matches those records against
the plan. Fail-closed classification: any action whose mode is not
``cas`` requires an execution record.

**Gate-first hooks.** The orchestrator consults the
:class:`evoruntime.campaign.machine.CompensationGate` before recording the
APPROVE→CANARY edge (refusing promotion while a requires-execution
compensation is unexecuted) and before recording a rollback edge
(executing declared compensations in declared order). A refusal leaves no
transition in the log — the same discipline as the F3 execution gate.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from evoruntime.campaign.errors import (
    CompensationPlanBuildError,
    CompensationPlanTamperedError,
    UnexecutedCompensationError,
)
from evoruntime.security.signing import DetachedSignature, sign, verify

_DIGEST_PREFIX = "sha256:"

_PLAN_SCHEMA_ID = "evoruntime.compensation.plan/v1"
"""Schema id for signed compensation-plan bytes stored in a checkpoint store."""

#: Execution modes — the F10 record vocabulary, restated here so the
#: campaign package does not import the DB layer.
CAS_MODE = "cas"
REQUIRES_EXECUTION_MODE = "requires_execution"
COMPENSATION_MODES = (CAS_MODE, REQUIRES_EXECUTION_MODE)


class CompensationActionKind(StrEnum):
    """The three compensating actions a spec may declare (F5)."""

    RESTORE_PRIOR_RELEASE_POINTER = "restore_prior_release_pointer"
    """CAS: the release controller's existing rollback move — no extra execution."""

    REVOKE_ARTIFACT = "revoke_artifact"
    """CAS: the pointer move alone removes the artifact from resolution."""

    RUN_COMPENSATION_HOOK = "run_compensation_hook"
    """Requires execution: an externally declared, digest-pinned hook."""


CAS_ACTION_KINDS = frozenset(
    {
        CompensationActionKind.RESTORE_PRIOR_RELEASE_POINTER,
        CompensationActionKind.REVOKE_ARTIFACT,
    }
)
"""Action kinds with no extra execution — the pointer rollback covers them."""

REQUIRES_EXECUTION_ACTION_KINDS = frozenset({CompensationActionKind.RUN_COMPENSATION_HOOK})
"""Action kinds that must be executed and evidenced before promotion."""


def classification_for_action(action: str) -> str:
    """The execution mode an action kind implies.

    Unknown action names classify as requires-execution: a compensating
    action this runtime cannot name might still mutate external state, so
    it is treated as requiring evidence, never waved through.
    """
    try:
        kind = CompensationActionKind(action)
    except ValueError:
        return REQUIRES_EXECUTION_MODE
    return CAS_MODE if kind in CAS_ACTION_KINDS else REQUIRES_EXECUTION_MODE


@dataclass(frozen=True, slots=True)
class CompensationExecutionRecord:
    """Evidence that one declared compensation was executed.

    ``action_index`` is the action's position in the plan's declared
    order — the position, not the digest alone, is what "in order" is
    checked against. ``at`` comes from the injected clock.
    """

    plan_id: str
    action_index: int
    artifact_digest: str
    at: float

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form of this execution record."""
        return {
            "plan_id": self.plan_id,
            "action_index": self.action_index,
            "artifact_digest": self.artifact_digest,
            "at": self.at,
        }

    @classmethod
    def from_canonical_dict(cls, raw: dict[str, Any]) -> CompensationExecutionRecord:
        """Rebuild an execution record from its canonical form."""
        return cls(
            plan_id=str(raw["plan_id"]),
            action_index=int(raw["action_index"]),
            artifact_digest=str(raw["artifact_digest"]),
            at=float(raw["at"]),
        )


class ContentAddressedStore(Protocol):
    """Content-addressed byte store (the campaign checkpoint store's shape).

    Structural on purpose: the machine's ``CheckpointStore`` and any
    production payload store with the same shape plug in unchanged, and
    this module stays importable from the spec without a cycle.
    """

    def store(self, data: bytes, *, schema_id: str) -> str: ...

    def load(self, digest: str) -> bytes: ...


class ExecutionSink(Protocol):
    """Where execution evidence goes. A DB table in production; memory in tests."""

    def append(self, record: CompensationExecutionRecord) -> None: ...

    def all(self) -> tuple[CompensationExecutionRecord, ...]: ...


class InMemoryExecutionSink:
    """Append-only in-memory execution log (tests and tools)."""

    def __init__(self) -> None:
        self._records: list[CompensationExecutionRecord] = []

    def append(self, record: CompensationExecutionRecord) -> None:
        """Append one execution record to the log."""
        self._records.append(record)

    def all(self) -> tuple[CompensationExecutionRecord, ...]:
        """Every execution record, in append order."""
        return tuple(self._records)


def compensation_plan_body(
    *,
    plan_id: str,
    campaign_id: str | None,
    manifest_digest: str | None,
    actions: list[dict[str, Any]],
) -> bytes:
    """Canonical bytes a compensation plan's digest and signature cover.

    Pure: the signed body is exactly the declared plan — id, scope, and
    actions — in a byte-stable form, so a plan whose bytes no longer
    hash to their digest is detectable, not trusted. This is the single
    definition of plan bytes: the F10 API surface and the F5 record type
    both sign over it.
    """
    body = {
        "plan_id": plan_id,
        "campaign_id": campaign_id,
        "manifest_digest": manifest_digest,
        "actions": actions,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def validate_compensation_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validate the F5 action shape: per-artifact compensating actions,
    each CAS or requires-execution, with an executed flag."""
    validated: list[dict[str, Any]] = []
    for index, action in enumerate(actions):
        if not isinstance(action, dict):
            raise CompensationPlanBuildError(f"compensation action #{index} is not an object")
        artifact_digest = action.get("artifact_digest")
        mode = action.get("mode")
        if not isinstance(artifact_digest, str) or not artifact_digest:
            raise CompensationPlanBuildError(
                f"compensation action #{index} declares no artifact_digest"
            )
        if mode not in COMPENSATION_MODES:
            raise CompensationPlanBuildError(
                f"compensation action #{index} mode {mode!r} must be one of "
                f"{', '.join(COMPENSATION_MODES)}"
            )
        validated.append(
            {
                "artifact_digest": artifact_digest,
                "action": str(action.get("action", "")),
                "mode": mode,
                "executed": bool(action.get("executed", False)),
            }
        )
    return validated


@dataclass(frozen=True, slots=True)
class SignedCompensationPlan:
    """A signed compensation plan: the promotion-gating record (F5).

    ``plan_digest`` is the content address of the canonical body. The
    signature and public key are excluded from the digested body by
    construction (they vouch for it, they are not part of it).
    """

    plan_id: str
    campaign_id: str | None
    manifest_digest: str | None
    actions: tuple[dict[str, Any], ...]
    plan_digest: str
    signature: bytes
    signer_public_key: bytes

    def body(self) -> bytes:
        """The canonical bytes this plan's digest and signature cover."""
        return compensation_plan_body(
            plan_id=self.plan_id,
            campaign_id=self.campaign_id,
            manifest_digest=self.manifest_digest,
            actions=list(self.actions),
        )

    def verify(self) -> bool:
        """True when the digest matches the canonical bytes AND the
        signature verifies over them. Either check failing is tampering."""
        if self.plan_digest != _DIGEST_PREFIX + hashlib.sha256(self.body()).hexdigest():
            return False
        return verify(
            DetachedSignature(signature=self.signature, public_key=self.signer_public_key),
            self.body(),
        )


def sign_compensation_plan(
    *,
    plan_id: str,
    campaign_id: str | None,
    manifest_digest: str | None,
    actions: list[dict[str, Any]],
    private_key: Any,
) -> SignedCompensationPlan:
    """Validate, digest, and sign a compensation plan over its canonical bytes.

    The actions are validated into their executable shape first, so a
    plan object is always well-formed; trust still requires ``verify()``
    (or a load through :class:`CompensationPlanStore`).
    """
    validated = validate_compensation_actions(actions)
    body = compensation_plan_body(
        plan_id=plan_id,
        campaign_id=campaign_id,
        manifest_digest=manifest_digest,
        actions=validated,
    )
    detached = sign(private_key, body)
    return SignedCompensationPlan(
        plan_id=plan_id,
        campaign_id=campaign_id,
        manifest_digest=manifest_digest,
        actions=tuple(validated),
        plan_digest=_DIGEST_PREFIX + hashlib.sha256(body).hexdigest(),
        signature=detached.signature,
        signer_public_key=detached.public_key,
    )


class CompensationPlanStore:
    """Content-addressed persistence for signed plans (the checkpoint pattern).

    Plans are stored under the sha256 of their canonical bytes and
    re-verified on load — content address first, then signature. A plan
    that fails either check is a forgery (or corruption), and is refused
    rather than resumed, exactly like a campaign checkpoint.
    """

    def __init__(self, checkpoints: ContentAddressedStore) -> None:
        self._checkpoints = checkpoints

    def save(self, plan: SignedCompensationPlan) -> str:
        """Store the plan under its content address; return that digest.

        The stored bytes are an envelope: the plan's fields plus its
        digest and signature in hex. The envelope's own sha256 is the
        storage address — tampering with the stored bytes is detectable
        at load before anything is parsed, and a plan whose body was
        edited still fails ``verify()`` (digest + signature over the
        canonical body).
        """
        envelope = {
            "schema_id": _PLAN_SCHEMA_ID,
            "plan_id": plan.plan_id,
            "campaign_id": plan.campaign_id,
            "manifest_digest": plan.manifest_digest,
            "actions": list(plan.actions),
            "plan_digest": plan.plan_digest,
            "signature_hex": plan.signature.hex(),
            "signer_public_key_hex": plan.signer_public_key.hex(),
        }
        data = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self._checkpoints.store(data, schema_id=_PLAN_SCHEMA_ID)

    def load(self, digest: str) -> SignedCompensationPlan:
        """Load and verify a plan by content digest.

        Raises:
            CompensationPlanTamperedError: the stored bytes do not hash
                to ``digest``, are not a parseable plan, or the signature
                does not verify — tampering, not a soft failure.
        """
        data = self._checkpoints.load(digest)
        actual = _DIGEST_PREFIX + hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise CompensationPlanTamperedError(
                f"compensation plan {digest} does not hash to its content address "
                f"(stored bytes hash to {actual})"
            )
        try:
            payload = json.loads(data)
            plan = SignedCompensationPlan(
                plan_id=str(payload["plan_id"]),
                campaign_id=payload["campaign_id"],
                manifest_digest=payload["manifest_digest"],
                actions=tuple(dict(action) for action in payload["actions"]),
                plan_digest=str(payload["plan_digest"]),
                signature=bytes.fromhex(payload["signature_hex"]),
                signer_public_key=bytes.fromhex(payload["signer_public_key_hex"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CompensationPlanTamperedError(
                f"compensation plan {digest} is not a parseable signed plan: {exc}"
            ) from exc
        if not plan.verify():
            raise CompensationPlanTamperedError(
                f"compensation plan {digest} failed digest or signature verification"
            )
        return plan


class CompensationExecutor(Protocol):
    """Executes one declared compensation. Raises on failure."""

    def execute(self, action_index: int, action: Mapping[str, Any]) -> None: ...


def execute_rollback_compensations(
    plan: SignedCompensationPlan,
    executor: CompensationExecutor,
    *,
    clock: Any | None = None,
) -> tuple[CompensationExecutionRecord, ...]:
    """Execute the plan's requires-execution compensations, in declared order.

    CAS actions are skipped — by definition they need no extra execution;
    the release controller's pointer rollback covers them. A failing
    executor aborts the walk: the actions before the failure have their
    execution records, the failing one and everything after it do not,
    and the promotion check keeps refusing until the plan is discharged.

    Returns the execution records for the actions actually executed (the
    caller persists them through an :class:`ExecutionSink`).
    """
    records: list[CompensationExecutionRecord] = []
    for index, action in enumerate(plan.actions):
        if action.get("mode") == CAS_MODE:
            continue
        executor.execute(index, action)
        records.append(
            CompensationExecutionRecord(
                plan_id=plan.plan_id,
                action_index=index,
                artifact_digest=str(action.get("artifact_digest", "")),
                at=float(clock.now()) if clock is not None else 0.0,
            )
        )
    return tuple(records)


def assert_promotion_allowed(
    plan: SignedCompensationPlan,
    executions: Sequence[CompensationExecutionRecord],
) -> None:
    """The release-plane promotion check (F5).

    Refuses promotion while any non-CAS compensation in ``plan`` lacks an
    execution record. Fail-closed: an action whose mode is not ``cas``
    requires evidence, and a plan whose bytes no longer verify is tampering,
    not a plan.

    Raises:
        CompensationPlanTamperedError: the plan fails digest or signature
            verification.
        UnexecutedCompensationError: a requires-execution action has no
            matching execution record.
    """
    if not plan.verify():
        raise CompensationPlanTamperedError(
            f"compensation plan {plan.plan_id!r} failed digest or signature "
            "verification — refusing to gate promotion on it"
        )
    executed = {record.action_index for record in executions if record.plan_id == plan.plan_id}
    for index, action in enumerate(plan.actions):
        if action.get("mode") == CAS_MODE:
            continue
        if index not in executed:
            raise UnexecutedCompensationError(
                plan.plan_id,
                index,
                str(action.get("action", "")),
                str(action.get("artifact_digest", "")),
            )


def plan_actions_from_spec(
    spec_actions: Sequence[Any],
    artifact_digests: Mapping[str, str],
) -> list[dict[str, Any]]:
    """Build record actions from a spec's :class:`CompensationPlanSection`.

    The spec classifies by action name; the record carries the derived
    mode. Every action's artifact_type must resolve to a candidate
    artifact digest — a plan that cannot name what it would compensate
    is not buildable.
    """
    actions: list[dict[str, Any]] = []
    for position, spec_action in enumerate(spec_actions):
        digest = artifact_digests.get(spec_action.artifact_type)
        if not digest:
            raise CompensationPlanBuildError(
                f"compensation action #{position} targets {spec_action.artifact_type!r}, "
                "which has no resolved artifact digest — a plan is built from the "
                "candidate's resolved artifact set"
            )
        actions.append(
            {
                "artifact_digest": digest,
                "action": spec_action.action,
                "mode": classification_for_action(spec_action.action),
                "executed": False,
            }
        )
    return actions


class CheckpointedCompensationGate:
    """The concrete :class:`CompensationGate` over a signed plan.

    Backs the orchestrator's APPROVE→CANARY and rollback hooks with the
    persisted evidence: ``approve_canary`` reads the execution sink,
    ``execute_rollback_compensations`` runs the executor in declared
    order and appends the resulting records to the sink.
    """

    def __init__(
        self,
        plan: SignedCompensationPlan,
        *,
        executions: ExecutionSink,
        executor: CompensationExecutor,
        clock: Any | None = None,
    ) -> None:
        self._plan = plan
        self._executions = executions
        self._executor = executor
        self._clock = clock

    @property
    def plan(self) -> SignedCompensationPlan:
        """The plan this gate enforces."""
        return self._plan

    def approve_canary(self) -> None:
        """Refuse the APPROVE→CANARY edge while a requires-execution
        compensation is unexecuted."""
        assert_promotion_allowed(self._plan, self._executions.all())

    def execute_rollback_compensations(self) -> None:
        """Execute declared compensations in order, recording evidence."""
        records = execute_rollback_compensations(self._plan, self._executor, clock=self._clock)
        for record in records:
            self._executions.append(record)


__all__ = [
    "CAS_ACTION_KINDS",
    "CompensationPlanBuildError",
    "ContentAddressedStore",
    "CAS_MODE",
    "COMPENSATION_MODES",
    "REQUIRES_EXECUTION_ACTION_KINDS",
    "REQUIRES_EXECUTION_MODE",
    "CheckpointedCompensationGate",
    "CompensationActionKind",
    "CompensationExecutionRecord",
    "CompensationExecutor",
    "CompensationPlanStore",
    "ExecutionSink",
    "InMemoryExecutionSink",
    "SignedCompensationPlan",
    "assert_promotion_allowed",
    "classification_for_action",
    "compensation_plan_body",
    "execute_rollback_compensations",
    "plan_actions_from_spec",
    "sign_compensation_plan",
    "validate_compensation_actions",
]
