"""The canary monitoring service (H6, PRD §17.1 steps 8–9).

The fixed-horizon canary harness is library code; this module is the
operational surface around it. Three things the library deliberately does
not do live here:

- **Admission** — a canary run starts with the eligibility predicate over
  the release's resolved artifact classes
  (:func:`~evoruntime.release.eligibility.assert_canary_eligible`). A
  release whose resolved set is not read-only or transactionally
  reversible is refused before any canary machinery runs, because the
  harness's only undo is the pointer rollback.
- **Candidate-state namespacing** — the service wraps the fleet adapter
  with its own arm→namespace enforcement
  (:class:`ServiceNamespacedFleet`). The in-process simulator enforces
  the same rule, but that enforcement is the test harness's; a service
  cannot borrow its guarantees from test code. The wrapper tracks each
  session's arm as the service pins it and refuses any state write whose
  namespace does not match the session's own arm before the inner
  adapter sees it.
- **Severity-1 auto-rollback driving release/rollback** — when the
  harness ends ``rolled_back`` (a deterministic severity-1 guardrail
  event stopped the horizon), the service drives the control plane's
  release rollback path, so the activation ledger records what the
  runtime plane already did: the candidate rolled back, the prior
  release active again.

Run measurements land in the append-only ``canary_runs`` table; the
release activation ledger stays the authority on pointer state.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from evoruntime.api.errors import ReleaseNotFoundError, ReleaseStateError
from evoruntime.api.schemas import CanaryRunView, CanaryStatusView
from evoruntime.api.service import CampaignApiService
from evoruntime.core.principal import Principal
from evoruntime.db.base import session_scope
from evoruntime.db.models.campaign import CanaryRun, ReleaseActivation
from evoruntime.db.models.registry import ReleaseManifest
from evoruntime.registry.service import RegistryService
from evoruntime.release import (
    CANDIDATE_NAMESPACE,
    INCUMBENT_NAMESPACE,
    CanaryConfig,
    CanaryFleet,
    CanaryHarness,
    CanaryOutcome,
    CanaryResult,
    GuardrailEvent,
    ReleaseController,
    SessionArm,
    SignedReleaseManifest,
    UnknownSessionError,
    WallClock,
    assert_canary_eligible,
    verify_release_manifest,
)
from evoruntime.release.errors import NamespaceViolationError, NoActiveReleaseError
from evoruntime.selection.authority import ResolvedRelease


class ServiceNamespacedFleet:
    """The service-level candidate-state namespacing boundary (H6).

    Wraps the deployment's fleet adapter: every session's arm is tracked
    as the service pins it, and a state write whose namespace does not
    match the session's own arm is refused with
    :class:`NamespaceViolationError` *before* the inner adapter sees it.
    Candidate sessions write candidate state only — incumbent memory is
    out of reach at the service boundary, not only inside the test
    simulator.
    """

    def __init__(self, inner: CanaryFleet) -> None:
        self._inner = inner
        self._arms: dict[str, SessionArm] = {}

    # -- FleetAdapter operations, with arm tracking at the pin boundary --

    def pin_session(
        self, session_id: str, manifest_digest: str, *, arm: SessionArm = "incumbent"
    ) -> None:
        self._arms[session_id] = arm
        self._inner.pin_session(session_id, manifest_digest, arm=arm)

    def resolve_manifest(self, session_id: str) -> str:
        return self._inner.resolve_manifest(session_id)

    def report_digest(self, session_id: str, manifest_digest: str) -> None:
        self._inner.report_digest(session_id, manifest_digest)

    def invalidate_caches(self, manifest_digest: str) -> None:
        self._inner.invalidate_caches(manifest_digest)

    # -- Namespaced candidate state, enforced here, delegated below --

    def write_state(self, session_id: str, key: str, value: object, *, namespace: str) -> None:
        """Write session state, refusing any cross-namespace write.

        The namespace a session may write into is fixed by the arm the
        service pinned it under — the same rule the fleet simulator
        enforces, restated where production writes enter.
        """
        arm = self._arms.get(session_id)
        if arm is None:
            raise UnknownSessionError(session_id, "write state")
        allowed = CANDIDATE_NAMESPACE if arm == "candidate" else INCUMBENT_NAMESPACE
        if namespace != allowed:
            raise NamespaceViolationError(session_id, namespace, allowed)
        self._inner.write_state(session_id, key, value, namespace=namespace)

    # -- FR-012 measurement surfaces, delegated --

    def digest_report_coverage(self, *, expected_sessions: set[str] | None = None) -> float:
        return self._inner.digest_report_coverage(expected_sessions=expected_sessions)

    def p99_convergence_seconds(self) -> float:
        return self._inner.p99_convergence_seconds()


class CanaryService:
    """The canary monitoring service bound to one deployment's release
    plane: a release controller, a fleet adapter, and a clock, plus the
    control-plane service whose rollback path a severity-1 event drives.
    """

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        releases: CampaignApiService,
        controller: ReleaseController,
        fleet: CanaryFleet,
        clock: WallClock,
        config: CanaryConfig | None = None,
    ) -> None:
        self._session_factory = session_factory
        self._releases = releases
        self._controller = controller
        self._fleet = fleet
        self._clock = clock
        self._default_config = config or CanaryConfig()

    # ------------------------------------------------------------------
    # Operations
    # ------------------------------------------------------------------

    def start_canary(
        self,
        principal: Principal,
        manifest_digest: str,
        *,
        config: CanaryConfig | None = None,
        guardrail_events: Sequence[GuardrailEvent] = (),
    ) -> CanaryRunView:
        """Admit and run one fixed-horizon canary for ``manifest_digest``.

        Admission is two gates in order: the release must be in canary
        status, and its resolved artifact classes must be canary-eligible
        (read-only or transactionally reversible). Then the harness runs
        against the deployment's release plane; a severity-1 outcome
        drives the control plane's release rollback before the view is
        returned.
        """
        run_config = config or self._default_config
        with session_scope(self._session_factory) as session:
            manifest_row = self._require_manifest(session, principal.tenant_id, manifest_digest)
            latest = self._latest_activation(session, principal.tenant_id, manifest_digest)
            if latest is None or latest.status != "canary":
                raise ReleaseStateError(
                    f"release {manifest_digest} is not in canary — a canary run compares "
                    "a canary-status release against the active incumbent"
                )
            # H6 admission gate: eligibility over the resolved artifact
            # classes. A refusal here means nothing runs and nothing is
            # recorded — the canary never existed.
            assert_canary_eligible(
                self._resolved_release(session, principal.tenant_id, manifest_row)
            )
            candidate = self._reconstruct_manifest(manifest_row)
            self._ensure_incumbent_active(session, principal.tenant_id, candidate)

        # The harness advances the clock and moves the release-plane
        # pointer; it runs outside the DB transaction, then the run row
        # records what it measured.
        harness = CanaryHarness(
            config=run_config,
            controller=self._controller,
            fleet=ServiceNamespacedFleet(self._fleet),
            clock=self._clock,
        )
        result = harness.run(candidate, guardrail_events)
        view = self._record_run(principal, manifest_digest, run_config=run_config, result=result)

        if result.outcome is CanaryOutcome.ROLLED_BACK:
            # Severity-1 auto-rollback drives the control plane's release
            # rollback path: the activation ledger records the rollback
            # and restores the prior release to active.
            self._releases.rollback_release(principal, manifest_digest)
        return self._with_release_status(principal, view)

    def canary_status(self, principal: Principal, manifest_digest: str) -> CanaryStatusView:
        """Where a release stands with respect to its canary runs."""
        with session_scope(self._session_factory) as session:
            self._require_manifest(session, principal.tenant_id, manifest_digest)
            latest_activation = self._latest_activation(
                session, principal.tenant_id, manifest_digest
            )
            run_row = session.execute(
                select(CanaryRun)
                .where(
                    CanaryRun.tenant_id == principal.tenant_id,
                    CanaryRun.manifest_digest == manifest_digest,
                )
                .order_by(CanaryRun.created_at.desc())
                .limit(1)
            ).scalar_one_or_none()
            return CanaryStatusView(
                manifest_digest=manifest_digest,
                release_status=latest_activation.status if latest_activation else None,
                latest_run=_run_view(run_row) if run_row else None,
            )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _record_run(
        self,
        principal: Principal,
        manifest_digest: str,
        *,
        run_config: CanaryConfig,
        result: CanaryResult,
    ) -> CanaryRunView:
        """Append the run's measurements to the canary_runs ledger."""
        run_id = f"canary-{uuid.uuid4().hex[:12]}"
        row = CanaryRun(
            tenant_id=principal.tenant_id,
            manifest_digest=manifest_digest,
            run_id=run_id,
            outcome=result.outcome.value,
            config=_config_payload(run_config),
            result=_result_payload(result),
            started_by=principal.identity_id,
        )
        with session_scope(self._session_factory) as session:
            session.add(row)
        return _run_view(row)

    def _with_release_status(self, principal: Principal, view: CanaryRunView) -> CanaryRunView:
        """Attach the release's post-run activation status to the view."""
        status = self.canary_status(principal, view.manifest_digest).release_status
        return view.model_copy(update={"release_status": status})

    def _ensure_incumbent_active(
        self, session: Session, tenant_id: str, candidate: SignedReleaseManifest
    ) -> str:
        """Bootstrap the release-plane pointer from the activation ledger
        and verify the canary's declared incumbent is what is active.

        The pointer is the runtime plane's authority; the DB ledger is the
        control plane's record. When the pointer has never been set, the
        ledger's active release is activated onto it through the
        controller (the same CAS any other activation rides). Either way,
        a canary may only compare its candidate against the incumbent it
        declares as its prior release — that is the release a severity-1
        rollback returns to.
        """
        active = self._controller.active_digest()
        if active is None:
            incumbent_row = session.execute(
                select(ReleaseActivation)
                .where(
                    ReleaseActivation.tenant_id == tenant_id,
                    ReleaseActivation.status == "active",
                )
                .order_by(ReleaseActivation.created_at.desc())
                .limit(1)
            ).scalar_one_or_none()
            if incumbent_row is None:
                raise NoActiveReleaseError(
                    "no active release — a canary compares a candidate against an "
                    "incumbent, and there is no incumbent to compare against"
                )
            incumbent = self._require_manifest(session, tenant_id, incumbent_row.manifest_digest)
            self._controller.activate(self._reconstruct_manifest(incumbent))
            active = self._controller.active_digest()
        if candidate.prior_release_digest is None:
            raise ReleaseStateError(
                f"release {candidate.manifest_digest} has no prior release — a canary "
                "compares a change against its declared incumbent, and severity-1 "
                "auto-rollback needs that incumbent to return to"
            )
        if candidate.prior_release_digest != active:
            raise ReleaseStateError(
                f"release {candidate.manifest_digest} declares prior release "
                f"{candidate.prior_release_digest} but the active release is "
                f"{active} — a canary compares against its own declared incumbent"
            )
        return active

    def _resolved_release(
        self, session: Session, tenant_id: str, manifest_row: ReleaseManifest
    ) -> ResolvedRelease:
        """The resolved release view the eligibility predicate judges:
        each artifact digest's registered class, in manifest order."""
        registry = RegistryService(session)
        classes = tuple(
            registry.get_artifact(tenant_id=tenant_id, digest=str(digest)).artifact_type
            for digest in manifest_row.artifact_digests
        )
        return ResolvedRelease(artifact_classes=classes)

    def _reconstruct_manifest(self, row: ReleaseManifest) -> SignedReleaseManifest:
        """Rebuild the signed manifest value object from its DB row and
        re-verify the signature — a row whose bytes no longer verify is
        not the release anyone approved, and is refused."""
        manifest = SignedReleaseManifest(
            manifest_digest=row.manifest_digest,
            artifact_digests=tuple(str(d) for d in row.artifact_digests),
            adapter_versions=dict(row.adapter_versions),
            model_routes=dict(row.model_routes),
            policies=dict(row.policies),
            prior_release_digest=row.prior_release_digest,
            signature=row.signature,
            signer_public_key=row.signer_public_key,
        )
        verify_release_manifest(manifest)
        return manifest

    def _require_manifest(
        self, session: Session, tenant_id: str, manifest_digest: str
    ) -> ReleaseManifest:
        row = session.execute(
            select(ReleaseManifest).where(
                ReleaseManifest.tenant_id == tenant_id,
                ReleaseManifest.manifest_digest == manifest_digest,
            )
        ).scalar_one_or_none()
        if row is None:
            raise ReleaseNotFoundError(f"no release manifest {manifest_digest!r} in this tenant")
        return row

    def _latest_activation(
        self, session: Session, tenant_id: str, manifest_digest: str
    ) -> ReleaseActivation | None:
        return session.execute(
            select(ReleaseActivation)
            .where(
                ReleaseActivation.tenant_id == tenant_id,
                ReleaseActivation.manifest_digest == manifest_digest,
            )
            .order_by(ReleaseActivation.created_at.desc())
            .limit(1)
        ).scalar_one_or_none()


def _config_payload(config: CanaryConfig) -> dict[str, object]:
    """The canary's preregistered shape, as stored alongside the result."""
    return {
        "min_paired_tasks": config.min_paired_tasks,
        "max_candidate_allocation": config.max_candidate_allocation,
        "observation_horizon_seconds": config.observation_horizon.total_seconds(),
        "seed": config.seed,
    }


def _result_payload(result: CanaryResult) -> dict[str, object]:
    """The harness result, verbatim, in JSONB-safe primitives."""
    return {
        "paired_tasks": result.paired_tasks,
        "total_sessions": result.total_sessions,
        "candidate_sessions": result.candidate_sessions,
        "candidate_allocation": result.candidate_allocation,
        "stopped_reason": result.stopped_reason,
        "rolled_back_to": result.rolled_back_to,
        "digest_report_coverage": result.digest_report_coverage,
        "p99_convergence_seconds": result.p99_convergence_seconds,
        "observation_elapsed_seconds": result.observation_elapsed.total_seconds(),
        "guardrail_events": [
            {
                "severity": event.severity,
                "kind": event.kind,
                "task_index": event.task_index,
                "detail": event.detail,
            }
            for event in result.guardrail_events
        ],
    }


def _json_int(result: dict[str, Any], key: str) -> int:
    """An int field of the stored JSONB result, tolerating a missing key."""
    value = result.get(key, 0)
    return int(value) if isinstance(value, (int, float)) else 0


def _json_float(result: dict[str, Any], key: str) -> float:
    """A float field of the stored JSONB result, tolerating a missing key."""
    value = result.get(key, 0.0)
    return float(value) if isinstance(value, (int, float)) else 0.0


def _json_str(result: dict[str, Any], key: str) -> str | None:
    """A nullable string field of the stored JSONB result."""
    value = result.get(key)
    return value if isinstance(value, str) else None


def _json_float_or_none(result: dict[str, Any], key: str) -> float | None:
    """A nullable float field of the stored JSONB result."""
    value = result.get(key)
    return float(value) if isinstance(value, (int, float)) else None


def _json_events(result: dict[str, Any]) -> list[dict[str, Any]]:
    """The guardrail-event list of the stored JSONB result."""
    value = result.get("guardrail_events", [])
    return [event for event in value if isinstance(event, dict)] if isinstance(value, list) else []


def _run_view(row: CanaryRun) -> CanaryRunView:
    """The read-side projection of one canary run row."""
    result: dict[str, Any] = dict(row.result)
    return CanaryRunView(
        run_id=row.run_id,
        manifest_digest=row.manifest_digest,
        outcome=row.outcome,
        paired_tasks=_json_int(result, "paired_tasks"),
        total_sessions=_json_int(result, "total_sessions"),
        candidate_sessions=_json_int(result, "candidate_sessions"),
        candidate_allocation=_json_float(result, "candidate_allocation"),
        stopped_reason=_json_str(result, "stopped_reason"),
        rolled_back_to=_json_str(result, "rolled_back_to"),
        digest_report_coverage=_json_float(result, "digest_report_coverage"),
        p99_convergence_seconds=_json_float_or_none(result, "p99_convergence_seconds"),
        observation_elapsed_seconds=_json_float(result, "observation_elapsed_seconds"),
        guardrail_events=_json_events(result),
        created_at=row.created_at,
    )


__all__ = [
    "CanaryService",
    "ServiceNamespacedFleet",
]
