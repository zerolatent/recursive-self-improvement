"""Request-scoped dependencies: the caller's principal and the services.

The principal is built from workload-identity headers that a mesh/sidecar
is expected to set and strip from untrusted ingress. That is a Phase 0
placeholder for real mTLS/SPIFFE identity (deliverable D7) — and it is
called out loudly here rather than silently trusted, because "the header
said evaluator" is not an authentication scheme.

What is *not* a placeholder is everything downstream: the authorization
rules, ledger writes, and denial logging all act on the `Principal`
produced here, so swapping in real identity later changes this module and
nothing else.

"""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session, sessionmaker

from evoruntime.api.approvals import ApprovalWorkflowService
from evoruntime.api.canary import CanaryService
from evoruntime.api.service import CampaignApiService
from evoruntime.core.principal import Principal
from evoruntime.datasets.service import DatasetService, HoldoutService
from evoruntime.db.base import build_engine, build_session_factory
from evoruntime.release import (
    InProcessFleetSimulator,
    RealClock,
    ReleaseController,
    WallClock,
)
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.signing import SigningKeyError, load_evaluator_signing_key
from evoruntime.selection.release_pointer import ReleasePointerStore
from evoruntime.server.settings import get_settings

IDENTITY_HEADER = "x-evoruntime-identity"
ROLE_HEADER = "x-evoruntime-role"
TENANT_HEADER = "x-evoruntime-tenant"


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    """Return the process-wide session factory (one engine per process)."""
    return build_session_factory(build_engine())


SessionFactoryDep = Annotated["sessionmaker[Session]", Depends(get_session_factory)]


def get_dataset_service(session_factory: SessionFactoryDep) -> DatasetService:
    """Return the partition service bound to the injected session factory."""
    return DatasetService(session_factory)


def get_holdout_service(session_factory: SessionFactoryDep) -> HoldoutService:
    """Return the holdout service bound to the injected session factory.

    The session factory arrives via `Depends` rather than a direct call so
    a test can point the whole API at a throwaway database with one
    dependency override — and so the wiring stays visible in one place.
    """
    return HoldoutService(session_factory)


def get_principal(
    x_evoruntime_identity: Annotated[str | None, Header()] = None,
    x_evoruntime_role: Annotated[str | None, Header()] = None,
    x_evoruntime_tenant: Annotated[str | None, Header()] = None,
) -> Principal:
    """Build the caller's principal, rejecting anything unrecognized.

    An unknown role is a 401, never a default: defaulting an unparseable
    role to the least-privileged one would let a typo in a workload's
    config silently turn into a permission the operator never reviewed.
    """
    if not x_evoruntime_identity or not x_evoruntime_role or not x_evoruntime_tenant:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="missing workload identity headers"
        )
    try:
        role = WorkloadRole(x_evoruntime_role)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="unknown workload role"
        ) from None
    identity = WorkloadIdentity(role=role, subject=x_evoruntime_identity)
    return Principal(identity=identity, tenant_id=x_evoruntime_tenant)


def get_campaign_service(session_factory: SessionFactoryDep) -> CampaignApiService:
    """Return the FR-014 control-plane service bound to this deployment.

    The signing key is the evaluation plane's own (loaded through the same
    gated loader every other consumer uses), and the artifact adapter
    command comes from deployment settings — never from a request.
    """
    settings = get_settings()
    server_identity = WorkloadIdentity(
        role=WorkloadRole.EVALUATOR, subject=settings.evaluator_subject
    )
    try:
        signing_key: Ed25519PrivateKey = load_evaluator_signing_key(server_identity)
    except SigningKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"evaluation-plane signing key is not configured: {exc}",
        ) from exc
    adapter_command = tuple(settings.adapter_command.split()) if settings.adapter_command else ()
    return CampaignApiService(
        session_factory,
        signing_key=signing_key,
        evaluator_subject=settings.evaluator_subject,
        adapter_command=adapter_command,
    )


def get_approval_service(session_factory: SessionFactoryDep) -> ApprovalWorkflowService:
    """Return the F10 review-board service bound to this deployment.

    The signing key is the evaluation plane's own, loaded through the
    same gated loader the campaign service uses — admission records are
    governance artifacts, so they are signed by exactly the identity the
    Phase 0 policy check lets sign them.
    """
    settings = get_settings()
    server_identity = WorkloadIdentity(
        role=WorkloadRole.EVALUATOR, subject=settings.evaluator_subject
    )
    try:
        signing_key: Ed25519PrivateKey = load_evaluator_signing_key(server_identity)
    except SigningKeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"evaluation-plane signing key is not configured: {exc}",
        ) from exc
    return ApprovalWorkflowService(
        session_factory,
        signing_key=signing_key,
        evaluator_subject=settings.evaluator_subject,
    )


@lru_cache
def get_release_plane() -> tuple[ReleaseController, InProcessFleetSimulator, WallClock]:
    """Return the process-wide release plane the canary service runs on.

    The pointer store, fleet, and clock are deployment-level singletons:
    pointer state must survive across requests (a canary bootstraps the
    incumbent once and every later run compares against it). The fleet is
    the in-process reference adapter — real fleet wiring (Kubernetes
    rollout, edge invalidation) is deployment-specific (locked decision
    #5) and replaces this at the same seam.
    """
    clock = RealClock()
    fleet = InProcessFleetSimulator(
        worker_count=8,
        latency_sampler=lambda: 2.0,
        clock=clock,
    )
    controller = ReleaseController(
        ReleasePointerStore(),
        WorkloadIdentity(
            role=WorkloadRole.RELEASE_CONTROLLER,
            subject="evoruntime-release-controller",
        ),
    )
    return controller, fleet, clock


ReleasePlaneDep = Annotated[
    tuple[ReleaseController, InProcessFleetSimulator, WallClock],
    Depends(get_release_plane),
]


def get_canary_service(
    session_factory: SessionFactoryDep,
    releases: CampaignServiceDep,
    plane: ReleasePlaneDep,
) -> CanaryService:
    """Return the H6 canary monitoring service bound to this deployment.

    The release plane arrives through `Depends` (not a direct call) so
    dependency overrides — tests swap in a fresh plane per test — are
    honored.
    """
    controller, fleet, clock = plane
    return CanaryService(
        session_factory,
        releases=releases,
        controller=controller,
        fleet=fleet,
        clock=clock,
    )


PrincipalDep = Annotated[Principal, Depends(get_principal)]
DatasetServiceDep = Annotated[DatasetService, Depends(get_dataset_service)]
HoldoutServiceDep = Annotated[HoldoutService, Depends(get_holdout_service)]
CampaignServiceDep = Annotated[CampaignApiService, Depends(get_campaign_service)]
CanaryServiceDep = Annotated[CanaryService, Depends(get_canary_service)]
ApprovalServiceDep = Annotated[ApprovalWorkflowService, Depends(get_approval_service)]
