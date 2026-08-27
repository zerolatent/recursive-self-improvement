"""Request-scoped dependencies: the caller's principal and the dataset services.

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

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.orm import Session, sessionmaker

from evoruntime.core.identity import Principal, Role
from evoruntime.datasets.service import DatasetService, HoldoutService
from evoruntime.db.base import build_engine, build_session_factory

IDENTITY_HEADER = "x-evoruntime-identity"
ROLE_HEADER = "x-evoruntime-role"
TENANT_HEADER = "x-evoruntime-tenant"


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    """Return the process-wide session factory (one engine per process)."""
    return build_session_factory(build_engine())


def get_dataset_service() -> DatasetService:
    """Return the partition service bound to the process session factory."""
    return DatasetService(get_session_factory())


def get_holdout_service() -> HoldoutService:
    """Return the holdout service bound to the process session factory."""
    return HoldoutService(get_session_factory())


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
        role = Role(x_evoruntime_role)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="unknown workload role"
        ) from None
    return Principal(
        identity_id=x_evoruntime_identity, role=role, tenant_id=x_evoruntime_tenant
    )


PrincipalDep = Annotated[Principal, Depends(get_principal)]
DatasetServiceDep = Annotated[DatasetService, Depends(get_dataset_service)]
HoldoutServiceDep = Annotated[HoldoutService, Depends(get_holdout_service)]
