"""Shared fixtures for the registry test suite (deliverable E1).

Tests are tenant-scoped, like the dataset and trace-ingest suites: the
`db_session` fixture truncates the lineage tables (which registry payloads
share) but not the registry tables, so every test uses a fresh tenant_id
and asserts only on rows it wrote. Artifact bodies embed the tenant id, so
digests never collide across tests either.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.orm import Session

from evoruntime.registry.service import RegistryService
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.signing import generate_signing_key


@pytest.fixture
def registry_tenant() -> str:
    """A tenant unique to this test — registry rows accumulate across tests."""
    return f"tnt_{uuid.uuid4().hex[:12]}"


@pytest.fixture
def registry_service(db_session: Session) -> RegistryService:
    return RegistryService(db_session)


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    """A throwaway Ed25519 key for signing attestations and manifests."""
    return generate_signing_key()


@pytest.fixture
def evaluator_identity(registry_tenant: str) -> WorkloadIdentity:
    return WorkloadIdentity(role=WorkloadRole.EVALUATOR, subject=f"svc_eval_{registry_tenant}")


@pytest.fixture
def candidate_identity(registry_tenant: str) -> WorkloadIdentity:
    return WorkloadIdentity(
        role=WorkloadRole.CANDIDATE_RUNNER, subject=f"svc_cand_{registry_tenant}"
    )


def unique_body(tenant_id: str, label: str = "body") -> bytes:
    """Canonical artifact bytes unique to this test (tenant-scoped digest)."""
    return f'{{"tenant":"{tenant_id}","label":"{label}","nonce":"{uuid.uuid4().hex}"}}'.encode()


def register_simple(
    service: RegistryService,
    tenant_id: str,
    label: str = "artifact",
    **kwargs: Any,
) -> Any:
    """Register a uniquely-named artifact and return the row."""
    return service.register_artifact(
        tenant_id=tenant_id,
        artifact_type="prompt_bundle",
        canonical_bytes=unique_body(tenant_id, label),
        **kwargs,
    )


@pytest.fixture
def register(registry_service: RegistryService, registry_tenant: str) -> Callable[..., Any]:
    """Register a unique artifact in this test's tenant."""

    def _register(label: str = "artifact", **kwargs: Any) -> Any:
        return register_simple(registry_service, registry_tenant, label, **kwargs)

    return _register
