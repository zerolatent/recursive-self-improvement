"""Shared fixtures for the E5 release-controller test suite.

Every test runs against the in-process fleet simulator with a compressed
clock: the 24-hour observation horizon elapses in advanced seconds, the
fleet's convergence latencies are drawn from a seeded distribution, and
the signing key is a fresh Ed25519 key per test (never shared, never
embedded — the same custody rule the signing service enforces).
"""

from __future__ import annotations

import random
from collections.abc import Callable
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evoruntime.release import (
    CompressedClock,
    InProcessFleetSimulator,
    ReleaseController,
    SignedReleaseManifest,
    sign_release_manifest,
)
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.signing import generate_signing_key
from evoruntime.selection import InMemoryPointerAuditLog, ReleasePointerStore

CONTROLLER_IDENTITY = WorkloadIdentity(
    role=WorkloadRole.RELEASE_CONTROLLER, subject="svc-release-controller"
)
EVALUATOR_IDENTITY = WorkloadIdentity(role=WorkloadRole.EVALUATOR, subject="svc-evaluator")
CANDIDATE_IDENTITY = WorkloadIdentity(role=WorkloadRole.CANDIDATE_RUNNER, subject="agt-candidate")


def digest(n: int) -> str:
    """A stable, unique-looking artifact digest for fixture manifests."""
    return "sha256:" + f"{n:064x}"


def make_manifest(
    key: Ed25519PrivateKey,
    *,
    artifact_digests: list[str],
    prior_release_digest: str | None = None,
    adapter_versions: dict[str, Any] | None = None,
    model_routes: dict[str, Any] | None = None,
    policies: dict[str, Any] | None = None,
) -> SignedReleaseManifest:
    """A signed release manifest over the given resolved artifacts."""
    return sign_release_manifest(
        artifact_digests=artifact_digests,
        adapter_versions=adapter_versions or {"adapter": "1.0.0"},
        model_routes=model_routes or {"default": "model-a"},
        policies=policies or {"canary": "p0"},
        prior_release_digest=prior_release_digest,
        private_key=key,
    )


@pytest.fixture
def signing_key() -> Ed25519PrivateKey:
    return generate_signing_key()


@pytest.fixture
def pointer_store() -> ReleasePointerStore:
    return ReleasePointerStore(audit_log=InMemoryPointerAuditLog())


@pytest.fixture
def controller(pointer_store: ReleasePointerStore) -> ReleaseController:
    return ReleaseController(pointer_store, CONTROLLER_IDENTITY)


@pytest.fixture
def clock() -> CompressedClock:
    """Compressed time: one advanced second of harness time is one hour
    of observation — the 24h horizon elapses in 24 advanced seconds."""
    return CompressedClock(scale=3600.0)


@pytest.fixture
def latency_sampler() -> Callable[[], float]:
    """Seeded per-worker convergence latency: most workers in 30–120s,
    a realistic tail approaching but staying under the 5-minute bound."""
    rng = random.Random(20260828)
    return lambda: rng.uniform(30.0, 120.0) if rng.random() < 0.95 else rng.uniform(120.0, 290.0)


@pytest.fixture
def fleet(clock: CompressedClock, latency_sampler: Callable[[], float]) -> InProcessFleetSimulator:
    return InProcessFleetSimulator(worker_count=100, latency_sampler=latency_sampler, clock=clock)
