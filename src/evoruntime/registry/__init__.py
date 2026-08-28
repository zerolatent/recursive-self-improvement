"""Artifact registry (deliverable E1, PRD §9.2).

The five-record model: immutable content-addressed `ArtifactContent`,
`ProposalRecord`, signed `EvaluationAttestation`, append-only
`ArtifactStatusEvent` (with the current-status projection), and signed
`ReleaseManifest`. See `evoruntime.registry.service` for the FR-003
rejection boundary and `evoruntime.registry.canonical` for the digest
conventions.
"""

from __future__ import annotations

from evoruntime.registry.canonical import (
    artifact_digest_for,
    payload_body_digest,
)
from evoruntime.registry.errors import (
    ArtifactNotFoundError,
    CircularMetadataError,
    DigestMismatchError,
    InvalidStatusEventError,
    MixedReleaseActivationError,
    RegistryError,
    UnsignedActivationError,
)
from evoruntime.registry.service import RegistryService

__all__ = [
    "ArtifactNotFoundError",
    "CircularMetadataError",
    "DigestMismatchError",
    "InvalidStatusEventError",
    "MixedReleaseActivationError",
    "RegistryError",
    "RegistryService",
    "UnsignedActivationError",
    "artifact_digest_for",
    "payload_body_digest",
]
