"""Shared fixtures for the sandbox plane tests."""

from __future__ import annotations

import hashlib
from typing import Any

from evoruntime.plugins.protocol import InMemoryCheckpointStore
from evoruntime.sandbox.profile import ExecutionProfile, ExecutionRequest, PayloadRef

TENANT = "tenant-1"


class DictPayloadReader:
    """Serves payloads from an in-memory digest -> bytes map."""

    def __init__(self, blobs: dict[str, bytes]) -> None:
        self._blobs = dict(blobs)

    def read(self, *, tenant_id: str, payload_digest: str) -> bytes:
        if tenant_id != TENANT:
            raise KeyError(f"unknown tenant {tenant_id!r}")
        return self._blobs[payload_digest]


def digest_of(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def make_payload(path: str, data: bytes) -> PayloadRef:
    return PayloadRef(path=path, digest=digest_of(data))


def make_request(
    *,
    profile: ExecutionProfile,
    payloads: tuple[PayloadRef, ...],
    command: tuple[str, ...],
    image_digest: str = "ghcr.io/acme/candidate@sha256:" + "cd" * 32,
) -> ExecutionRequest:
    return ExecutionRequest(
        tenant_id=TENANT,
        image_digest=image_digest,
        profile=profile,
        payloads=payloads,
        command=command,
    )


def assert_attestation_roundtrips(store: InMemoryCheckpointStore, result: Any) -> None:
    """The attestation digest must bind the exact persisted bytes."""
    stored = store._blobs[result.attestation_digest]
    assert result.attestation.model_dump_json().encode("utf-8") == stored


__all__ = [
    "DictPayloadReader",
    "TENANT",
    "assert_attestation_roundtrips",
    "digest_of",
    "make_payload",
    "make_request",
]
