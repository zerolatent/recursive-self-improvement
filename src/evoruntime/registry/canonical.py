"""Canonical serialization and digest computation for the registry.

Every digest in the registry is sha256 over *canonical* bytes: JSON with
sorted keys and no insignificant whitespace, UTF-8 encoded. Two callers
serializing the same logical body must produce byte-identical output, or
the content address they compute for it would differ.

What the artifact digest covers (PRD §9.2): artifact_type,
canonical_body_digest, dependencies, capability_requests. What it
deliberately excludes: the generated artifact id (derived, not authored),
the storage URI (an implementation detail of where bytes live), and any
signature (attached to the body, never part of what it vouches for).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from evoruntime.core.ids import new_id

ARTIFACT_ID_PREFIX = "art"
PROPOSAL_ID_PREFIX = "prp"
ATTESTATION_ID_PREFIX = "att"
EVENT_ID_PREFIX = "ase"
MANIFEST_ID_PREFIX = "rel"

#: Where canonical artifact bytes live: the lineage payload store, keyed by
#: (tenant_id, payload digest). The URI is recorded on the row for
#: provenance but excluded from the digested body.
STORAGE_URI_SCHEME = "evoruntime-payload"


def canonical_json(body: dict[str, Any]) -> bytes:
    """Serialize `body` to canonical JSON bytes (sorted keys, compact)."""
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload_body_digest(canonical_bytes: bytes) -> str:
    """Digest of the artifact's canonical byte payload: Merkle root + size.

    Phase 1 payloads are single-leaf Merkle trees — the root of a one-leaf
    tree is the leaf hash, sha256 of the bytes — so the root and the byte
    size together let a verifier check the record against storage without
    reading the payload. If payloads ever become multi-part trees, only this
    function's root computation changes; the record format already carries
    both values.
    """
    return f"sha256:{sha256_hex(canonical_bytes)}:{len(canonical_bytes)}"


def artifact_digest_for(
    *,
    artifact_type: str,
    canonical_body_digest: str,
    dependencies: Sequence[object],
    capability_requests: Mapping[str, object],
) -> str:
    """The artifact's content address: sha256 over the canonical JSON of the
    digested body. Generated id, storage URI, and signature are excluded by
    construction — they are not fields of this body.
    """
    body = canonical_json(
        {
            "artifact_type": artifact_type,
            "canonical_body_digest": canonical_body_digest,
            "dependencies": dependencies,
            "capability_requests": capability_requests,
        }
    )
    return f"sha256:{sha256_hex(body)}"


def attestation_body_bytes(
    *,
    artifact_digest: str,
    evaluator_subject: str,
    outcome: str,
    result_metrics: Mapping[str, object],
    evaluation_payload_digest: str,
) -> bytes:
    """Canonical bytes an evaluation attestation is signed over. Signature
    and public key columns are excluded — they attach to this body."""
    return canonical_json(
        {
            "artifact_digest": artifact_digest,
            "evaluator_subject": evaluator_subject,
            "outcome": outcome,
            "result_metrics": result_metrics,
            "evaluation_payload_digest": evaluation_payload_digest,
        }
    )


def manifest_body_bytes(
    *,
    artifact_digests: Sequence[object],
    adapter_versions: Mapping[str, object],
    model_routes: Mapping[str, object],
    policies: Mapping[str, object],
    prior_release_digest: str | None,
) -> bytes:
    """Canonical bytes a release manifest is signed over. Signature, public
    key, and storage URI are excluded — the manifest is the atomic
    activation unit, and what it vouches for is exactly this body."""
    return canonical_json(
        {
            "artifact_digests": artifact_digests,
            "adapter_versions": adapter_versions,
            "model_routes": model_routes,
            "policies": policies,
            "prior_release_digest": prior_release_digest,
        }
    )


def manifest_digest_for(canonical_bytes: bytes) -> str:
    return f"sha256:{sha256_hex(canonical_bytes)}"


def storage_uri_for(payload_digest: str) -> str:
    return f"{STORAGE_URI_SCHEME}://{payload_digest}"


def new_artifact_id() -> str:
    return new_id(ARTIFACT_ID_PREFIX)


def new_proposal_id() -> str:
    return new_id(PROPOSAL_ID_PREFIX)


def new_attestation_id() -> str:
    return new_id(ATTESTATION_ID_PREFIX)


def new_event_id() -> str:
    return new_id(EVENT_ID_PREFIX)


def new_manifest_id() -> str:
    return new_id(MANIFEST_ID_PREFIX)
