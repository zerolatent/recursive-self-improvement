"""Outcome attestation: the authoritative result, signed by the evaluator.

`Trace.claim_outcome` records what the *agent* says happened. This module
records what an external verifier *proved* happened, and binds it to a key
the candidate cannot reach. The split is the point: an optimizer scored on
self-reported success learns to report success, so the number a campaign is
allowed to act on has to come from somewhere the candidate cannot write.

An attestation binds four things at once, and each of them closes a specific
way a result could be misrepresented:

* `trace_id` — which execution produced it (not a different, better run)
* `task_set_digest` — which tasks were attempted (not an easier subset)
* `evaluator_bundle_digest` — which grader decided (not a weakened one)
* `raw_result_digest` — the exact result bytes (not a summarized retelling)

Change any one and the signature fails. The signature is detached and
verifiable with the public key alone, so a release controller can check an
attestation without holding evaluator key material of its own.
"""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from typing import Annotated

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import AwareDatetime, Field, StringConstraints

from evoruntime.core.events import SHA256_DIGEST_PATTERN, TRACE_ID_PATTERN
from evoruntime.core.schemas import EvoRuntimeBaseModel
from evoruntime.security.identities import WorkloadIdentity, identity_from_env
from evoruntime.security.policy import require_evaluator_key_access
from evoruntime.security.signing import (
    DetachedSignature,
    load_evaluator_signing_key,
    verify,
)
from evoruntime.security.signing import sign as sign_detached

ATTESTATION_DOMAIN = "evoruntime.outcome-attestation.v1"
"""Domain separator mixed into every signed payload.

Without it, a signature over some other evaluator-signed structure with
coincidentally similar fields could be replayed as an attestation. One
constant string makes each signature valid for exactly one message type.
"""

_Sha256Digest = Annotated[str, StringConstraints(pattern=SHA256_DIGEST_PATTERN)]
_TraceId = Annotated[str, StringConstraints(pattern=TRACE_ID_PATTERN)]


def attestation_payload(
    *,
    trace_id: str,
    task_set_digest: str,
    evaluator_bundle_digest: str,
    raw_result_digest: str,
    signed_at: datetime,
    evaluator_subject: str,
) -> bytes:
    """Build the exact bytes an attestation signature covers.

    A pure function, deliberately: signing and verification must derive the
    payload the same way, and the only reliable way to guarantee that is for
    both to call one function that touches nothing else.
    """
    return json.dumps(
        {
            "domain": ATTESTATION_DOMAIN,
            "trace_id": trace_id,
            "task_set_digest": task_set_digest,
            "evaluator_bundle_digest": evaluator_bundle_digest,
            "raw_result_digest": raw_result_digest,
            "signed_at": signed_at.isoformat(),
            "evaluator_subject": evaluator_subject,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class OutcomeAttestation(EvoRuntimeBaseModel):
    """A verifier's signed statement about what one trace actually achieved."""

    trace_id: _TraceId
    task_set_digest: _Sha256Digest
    evaluator_bundle_digest: _Sha256Digest
    raw_result_digest: _Sha256Digest
    signed_at: AwareDatetime
    evaluator_subject: str = Field(min_length=1)
    signature_b64: str = Field(min_length=1)
    public_key_b64: str = Field(min_length=1)

    @classmethod
    def sign(
        cls,
        *,
        trace_id: str,
        task_set_digest: str,
        evaluator_bundle_digest: str,
        raw_result_digest: str,
        identity: WorkloadIdentity | None = None,
        private_key: Ed25519PrivateKey | None = None,
        signed_at: datetime | None = None,
    ) -> OutcomeAttestation:
        """Sign an attestation as the evaluator.

        The identity gate runs here even when ``private_key`` is supplied
        directly. Checking only inside the key *loader* would mean a caller
        holding a key object by any other route bypasses the boundary
        entirely — the check belongs on the action, not on one path to it.

        Raises:
            evoruntime.security.policy.PermissionDeniedError: the caller is
                not the evaluator role.
            evoruntime.security.signing.SigningKeyError: no usable evaluator
                key is configured.
        """
        resolved_identity = identity or identity_from_env()
        require_evaluator_key_access(resolved_identity)
        key = private_key or load_evaluator_signing_key(resolved_identity)
        moment = signed_at or datetime.now(UTC)
        detached = sign_detached(
            key,
            attestation_payload(
                trace_id=trace_id,
                task_set_digest=task_set_digest,
                evaluator_bundle_digest=evaluator_bundle_digest,
                raw_result_digest=raw_result_digest,
                signed_at=moment,
                evaluator_subject=resolved_identity.subject,
            ),
        )
        return cls(
            trace_id=trace_id,
            task_set_digest=task_set_digest,
            evaluator_bundle_digest=evaluator_bundle_digest,
            raw_result_digest=raw_result_digest,
            signed_at=moment,
            evaluator_subject=resolved_identity.subject,
            signature_b64=base64.b64encode(detached.signature).decode("ascii"),
            public_key_b64=base64.b64encode(detached.public_key).decode("ascii"),
        )

    def signed_payload(self) -> bytes:
        """Recompute the bytes this attestation's signature must cover."""
        return attestation_payload(
            trace_id=self.trace_id,
            task_set_digest=self.task_set_digest,
            evaluator_bundle_digest=self.evaluator_bundle_digest,
            raw_result_digest=self.raw_result_digest,
            signed_at=self.signed_at,
            evaluator_subject=self.evaluator_subject,
        )

    def detached_signature(self) -> DetachedSignature:
        """Decode the stored signature into D7's verification primitive."""
        return DetachedSignature(
            signature=base64.b64decode(self.signature_b64),
            public_key=base64.b64decode(self.public_key_b64),
        )

    def verify(self, *, expected_public_key: bytes | None = None) -> bool:
        """Check the signature over this attestation's own fields.

        ``expected_public_key`` is how a caller answers the question the
        signature alone cannot: *whose* key signed this. A valid signature
        from an unknown key proves only that someone with some key signed
        these bytes, so a release controller pins the evaluator's published
        key here rather than trusting the one carried in the record.
        """
        detached = self.detached_signature()
        if expected_public_key is not None and detached.public_key != expected_public_key:
            return False
        return verify(detached, self.signed_payload())
