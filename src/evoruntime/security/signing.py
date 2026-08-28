"""Ed25519 detached-signature signing service.

Release manifests and outcome attestations are only as trustworthy as the
signature binding them to a specific byte sequence. This module provides
that primitive: sign arbitrary bytes with an evaluator-held Ed25519 private
key, produce a detached signature, and verify it later against the public
key alone. Detached (rather than embedded) signatures matter because the
signed artifact — a manifest, an attestation record — needs to stay in its
own native format (JSON, Pydantic model) rather than be wrapped in a
signature envelope.

Key custody basics for Phase 0: private key material is never embedded in
code or test fixtures. It is loaded from an environment variable (backed,
in a real deployment, by the project secrets store) and gated behind
:func:`evoruntime.security.policy.require_evaluator_key_access` so a
candidate-runner identity cannot load it even if it can reach the process.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from evoruntime.security.identities import WorkloadIdentity
from evoruntime.security.policy import require_evaluator_key_access

_PRIVATE_KEY_ENV_VAR = "EVORUNTIME_EVALUATOR_SIGNING_KEY"


class SigningKeyError(RuntimeError):
    """Raised when evaluator signing key material is missing or malformed."""


@dataclass(frozen=True)
class DetachedSignature:
    """A signature over a payload, plus the public key needed to verify it.

    The public key travels with the signature (not the payload) because a
    verifier — which may run outside the evaluation plane entirely, e.g. a
    release controller checking an attestation — needs it to verify
    without evaluator key access of its own.
    """

    signature: bytes
    public_key: bytes


def generate_signing_key() -> Ed25519PrivateKey:
    """Generate a fresh Ed25519 keypair.

    Used by operators to provision the value that goes into
    ``EVORUNTIME_EVALUATOR_SIGNING_KEY`` (via the secrets store) and by
    tests that need a throwaway key — never to hold a long-lived key in
    process memory across requests.
    """
    return Ed25519PrivateKey.generate()


def encode_private_key(private_key: Ed25519PrivateKey) -> str:
    """Serialize a private key to the base64 form the env var expects."""
    raw = private_key.private_bytes(
        encoding=Encoding.Raw, format=PrivateFormat.Raw, encryption_algorithm=NoEncryption()
    )
    return base64.b64encode(raw).decode("ascii")


def load_evaluator_signing_key(
    identity: WorkloadIdentity, *, env_var: str = _PRIVATE_KEY_ENV_VAR
) -> Ed25519PrivateKey:
    """Load the evaluator's private signing key, gated by identity.

    Raises:
        evoruntime.security.policy.PermissionDeniedError: ``identity`` is
            not the evaluator role. Checked before the environment is even
            read, so a denied caller learns nothing about whether key
            material is configured.
        SigningKeyError: the evaluator role is confirmed but no key (or a
            malformed one) is configured — a deployment bug, not a policy
            violation.
    """
    require_evaluator_key_access(identity)
    encoded = os.environ.get(env_var)
    if not encoded:
        raise SigningKeyError(
            f"{env_var} is not set; evaluator signing key must come from the secrets "
            "store at runtime, never a hardcoded default"
        )
    try:
        raw = base64.b64decode(encoded, validate=True)
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise SigningKeyError(f"{env_var} does not contain a valid base64 Ed25519 key") from exc


def sign(private_key: Ed25519PrivateKey, payload: bytes) -> DetachedSignature:
    """Produce a detached signature over ``payload``."""
    signature = private_key.sign(payload)
    public_key = private_key.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw
    )
    return DetachedSignature(signature=signature, public_key=public_key)


def verify(detached: DetachedSignature, payload: bytes) -> bool:
    """Verify a detached signature against ``payload``.

    Returns ``False`` on any mismatch (wrong key, altered payload,
    corrupted signature bytes) rather than raising — callers that need to
    branch on validity get a plain boolean; callers that need to fail loud
    should raise on a ``False`` result themselves. This function never
    swallows a verification failure silently — it reports it as its
    return value, which is the whole point of the call.
    """
    try:
        Ed25519PublicKey.from_public_bytes(detached.public_key).verify(detached.signature, payload)
    except (InvalidSignature, ValueError):
        # ValueError covers malformed key/signature material (wrong length,
        # empty bytes) — a row that never carried a real signature is as
        # unverified as one carrying a wrong one.
        return False
    return True
