"""Outcome attestation: what the evaluator proved, not what the agent claimed.

The tests that matter here are the negative ones. An attestation's whole job
is to fail when something has been swapped — a different trace, an easier
task set, a weakened grader, edited result bytes — so each of those swaps
gets its own test.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evoruntime.sdk.attestation import ATTESTATION_DOMAIN, OutcomeAttestation, attestation_payload
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.policy import PermissionDeniedError
from evoruntime.security.signing import (
    SigningKeyError,
    encode_private_key,
    generate_signing_key,
    verify,
)
from tests.sdk.support import digest

EVALUATOR = WorkloadIdentity(subject="svc_evaluator", role=WorkloadRole.EVALUATOR)
CANDIDATE = WorkloadIdentity(subject="agt_candidate", role=WorkloadRole.CANDIDATE_RUNNER)

TRACE_ID = "trc_000000000001"


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return generate_signing_key()


def sign_attestation(key: Ed25519PrivateKey, **overrides: str) -> OutcomeAttestation:
    fields: dict[str, str] = {
        "trace_id": TRACE_ID,
        "task_set_digest": digest(1),
        "evaluator_bundle_digest": digest(2),
        "raw_result_digest": digest(3),
    }
    fields.update(overrides)
    return OutcomeAttestation.sign(identity=EVALUATOR, private_key=key, **fields)


def test_a_signed_attestation_verifies(key: Ed25519PrivateKey) -> None:
    attestation = sign_attestation(key)

    assert attestation.verify() is True
    assert attestation.trace_id == TRACE_ID
    assert attestation.evaluator_subject == EVALUATOR.subject
    assert attestation.signed_at.tzinfo is not None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("trace_id", "trc_000000000002"),
        ("task_set_digest", digest(11)),
        ("evaluator_bundle_digest", digest(12)),
        ("raw_result_digest", digest(13)),
        ("evaluator_subject", "svc_someone_else"),
    ],
)
def test_editing_any_bound_field_breaks_the_signature(
    key: Ed25519PrivateKey, field: str, value: str
) -> None:
    """Each field closes one way a result could be misattributed: a different
    run, an easier task set, a weakened grader, edited result bytes."""
    attestation = sign_attestation(key)

    tampered = attestation.model_copy(update={field: value})

    assert tampered.verify() is False


def test_backdating_an_attestation_breaks_the_signature(key: Ed25519PrivateKey) -> None:
    attestation = sign_attestation(key)

    tampered = attestation.model_copy(
        update={"signed_at": attestation.signed_at - timedelta(days=30)}
    )

    assert tampered.verify() is False


def test_a_swapped_signature_does_not_verify(key: Ed25519PrivateKey) -> None:
    first = sign_attestation(key)
    second = sign_attestation(key, raw_result_digest=digest(99))

    forged = first.model_copy(update={"signature_b64": second.signature_b64})

    assert forged.verify() is False


def test_a_signature_from_the_wrong_key_does_not_verify(key: Ed25519PrivateKey) -> None:
    """Re-signing the same bytes with a self-generated key is the obvious
    forgery; it fails only because the key is pinned, not because the bytes
    changed."""
    attestation = sign_attestation(key)
    attacker_key = generate_signing_key()
    forged = OutcomeAttestation.sign(
        identity=EVALUATOR,
        private_key=attacker_key,
        trace_id=attestation.trace_id,
        task_set_digest=attestation.task_set_digest,
        evaluator_bundle_digest=attestation.evaluator_bundle_digest,
        raw_result_digest=attestation.raw_result_digest,
        signed_at=attestation.signed_at,
    )

    assert forged.verify() is True  # self-consistent...
    assert forged.verify(expected_public_key=attestation.detached_signature().public_key) is False


def test_pinning_the_expected_key_accepts_the_real_evaluator(key: Ed25519PrivateKey) -> None:
    attestation = sign_attestation(key)

    expected = attestation.detached_signature().public_key

    assert attestation.verify(expected_public_key=expected) is True


def test_the_candidate_runner_cannot_sign_even_holding_a_key(key: Ed25519PrivateKey) -> None:
    """The gate is on the action, not on the key loader — otherwise a caller
    who obtained a key object by any other route would bypass it."""
    with pytest.raises(PermissionDeniedError):
        OutcomeAttestation.sign(
            identity=CANDIDATE,
            private_key=key,
            trace_id=TRACE_ID,
            task_set_digest=digest(1),
            evaluator_bundle_digest=digest(2),
            raw_result_digest=digest(3),
        )


def test_signing_without_a_configured_key_fails_loudly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("EVORUNTIME_EVALUATOR_SIGNING_KEY", raising=False)

    with pytest.raises(SigningKeyError):
        OutcomeAttestation.sign(
            identity=EVALUATOR,
            trace_id=TRACE_ID,
            task_set_digest=digest(1),
            evaluator_bundle_digest=digest(2),
            raw_result_digest=digest(3),
        )


def test_identity_and_key_can_come_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, key: Ed25519PrivateKey
) -> None:
    """The deployed path: the evaluator workload's identity and key arrive as
    environment configuration, not as call arguments."""
    monkeypatch.setenv("EVORUNTIME_WORKLOAD_ROLE", WorkloadRole.EVALUATOR.value)
    monkeypatch.setenv("EVORUNTIME_WORKLOAD_SUBJECT", "svc_evaluator_prod")
    monkeypatch.setenv("EVORUNTIME_EVALUATOR_SIGNING_KEY", encode_private_key(key))

    attestation = OutcomeAttestation.sign(
        trace_id=TRACE_ID,
        task_set_digest=digest(1),
        evaluator_bundle_digest=digest(2),
        raw_result_digest=digest(3),
    )

    assert attestation.evaluator_subject == "svc_evaluator_prod"
    assert attestation.verify() is True


def test_environment_default_identity_cannot_sign(
    monkeypatch: pytest.MonkeyPatch, key: Ed25519PrivateKey
) -> None:
    """An unconfigured environment defaults to the least-privileged role, so
    a misconfigured runner fails closed instead of signing."""
    monkeypatch.delenv("EVORUNTIME_WORKLOAD_ROLE", raising=False)
    monkeypatch.setenv("EVORUNTIME_EVALUATOR_SIGNING_KEY", encode_private_key(key))

    with pytest.raises(PermissionDeniedError):
        OutcomeAttestation.sign(
            trace_id=TRACE_ID,
            task_set_digest=digest(1),
            evaluator_bundle_digest=digest(2),
            raw_result_digest=digest(3),
        )


def test_the_signed_payload_is_domain_separated(key: Ed25519PrivateKey) -> None:
    """Without a domain tag, a signature over a similarly-shaped evaluator
    record could be replayed as an attestation."""
    attestation = sign_attestation(key)

    payload = attestation.signed_payload()

    assert ATTESTATION_DOMAIN.encode() in payload
    assert verify(attestation.detached_signature(), payload) is True


def test_the_payload_is_stable_across_calls() -> None:
    """Signing and verification must derive identical bytes, or verification
    fails for reasons that have nothing to do with tampering."""
    moment = datetime(2026, 8, 27, 12, 0, 0, tzinfo=UTC)
    args = {
        "trace_id": TRACE_ID,
        "task_set_digest": digest(1),
        "evaluator_bundle_digest": digest(2),
        "raw_result_digest": digest(3),
        "signed_at": moment,
        "evaluator_subject": EVALUATOR.subject,
    }

    assert attestation_payload(**args) == attestation_payload(**args)  # type: ignore[arg-type]


def test_an_attestation_survives_a_json_round_trip(key: Ed25519PrivateKey) -> None:
    """A release controller verifies a record it received, not one it holds
    in memory."""
    attestation = sign_attestation(key)

    restored = OutcomeAttestation.model_validate_json(attestation.model_dump_json())

    assert restored.verify() is True
    assert restored == attestation


def test_verification_is_possible_with_the_public_key_alone(key: Ed25519PrivateKey) -> None:
    """The controller must never need evaluator key material of its own."""
    attestation = sign_attestation(key)
    detached = attestation.detached_signature()

    assert detached.public_key == key.public_key().public_bytes_raw()
    assert verify(detached, attestation.signed_payload()) is True
    assert base64.b64decode(attestation.signature_b64) == detached.signature


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("trace_id", "not-a-trace-id"),
        ("task_set_digest", "deadbeef"),
        ("evaluator_bundle_digest", "sha256:xyz"),
        ("raw_result_digest", ""),
    ],
)
def test_malformed_identifiers_are_rejected_before_signing(
    key: Ed25519PrivateKey, field: str, value: str
) -> None:
    with pytest.raises(ValueError):
        sign_attestation(key, **{field: value})
