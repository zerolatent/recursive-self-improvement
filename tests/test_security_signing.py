"""Signing service tests: verification fails on any byte change; key
custody is gated by the evaluator-role policy check."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.policy import PermissionDeniedError
from evoruntime.security.signing import (
    DetachedSignature,
    SigningKeyError,
    encode_private_key,
    generate_signing_key,
    load_evaluator_signing_key,
    sign,
    verify,
)

EVALUATOR = WorkloadIdentity(role=WorkloadRole.EVALUATOR, subject="eval-svc-1")
CANDIDATE_RUNNER = WorkloadIdentity(
    role=WorkloadRole.CANDIDATE_RUNNER, subject="candidate-sandbox-7"
)


def test_sign_and_verify_round_trip() -> None:
    private_key = generate_signing_key()
    payload = b'{"release_id": "rel_01J...", "artifact_digest": "sha256:abc"}'

    detached = sign(private_key, payload)

    assert verify(detached, payload) is True


def test_verify_fails_on_any_byte_change_of_the_payload() -> None:
    private_key = generate_signing_key()
    payload = b'{"outcome": "success"}'
    detached = sign(private_key, payload)

    tampered = b'{"outcome": "success "}'  # one extra byte

    assert verify(detached, tampered) is False


def test_verify_fails_on_signature_corruption() -> None:
    private_key = generate_signing_key()
    payload = b"attestation payload"
    detached = sign(private_key, payload)

    corrupted_signature = bytes([detached.signature[0] ^ 0xFF]) + detached.signature[1:]
    corrupted = DetachedSignature(signature=corrupted_signature, public_key=detached.public_key)

    assert verify(corrupted, payload) is False


def test_verify_fails_with_the_wrong_public_key() -> None:
    signer_key = generate_signing_key()
    other_key = generate_signing_key()
    payload = b"attestation payload"
    detached = sign(signer_key, payload)

    wrong_key_public = other_key.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw
    )
    mismatched = DetachedSignature(signature=detached.signature, public_key=wrong_key_public)

    assert verify(mismatched, payload) is False


def test_candidate_runner_cannot_load_evaluator_signing_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "EVORUNTIME_EVALUATOR_SIGNING_KEY", encode_private_key(generate_signing_key())
    )

    with pytest.raises(PermissionDeniedError, match="read evaluator signing keys"):
        load_evaluator_signing_key(CANDIDATE_RUNNER)


def test_evaluator_can_load_its_own_signing_key(monkeypatch: pytest.MonkeyPatch) -> None:
    original = generate_signing_key()
    monkeypatch.setenv("EVORUNTIME_EVALUATOR_SIGNING_KEY", encode_private_key(original))

    loaded = load_evaluator_signing_key(EVALUATOR)

    payload = b"round-trip check"
    assert verify(sign(loaded, payload), payload) is True


def test_evaluator_load_fails_closed_when_key_is_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("EVORUNTIME_EVALUATOR_SIGNING_KEY", raising=False)

    with pytest.raises(SigningKeyError, match="not set"):
        load_evaluator_signing_key(EVALUATOR)


def test_evaluator_load_rejects_malformed_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("EVORUNTIME_EVALUATOR_SIGNING_KEY", "not-valid-base64-key-material!!")

    with pytest.raises(SigningKeyError, match="does not contain a valid"):
        load_evaluator_signing_key(EVALUATOR)
