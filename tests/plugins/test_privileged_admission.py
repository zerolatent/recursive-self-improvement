"""FR-022 privileged admission — signed records, two-person approval, pinned versions."""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from evoruntime.plugins.privileged import (
    AdmissionRequest,
    ApprovalRecord,
    DenialReason,
    PinnedVersion,
    PrivilegedAdmissionDeniedError,
    PrivilegedRole,
    _signed_bytes,
    admit_privileged,
    request_digest,
    verify_admission_record,
)
from evoruntime.security.identities import WorkloadIdentity, WorkloadRole
from evoruntime.security.policy import PermissionDeniedError

EVALUATOR = WorkloadIdentity(role=WorkloadRole.EVALUATOR, subject="eval-plane-1")
CANDIDATE_RUNNER = WorkloadIdentity(role=WorkloadRole.CANDIDATE_RUNNER, subject="candidate-1")


def make_request() -> AdmissionRequest:
    return AdmissionRequest(
        pinned=PinnedVersion(plugin_id="ref-adapter", digest="sha256:" + "cd" * 32),
        privileged_role=PrivilegedRole.ADAPTER,
        requested_by="workload-adapter-installer",
        justification="production adapter rollout",
    )


def approvals() -> list[ApprovalRecord]:
    return [
        ApprovalRecord(approver="alice", approver_role="security-lead"),
        ApprovalRecord(approver="bob", approver_role="platform-oncall"),
    ]


class TestHappyPath:
    def test_two_person_admission_signs_a_verifiable_record(self) -> None:
        key = Ed25519PrivateKey.generate()
        record = admit_privileged(
            make_request(), approvals(), signer_identity=EVALUATOR, private_key=key
        )
        assert record.decision == "admitted"
        assert record.request_digest == request_digest(make_request())
        assert verify_admission_record(record) is True

    def test_record_binds_the_pinned_version(self) -> None:
        key = Ed25519PrivateKey.generate()
        request = make_request()
        record = admit_privileged(request, approvals(), signer_identity=EVALUATOR, private_key=key)
        assert record.admitted_version.digest == request.pinned.digest
        assert record.admitted_version.plugin_id == request.pinned.plugin_id


class TestApprovalGates:
    def test_one_approval_is_denied(self) -> None:
        key = Ed25519PrivateKey.generate()
        with pytest.raises(PrivilegedAdmissionDeniedError) as excinfo:
            admit_privileged(
                make_request(), approvals()[:1], signer_identity=EVALUATOR, private_key=key
            )
        assert excinfo.value.reason is DenialReason.INSUFFICIENT_APPROVALS

    def test_duplicate_approver_is_denied(self) -> None:
        key = Ed25519PrivateKey.generate()
        same_twice = [
            ApprovalRecord(approver="alice", approver_role="security-lead"),
            ApprovalRecord(approver="ALICE", approver_role="platform-oncall"),
        ]
        with pytest.raises(PrivilegedAdmissionDeniedError) as excinfo:
            admit_privileged(make_request(), same_twice, signer_identity=EVALUATOR, private_key=key)
        assert excinfo.value.reason is DenialReason.DUPLICATE_APPROVER

    def test_self_approval_is_denied(self) -> None:
        key = Ed25519PrivateKey.generate()
        request = make_request()
        self_approving = [
            ApprovalRecord(approver=request.requested_by, approver_role="requester"),
            ApprovalRecord(approver="bob", approver_role="platform-oncall"),
        ]
        with pytest.raises(PrivilegedAdmissionDeniedError) as excinfo:
            admit_privileged(request, self_approving, signer_identity=EVALUATOR, private_key=key)
        assert excinfo.value.reason is DenialReason.SELF_APPROVAL


class TestSignerAuthorization:
    def test_candidate_runner_cannot_sign_admission_records(self) -> None:
        key = Ed25519PrivateKey.generate()
        with pytest.raises(PermissionDeniedError):
            admit_privileged(
                make_request(), approvals(), signer_identity=CANDIDATE_RUNNER, private_key=key
            )


class TestPinnedVersions:
    def test_floating_tag_cannot_be_constructed(self) -> None:
        with pytest.raises(ValidationError, match="sha256 content digest"):
            PinnedVersion(plugin_id="ref-adapter", digest="v1.2.3")

    def test_unpinned_version_denied(self) -> None:
        key = Ed25519PrivateKey.generate()
        with pytest.raises(ValidationError):
            admit_privileged(
                make_request().model_copy(
                    update={"pinned": {"plugin_id": "ref-adapter", "digest": "latest"}}
                ),
                approvals(),
                signer_identity=EVALUATOR,
                private_key=key,
            )


class TestTamperEvidence:
    def test_tampered_record_fails_verification(self) -> None:
        key = Ed25519PrivateKey.generate()
        record = admit_privileged(
            make_request(), approvals(), signer_identity=EVALUATOR, private_key=key
        )
        tampered = record.model_copy(update={"decision": "revoked"})
        assert verify_admission_record(tampered) is False

    def test_corrupted_signature_fails_verification(self) -> None:
        key = Ed25519PrivateKey.generate()
        record = admit_privileged(
            make_request(), approvals(), signer_identity=EVALUATOR, private_key=key
        )
        broken_sig = base64.b64encode(b"\\x00" * 64).decode()
        broken = record.model_copy(update={"signature_b64": broken_sig})
        assert verify_admission_record(broken) is False

    def test_key_swap_is_self_consistent_so_trust_is_out_of_band(self) -> None:
        """A forger can attach their own key + signature and the record stays
        self-consistent — signature verification proves integrity only. Callers
        must compare ``signer_public_key_b64`` against the trusted evaluator
        key registry; that binding is deliberately out of band."""
        signer = Ed25519PrivateKey.generate()
        impostor = Ed25519PrivateKey.generate()
        record = admit_privileged(
            make_request(), approvals(), signer_identity=EVALUATOR, private_key=signer
        )
        forged = record.model_copy(
            update={
                "signature_b64": base64.b64encode(impostor.sign(_signed_bytes(record))).decode(),
                "signer_public_key_b64": base64.b64encode(
                    impostor.public_key().public_bytes_raw()
                ).decode(),
            }
        )
        assert verify_admission_record(forged) is True
        assert forged.signer_public_key_b64 != record.signer_public_key_b64
