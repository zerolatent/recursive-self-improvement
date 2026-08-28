"""Privileged admission path for adapters and evaluators (FR-022).

Adapters and evaluators are privileged plugin roles: unlike a strategy —
which only ever proposes — they touch candidate bytes and evaluation
verdicts, so admitting one is a governance act, not a routine load. Three
controls, all mandatory:

* **Pinned versions.** A privileged plugin is admitted at an immutable
  content digest, never a floating tag. ``v2`` or ``latest`` can be
  re-pointed after approval; a sha256 digest cannot.
* **Two-person approval.** Two *distinct* human approvers must sign off,
  and neither may be the requester — one person's mistake (or one
  compromised account) must not be sufficient to put privileged code on
  the evaluation plane.
* **Signed admission records.** The resulting record is signed with the
  evaluator Ed25519 key (via the Phase 0 signing service, gated by the
  Phase 0 policy check), so an admission decision is itself tamper-evident
  and verifiable without holding the key.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from enum import StrEnum

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field, field_validator

from evoruntime.core.schemas import EvoRuntimeBaseModel
from evoruntime.security.identities import WorkloadIdentity
from evoruntime.security.policy import require_evaluator_key_access
from evoruntime.security.signing import DetachedSignature, sign, verify

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class PrivilegedRole(StrEnum):
    """The plugin roles that require the privileged admission path."""

    ADAPTER = "adapter"
    EVALUATOR = "evaluator"


class DenialReason(StrEnum):
    """Why a privileged admission request was refused."""

    INSUFFICIENT_APPROVALS = "insufficient_approvals"
    DUPLICATE_APPROVER = "duplicate_approver"
    SELF_APPROVAL = "self_approval"
    UNPINNED_VERSION = "unpinned_version"
    REQUESTER_NOT_AUTHORIZED = "requester_not_authorized"


class PrivilegedAdmissionDeniedError(PermissionError):
    """Raised when a privileged admission request fails a governance gate."""

    def __init__(self, reason: DenialReason, detail: str) -> None:
        self.reason = reason
        super().__init__(f"privileged admission denied ({reason.value}): {detail}")


class PinnedVersion(EvoRuntimeBaseModel):
    """An immutable plugin version: identity plus content digest.

    The digest is mandatory and shape-checked — a floating tag cannot be
    constructed into this model, so the type system carries the pin
    requirement.
    """

    plugin_id: str = Field(min_length=1)
    digest: str

    @field_validator("digest")
    @classmethod
    def _require_content_digest(cls, value: str) -> str:
        if not _DIGEST_RE.match(value):
            raise ValueError(
                f"digest {value!r} must be a sha256 content digest (sha256:<64 hex>) — "
                "floating tags cannot be admitted for privileged roles"
            )
        return value


class ApprovalRecord(EvoRuntimeBaseModel):
    """One human approval of a privileged admission request."""

    approver: str = Field(min_length=1, description="Human approver identity.")
    approver_role: str = Field(min_length=1)
    note: str = ""


class AdmissionRequest(EvoRuntimeBaseModel):
    """A request to admit a privileged plugin at a pinned version."""

    pinned: PinnedVersion
    privileged_role: PrivilegedRole
    requested_by: str = Field(min_length=1, description="Requesting workload subject.")
    justification: str = Field(min_length=1)


class SignedAdmissionRecord(EvoRuntimeBaseModel):
    """The signed, tamper-evident outcome of a privileged admission."""

    record_id: str
    request_digest: str
    decision: str = "admitted"
    admitted_version: PinnedVersion
    privileged_role: PrivilegedRole
    approvals: tuple[ApprovalRecord, ApprovalRecord]
    signature_b64: str
    signer_public_key_b64: str


def request_digest(request: AdmissionRequest) -> str:
    """Content digest over the canonical request bytes."""
    canonical = request.model_dump_json().encode()
    return f"sha256:{hashlib.sha256(canonical).hexdigest()}"


def admit_privileged(
    request: AdmissionRequest,
    approvals: list[ApprovalRecord],
    *,
    signer_identity: WorkloadIdentity,
    private_key: Ed25519PrivateKey,
) -> SignedAdmissionRecord:
    """Admit a privileged plugin, or raise :class:`PrivilegedAdmissionDeniedError`.

    ``signer_identity`` must pass the Phase 0 evaluator-key policy check —
    only the evaluator role may sign admission records, so a candidate-runner
    identity cannot mint governance artifacts even with the key in reach.
    """
    require_evaluator_key_access(signer_identity)

    if len(approvals) != 2:
        raise PrivilegedAdmissionDeniedError(
            DenialReason.INSUFFICIENT_APPROVALS,
            f"two-person approval requires exactly 2 approvals, got {len(approvals)}",
        )
    first, second = approvals[0], approvals[1]
    if first.approver.casefold() == second.approver.casefold():
        raise PrivilegedAdmissionDeniedError(
            DenialReason.DUPLICATE_APPROVER,
            f"both approvals name the same approver {first.approver!r}",
        )
    for approval in approvals:
        if approval.approver.casefold() == request.requested_by.casefold():
            raise PrivilegedAdmissionDeniedError(
                DenialReason.SELF_APPROVAL,
                f"requester {request.requested_by!r} cannot approve their own request",
            )

    record = SignedAdmissionRecord(
        record_id=f"adm-{request_digest(request)[:23]}",
        request_digest=request_digest(request),
        decision="admitted",
        admitted_version=request.pinned,
        privileged_role=request.privileged_role,
        approvals=(first, second),
        signature_b64="",
        signer_public_key_b64="",
    )
    signature = sign(private_key, _signed_bytes(record))
    return record.model_copy(
        update={
            "signature_b64": base64.b64encode(signature.signature).decode(),
            "signer_public_key_b64": base64.b64encode(signature.public_key).decode(),
        }
    )


def _signed_bytes(record: SignedAdmissionRecord) -> bytes:
    """Canonical bytes the signature covers — the record minus the signature."""
    unsigned = record.model_dump(mode="json", exclude={"signature_b64", "signer_public_key_b64"})
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()


def verify_admission_record(record: SignedAdmissionRecord) -> bool:
    """Verify a signed admission record against its attached public key.

    Returns False for any tampering with the record body or the signature —
    callers must treat an unverified record as if no admission happened.
    """
    try:
        detached = DetachedSignature(
            signature=base64.b64decode(record.signature_b64, validate=True),
            public_key=base64.b64decode(record.signer_public_key_b64, validate=True),
        )
    except (ValueError, TypeError):
        return False
    return verify(detached, _signed_bytes(record))
