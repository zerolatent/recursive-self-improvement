"""Protected-modules deny-list tests (Phase 3, G2): coverage semantics,
default deny-list shape, and tamper-evident signing of the policy document.

The deny-list is policy data, so the tests treat it the way the release
plane treats a manifest: it must sign, verify, and fail verification on
any byte change — a deny-list that can be edited silently is not a
deny-list, it is a suggestion.
"""

from __future__ import annotations

import pytest

from evoruntime.security.protected_modules import (
    DEFAULT_PROTECTED_ROOTS,
    InvalidProtectedModulesError,
    ProtectedModulesDocument,
    UnsignedProtectedModulesError,
    path_to_module,
    sign_protected_modules,
    verify_protected_modules,
)
from evoruntime.security.signing import generate_signing_key


def test_default_document_covers_every_spec_plane() -> None:
    protected = ProtectedModulesDocument.default()
    covered = {root for root in DEFAULT_PROTECTED_ROOTS if protected.covers(root)}
    assert covered == set(DEFAULT_PROTECTED_ROOTS)


def test_default_document_covers_the_holdout_and_attestation_planes() -> None:
    protected = ProtectedModulesDocument.default()
    # The holdout/ledger plane is evoruntime.datasets; the evaluation
    # plane's attestation path is evoruntime.sdk.attestation.
    assert protected.covers("evoruntime.datasets.ledger")
    assert protected.covers("evoruntime.sdk.attestation")
    assert not protected.covers("evoruntime.sdk.adapter")


def test_covers_matches_submodules_but_not_prefix_siblings() -> None:
    protected = ProtectedModulesDocument.default()
    assert protected.covers("evoruntime.security.egress")
    assert protected.covers("evoruntime.security")
    # A sibling that merely shares a prefix is not under the root.
    assert not protected.covers("evoruntime.securityx.egress")
    assert not protected.covers("evoruntime")


def test_covers_path_maps_file_paths_onto_module_roots() -> None:
    protected = ProtectedModulesDocument.default()
    assert protected.covers_path("src/evoruntime/security/egress.py") == "evoruntime.security"
    assert protected.covers_path("src/evoruntime/selection/arm.py") == "evoruntime.selection"
    # Unprotected trees stay writable.
    assert protected.covers_path("src/evoruntime/plugins/static_analysis.py") is None
    assert protected.covers_path("scripts/apply.py") is None


def test_covers_path_respects_module_boundary() -> None:
    protected = ProtectedModulesDocument.default()
    assert protected.covers_path("src/evoruntime/securityx/egress.py") is None


def test_path_to_module_drops_layout_prefix_and_suffix() -> None:
    assert path_to_module("src/evoruntime/security/policy.py") == "evoruntime.security.policy"
    assert path_to_module("evoruntime/security/policy.py") == "evoruntime.security.policy"
    assert path_to_module("prompts/notes.md") == "prompts.notes.md"


def test_document_signs_and_verifies() -> None:
    private_key = generate_signing_key()
    protected = ProtectedModulesDocument.default()
    signed = sign_protected_modules(protected, private_key)
    assert signed.verify() is True
    verify_protected_modules(signed)  # must not raise


def test_document_verification_fails_on_any_byte_change() -> None:
    private_key = generate_signing_key()
    protected = ProtectedModulesDocument.default()
    signed = sign_protected_modules(protected, private_key)

    # A widened deny-list under the same signature is a forgery: the
    # canonical bytes no longer match what was signed.
    tampered = ProtectedModulesDocument(
        document_id=protected.document_id,
        document_version=protected.document_version + 1,
        roots=protected.roots,
    )
    forged = type(signed)(
        document=tampered,
        digest=tampered.digest,
        signature=signed.signature,
        signer_public_key=signed.signer_public_key,
    )
    assert forged.verify() is False
    with pytest.raises(UnsignedProtectedModulesError, match="no valid signature"):
        verify_protected_modules(forged)


def test_document_is_immutable_after_construction() -> None:
    protected = ProtectedModulesDocument.default()
    with pytest.raises(InvalidProtectedModulesError, match="immutable"):
        protected.roots = ("evoruntime.attacker",)  # type: ignore[misc]


def test_document_refuses_an_empty_root_list() -> None:
    with pytest.raises(InvalidProtectedModulesError, match="at least one"):
        ProtectedModulesDocument(document_id="empty", roots=())


def test_document_refuses_a_non_identifier_root() -> None:
    with pytest.raises(InvalidProtectedModulesError, match="dotted module prefix"):
        ProtectedModulesDocument(document_id="bad", roots=("9security",))


def test_document_refuses_a_trailing_wildcard_root() -> None:
    with pytest.raises(InvalidProtectedModulesError, match="dotted module prefix"):
        ProtectedModulesDocument(document_id="bad", roots=("evoruntime.security.*",))


def test_document_refuses_duplicate_roots() -> None:
    with pytest.raises(InvalidProtectedModulesError, match="duplicate"):
        ProtectedModulesDocument(
            document_id="dupe",
            roots=("evoruntime.security", "evoruntime.security"),
        )


def test_document_refuses_an_empty_id() -> None:
    with pytest.raises(InvalidProtectedModulesError, match="document_id"):
        ProtectedModulesDocument(document_id="", roots=DEFAULT_PROTECTED_ROOTS)


def test_document_refuses_a_nonpositive_version() -> None:
    with pytest.raises(InvalidProtectedModulesError, match="document_version"):
        ProtectedModulesDocument(
            document_id="bad-version", document_version=0, roots=DEFAULT_PROTECTED_ROOTS
        )


def test_reason_for_names_the_plane() -> None:
    protected = ProtectedModulesDocument.default()
    for root in DEFAULT_PROTECTED_ROOTS:
        assert protected.reason_for(root)


def test_digest_is_stable_and_content_addressed() -> None:
    first = ProtectedModulesDocument.default()
    second = ProtectedModulesDocument.default()
    assert first.digest == second.digest
    assert first.digest.startswith("sha256:")
