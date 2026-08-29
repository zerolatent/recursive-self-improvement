"""The protected-modules deny-list as signed policy data (Phase 3, G2).

Scaffold mutation research lets candidates edit the runtime's own source.
That power needs a boundary drawn in policy, not in code: which module
roots a candidate may never import, write, or hold a mask path into. This
module is that boundary, and it follows the two disciplines the runtime
already uses for policy:

**Policy is DATA, not code** (the :class:`evoruntime.selection.policy.
PromotionPolicyDocument` pattern). The protected roots live in a frozen,
digestable document that is part of the campaign's preregistration. A
gate whose deny-list lives in code can be widened by a commit; a gate
whose deny-list lives in a signed document can only be changed before
search begins, and every change is attributable to a signature.

**The document is signed and versioned** (the signed-release-manifest
pattern). ``sign_protected_modules`` produces a detached Ed25519
signature over the document's canonical bytes; ``verify_protected_modules``
refuses a document whose bytes no longer verify — a deny-list edited in
flight is not a policy update, it is a forgery of one.

The default document pins the Phase 3 spec's protected planes: the
security, selection, release, sandbox, and DLP modules, the holdout/query
ledger plane (``evoruntime.datasets``), and the evaluation plane's
attestation path (``evoruntime.sdk.attestation``) — the module whose
signature vouches that a measured result is real. A candidate that can
edit its own measurement is not being evaluated, it is grading itself.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from evoruntime.security.signing import DetachedSignature, sign, verify

PROTECTED_MODULES_SCHEMA_ID = "evoruntime.policy.protected-modules/v1"
"""Schema id for the canonical deny-list bytes a digest/signature covers."""

_DIGEST_PREFIX = "sha256:"

#: The Phase 3 spec's protected planes, pinned as the shipped default.
#: Order is presentation only — matching is prefix-based and set-like.
DEFAULT_PROTECTED_ROOTS: tuple[str, ...] = (
    "evoruntime.security",
    "evoruntime.selection",
    "evoruntime.release",
    "evoruntime.sandbox",
    "evoruntime.dlp",
    "evoruntime.datasets",
    "evoruntime.sdk.attestation",
)

_ROOT_DOC_REASONS: dict[str, str] = {
    "evoruntime.security": "workload identities, egress broker, signing service",
    "evoruntime.selection": "trusted selector and promotion policy engine",
    "evoruntime.release": "release controller, manifests, rollback",
    "evoruntime.sandbox": "isolation profiles and the execution backend",
    "evoruntime.dlp": "redaction pipeline and labeled corpus",
    "evoruntime.datasets": "holdout/ledger plane — partitions, sealed handles, query ledger",
    "evoruntime.sdk.attestation": "the evaluation plane's attestation path — the "
    "signature that vouches a measured result is real",
}


def _normalize_root(root: str) -> str:
    return root.strip().rstrip(".")


class InvalidProtectedModulesError(ValueError):
    """Raised when a protected-modules document is malformed."""


class ProtectedModulesDocument:
    """The declarative protected-modules deny-list (Phase 3 G2, as data).

    Mirrors :class:`evoruntime.selection.policy.PromotionPolicyDocument`:
    validated at construction, canonical-JSON digestable, and pinned
    before search. ``roots`` are dotted module prefixes; a module is
    protected when its name equals a root or starts with ``root + "."``.
    """

    def __init__(
        self,
        *,
        document_id: str,
        document_version: int = 1,
        roots: tuple[str, ...] | list[str],
    ) -> None:
        self.document_id = document_id
        self.document_version = document_version
        self.roots = tuple(_normalize_root(root) for root in roots)
        self._validate()
        self._sealed = True

    def __setattr__(self, name: str, value: Any) -> None:
        # Policy is data: once constructed, the document is frozen. A
        # deny-list that could be mutated in place would silently widen
        # every gate that reads it, so mutation is refused at the object.
        if getattr(self, "_sealed", False):
            raise InvalidProtectedModulesError(
                "a protected-modules document is immutable — construct a new, "
                "re-signed document with a bumped document_version instead"
            )
        super().__setattr__(name, value)

    @classmethod
    def default(cls) -> ProtectedModulesDocument:
        """The shipped deny-list: the Phase 3 spec's protected planes."""
        return cls(
            document_id="evoruntime-default-protected-modules", roots=DEFAULT_PROTECTED_ROOTS
        )

    def _validate(self) -> None:
        if not self.document_id:
            raise InvalidProtectedModulesError("document_id must be non-empty")
        if self.document_version < 1:
            raise InvalidProtectedModulesError(
                f"document_version must be >= 1, got {self.document_version}"
            )
        if not self.roots:
            raise InvalidProtectedModulesError(
                "a protected-modules document must name at least one root — "
                "an empty deny-list protects nothing and is not a policy"
            )
        for root in self.roots:
            if not root or root != _normalize_root(root):
                raise InvalidProtectedModulesError(
                    f"protected root must be non-empty, trimmed, and dot-free at the "
                    f"edges, got {root!r}"
                )
            if not all(segment and segment.isidentifier() for segment in root.split(".")):
                raise InvalidProtectedModulesError(
                    f"protected root {root!r} is not a dotted module prefix"
                )
        # A root that is itself a suffix of another root is redundant, and a
        # duplicate entry is two names for one rule — both are authoring bugs.
        duplicates = sorted({r for r in self.roots if self.roots.count(r) > 1})
        if duplicates:
            raise InvalidProtectedModulesError(
                f"duplicate protected root(s): {', '.join(duplicates)}"
            )

    def covers(self, module_name: str) -> str | None:
        """The protected root covering ``module_name``, or None.

        Dotted-prefix match: the module itself or any ancestor module is
        protected, so ``evoruntime.security.signing`` is covered by the
        ``evoruntime.security`` root and ``evoruntime.sdk.attestation`` by
        its exact root — while ``evoruntime.sdk.adapter`` is not.
        """
        for root in self.roots:
            if module_name == root or module_name.startswith(root + "."):
                return root
        return None

    def covers_path(self, path: str) -> str | None:
        """The protected root covering a repo-relative file path, or None.

        Paths map to modules by dropping an optional ``src/`` layout prefix
        and the ``.py`` suffix, then joining with dots — the same layout the
        scaffold ships. ``src/evoruntime/security/policy.py`` therefore maps
        to ``evoruntime.security.policy`` and is covered; a mask path that
        names no module (``prompts/notes.md``) maps to a non-module name and
        is covered only if some root still prefixes it.
        """
        return self.covers(path_to_module(path))

    def reason_for(self, root: str) -> str:
        """Why a root is protected — the shipped reasons, or a fallback."""
        return _ROOT_DOC_REASONS.get(root, "named by the protected-modules document")

    def to_canonical_dict(self) -> dict[str, Any]:
        """Canonical JSON form — the bytes the digest and signature cover."""
        return {
            "schema_id": PROTECTED_MODULES_SCHEMA_ID,
            "document_id": self.document_id,
            "document_version": self.document_version,
            "roots": sorted(self.roots),
        }

    def canonical_bytes(self) -> bytes:
        """Canonical JSON bytes: sorted keys, no whitespace, UTF-8."""
        return json.dumps(
            self.to_canonical_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    @property
    def digest(self) -> str:
        """Content digest of the canonical bytes (``sha256:...``)."""
        return _DIGEST_PREFIX + hashlib.sha256(self.canonical_bytes()).hexdigest()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"ProtectedModulesDocument(document_id={self.document_id!r}, "
            f"document_version={self.document_version}, roots={self.roots!r})"
        )


def path_to_module(path: str) -> str:
    """Map a repo-relative file path to its dotted module name.

    Pure and layout-pinned: an optional leading ``src/`` (the package
    layout) and a trailing ``.py`` are dropped, separators become dots.
    Non-Python paths keep their name — they simply rarely match a root.
    """
    normalized = path.strip().replace("\\", "/")
    segments = [segment for segment in normalized.split("/") if segment]
    if segments and segments[0] == "src":
        segments = segments[1:]
    if segments and segments[-1].endswith(".py"):
        segments[-1] = segments[-1][: -len(".py")]
    return ".".join(segments)


@dataclass(frozen=True, slots=True)
class SignedProtectedModulesDocument:
    """A protected-modules document bound to its digest and a signature.

    Mirrors :class:`evoruntime.release.manifest.SignedReleaseManifest`:
    the digest addresses the canonical body; the signature and public key
    vouch for it and are excluded from it by construction.
    """

    document: ProtectedModulesDocument
    digest: str
    signature: bytes
    signer_public_key: bytes

    def verify(self) -> bool:
        """True when the digest matches AND the signature verifies over the
        canonical bytes. Either failing means the deny-list was tampered with."""
        if self.digest != self.document.digest:
            return False
        return verify(
            DetachedSignature(signature=self.signature, public_key=self.signer_public_key),
            self.document.canonical_bytes(),
        )


class UnsignedProtectedModulesError(ValueError):
    """Raised when a deny-list document's signature does not verify."""


def sign_protected_modules(
    document: ProtectedModulesDocument, private_key: Any
) -> SignedProtectedModulesDocument:
    """Sign a deny-list document over its canonical bytes.

    The same detached-signature service release manifests and pinned
    campaign specs use, so any party holding the public key — including
    parties with no evaluator key access — can verify which deny-list a
    campaign was actually gated by.
    """
    detached = sign(private_key, document.canonical_bytes())
    return SignedProtectedModulesDocument(
        document=document,
        digest=document.digest,
        signature=detached.signature,
        signer_public_key=detached.public_key,
    )


def verify_protected_modules(signed: SignedProtectedModulesDocument) -> None:
    """Verify a signed deny-list document, raising on any mismatch.

    Raises:
        UnsignedProtectedModulesError: the digest does not match the
            document's canonical bytes, or the signature does not verify.
            The document is refused as policy — bytes nobody vouches for
            are not a deny-list, they are a suggestion.
    """
    if not signed.verify():
        raise UnsignedProtectedModulesError(
            f"protected-modules document {signed.document.document_id!r} "
            f"({signed.digest}) has no valid signature over its canonical "
            "bytes — refusing to treat it as an enforced deny-list"
        )


__all__ = [
    "DEFAULT_PROTECTED_ROOTS",
    "PROTECTED_MODULES_SCHEMA_ID",
    "InvalidProtectedModulesError",
    "ProtectedModulesDocument",
    "SignedProtectedModulesDocument",
    "UnsignedProtectedModulesError",
    "path_to_module",
    "sign_protected_modules",
    "verify_protected_modules",
]
