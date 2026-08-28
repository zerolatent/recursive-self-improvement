"""Composite-proposal digests (Phase 2, F4 — locked decision 3).

A composite proposal mutates an ordered set of typed members. Its content
address is the digest over that ordered member set — there is no
"bundle" artifact convention: the composite is registered as an artifact
of the *primary* member's class, whose canonical bytes are the canonical
serialization of the ordered member set.

Two digest levels, both pure functions over the member set:

- ``member_digest`` — sha256 over one member's canonical JSON
  (``artifact_type``, ``patch``, ``declared_executables``). This is the
  per-member identity recorded in the ``proposal_members`` table.
- ``composite_digest`` — the registry artifact digest of the composite
  body: sha256 over the canonical JSON of (primary artifact type, digest
  of the ordered member-set bytes, empty dependencies, no capability
  requests). It reuses the registry's own digest formula
  (:func:`evoruntime.registry.canonical.artifact_digest_for`) so a
  composite registered through the normal registry path lands on exactly
  this address — the proposal's ``proposed_digest`` and the registered
  artifact's digest are the same value by construction.

Both digests bind every member: changing any member's type, patch, or
declared executables changes its member digest, hence the composite body,
hence the composite digest. Reordering members changes the body too —
order is part of the candidate.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

from evoruntime.plugins.protocol import ProposalMember
from evoruntime.registry.canonical import (
    artifact_digest_for,
    canonical_json,
    payload_body_digest,
)


def member_canonical_dict(member: ProposalMember) -> dict[str, Any]:
    """The member as a canonical-JSON-serializable dict (sorted downstream)."""
    return {
        "artifact_type": member.artifact_type,
        "patch": member.patch,
        "declared_executables": list(member.declared_executables),
    }


def member_canonical_bytes(member: ProposalMember) -> bytes:
    """Canonical JSON bytes of one member (sorted keys, compact, UTF-8)."""
    return canonical_json(member_canonical_dict(member))


def member_digest(member: ProposalMember) -> str:
    """Content digest of one member (``sha256:...``)."""
    return "sha256:" + hashlib.sha256(member_canonical_bytes(member)).hexdigest()


def composite_canonical_bytes(members: Sequence[ProposalMember]) -> bytes:
    """Canonical bytes of the ordered member set.

    The composite artifact's canonical payload: a JSON array of the
    member canonical dicts, in proposal order. Order is significant, so
    this is an array, never a mapping or a set.
    """
    return canonical_json({"members": [member_canonical_dict(member) for member in members]})


def composite_digest(members: Sequence[ProposalMember], *, artifact_type: str) -> str:
    """The composite candidate's artifact digest.

    Computed with the registry's artifact-digest formula over the ordered
    member-set body, so a composite registered through
    ``RegistryService.register_artifact`` with these canonical bytes
    resolves to exactly this digest — the proposal's ``proposed_digest``
    and the registered artifact's content address cannot drift apart.
    """
    body_digest = payload_body_digest(composite_canonical_bytes(members))
    return artifact_digest_for(
        artifact_type=artifact_type,
        canonical_body_digest=body_digest,
        dependencies=[],
        capability_requests={},
    )


__all__ = [
    "composite_canonical_bytes",
    "composite_digest",
    "member_canonical_bytes",
    "member_canonical_dict",
    "member_digest",
]
