"""Composite-proposal digest tests (Phase 2, F4 — locked decision 3).

The contract under test: the composite digest *binds* the ordered member
set — every member's type, patch, and declared executables are folded into
the digest, order included — and it is computed with the registry's own
artifact-digest formula, so a composite registered through the normal
registry path lands on exactly the digest the proposal records.
"""

from __future__ import annotations

import hashlib
import json

from evoruntime.plugins.composite import (
    composite_canonical_bytes,
    composite_digest,
    member_canonical_bytes,
    member_digest,
)
from evoruntime.plugins.protocol import ProposalMember
from evoruntime.registry.canonical import (
    artifact_digest_for,
    canonical_json,
    payload_body_digest,
)


def make_member(
    artifact_type: str = "prompt_bundle",
    patch: dict[str, object] | None = None,
    executables: tuple[str, ...] = (),
) -> ProposalMember:
    return ProposalMember(
        artifact_type=artifact_type,
        patch=patch or {"files": [{"path": "prompts/system.md", "content": "x"}]},
        declared_executables=executables,
    )


class TestMemberDigest:
    def test_member_digest_is_sha256_over_the_canonical_member(self) -> None:
        member = make_member()
        expected = "sha256:" + hashlib.sha256(member_canonical_bytes(member)).hexdigest()
        assert member_digest(member) == expected

    def test_changing_the_patch_changes_the_member_digest(self) -> None:
        base = make_member()
        changed = make_member(patch={"files": [{"path": "prompts/system.md", "content": "y"}]})
        assert member_digest(base) != member_digest(changed)

    def test_changing_declared_executables_changes_the_member_digest(self) -> None:
        base = make_member()
        changed = make_member(executables=("scripts/run.sh",))
        assert member_digest(base) != member_digest(changed)

    def test_changing_the_artifact_type_changes_the_member_digest(self) -> None:
        base = make_member()
        changed = make_member(artifact_type="workflow_graph")
        assert member_digest(base) != member_digest(changed)


class TestCompositeDigest:
    def test_composite_digest_binds_every_member(self) -> None:
        members = [make_member(), make_member(artifact_type="workflow_graph")]
        base = composite_digest(members, artifact_type="prompt_bundle")
        # Change the first member's patch -> different composite.
        mutated_first = [make_member(patch={"files": []}), members[1]]
        assert composite_digest(mutated_first, artifact_type="prompt_bundle") != base
        # Change the second member's executables -> different composite.
        mutated_second = [
            members[0],
            make_member(artifact_type="workflow_graph", executables=("a",)),
        ]
        assert composite_digest(mutated_second, artifact_type="prompt_bundle") != base

    def test_composite_digest_is_order_sensitive(self) -> None:
        members = [make_member(), make_member(artifact_type="workflow_graph")]
        forward = composite_digest(members, artifact_type="prompt_bundle")
        backward = composite_digest(list(reversed(members)), artifact_type="prompt_bundle")
        assert forward != backward

    def test_composite_digest_uses_the_registry_artifact_formula(self) -> None:
        """A composite registered through the normal registry path lands on
        exactly this digest — proposal and registry cannot drift apart."""
        members = [make_member(), make_member(artifact_type="workflow_graph")]
        body = composite_canonical_bytes(members)
        expected = artifact_digest_for(
            artifact_type="prompt_bundle",
            canonical_body_digest=payload_body_digest(body),
            dependencies=[],
            capability_requests={},
        )
        assert composite_digest(members, artifact_type="prompt_bundle") == expected

    def test_composite_digest_is_deterministic(self) -> None:
        members = [make_member(), make_member(artifact_type="workflow_graph")]
        first = composite_digest(members, artifact_type="prompt_bundle")
        second = composite_digest(list(members), artifact_type="prompt_bundle")
        assert first == second

    def test_composite_body_is_the_ordered_member_set_itself(self) -> None:
        """The canonical body is the ordered member list — there is no
        separate bundle-artifact wrapper convention."""
        members = [make_member(), make_member(artifact_type="workflow_graph")]
        parsed = json.loads(composite_canonical_bytes(members))
        assert [m["artifact_type"] for m in parsed["members"]] == [
            "prompt_bundle",
            "workflow_graph",
        ]

    def test_member_digest_is_stable_across_dict_key_order(self) -> None:
        a = ProposalMember(artifact_type="t", patch={"x": 1, "y": 2}, declared_executables=())
        b = ProposalMember(artifact_type="t", patch={"y": 2, "x": 1}, declared_executables=())
        assert member_digest(a) == member_digest(b)
        assert member_canonical_bytes(a) == canonical_json(
            {"artifact_type": "t", "patch": {"y": 2, "x": 1}, "declared_executables": []}
        )
