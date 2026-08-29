"""F4 acceptance: composite proposals round-trip through the registry.

The contract under test: a composite proposal recorded through
`record_composite_proposal` preserves its ordered typed member set —
artifact types, member digests, per-member parent edges (the multi-parent
lineage), patches, and declared executables — exactly as proposed, and the
composite digest the plugins layer computes is the digest the proposal row
carries. Requires PostgreSQL (skipped otherwise, like the rest of the
registry suite).
"""

from __future__ import annotations

from typing import Any

import pytest

from evoruntime.plugins.composite import composite_canonical_bytes, composite_digest
from evoruntime.plugins.protocol import ProposalMember
from evoruntime.registry.errors import (
    ArtifactNotFoundError,
    CircularMetadataError,
    InvalidProposalError,
)
from evoruntime.registry.service import RegistryService
from tests.registry.conftest import register_simple


def member_patch(label: str) -> dict[str, Any]:
    return {"files": [{"path": f"prompts/{label}.md", "content": label}]}


def member(label: str) -> ProposalMember:
    return ProposalMember(
        artifact_type="prompt_bundle",
        patch=member_patch(label),
        declared_executables=(),
    )


def test_composite_proposal_round_trips_with_members_in_order(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    primary = register_simple(registry_service, registry_tenant, "composite-primary")
    member_a = register_simple(registry_service, registry_tenant, "member-a")
    member_b = register_simple(registry_service, registry_tenant, "member-b")

    members = [
        {
            "artifact_type": "prompt_bundle",
            "member_digest": member_a.digest,
            "parent_digest": primary.digest,
            "patch": member_patch("a"),
            "declared_executables": [],
        },
        {
            "artifact_type": "workflow_graph",
            "member_digest": member_b.digest,
            "parent_digest": None,
            "patch": {"nodes": ["step-1"]},
            "declared_executables": ["scripts/validate.sh"],
        },
    ]
    member_objects = [
        ProposalMember(
            artifact_type="prompt_bundle",
            patch=member_patch("a"),
            declared_executables=(),
        ),
        ProposalMember(
            artifact_type="workflow_graph",
            patch={"nodes": ["step-1"]},
            declared_executables=("scripts/validate.sh",),
        ),
    ]
    composite = composite_digest(member_objects, artifact_type="prompt_bundle")
    # The composite is registered through the normal registry path with the
    # canonical member-set bytes as its body, so the registered artifact's
    # digest equals the composite digest by construction.
    registered = registry_service.register_artifact(
        tenant_id=registry_tenant,
        artifact_type="prompt_bundle",
        canonical_bytes=composite_canonical_bytes(member_objects),
        dependencies=[],
        capability_requests={},
    )
    assert registered.digest == composite
    proposal = registry_service.record_composite_proposal(
        tenant_id=registry_tenant,
        proposed_digest=registered.digest,  # composite registered as an artifact
        strategy_id="strat_composite_v1",
        members=members,
    )

    rows = registry_service.get_proposal_members(
        tenant_id=registry_tenant, proposal_id=proposal.proposal_id
    )
    assert [row.position for row in rows] == [0, 1]
    assert [row.artifact_type for row in rows] == ["prompt_bundle", "workflow_graph"]
    assert [row.member_digest for row in rows] == [member_a.digest, member_b.digest]
    assert rows[0].parent_digest == primary.digest
    assert rows[1].parent_digest is None
    assert rows[0].patch == member_patch("a")
    assert rows[1].patch == {"nodes": ["step-1"]}
    assert rows[1].declared_executables == ["scripts/validate.sh"]
    # The composite digest binds the member set: the proposal row and the
    # digest computed over the members agree by construction.
    assert proposal.proposed_digest == composite


def test_composite_member_rows_are_append_only_at_the_database_level(
    registry_service: RegistryService, registry_tenant: str, db_session: Any
) -> None:
    from sqlalchemy import text

    primary = register_simple(registry_service, registry_tenant, "append-only-composite")
    member_a = register_simple(registry_service, registry_tenant, "append-only-member")
    registry_service.record_composite_proposal(
        tenant_id=registry_tenant,
        proposed_digest=primary.digest,
        strategy_id="strat_composite_v1",
        members=[
            {
                "artifact_type": "prompt_bundle",
                "member_digest": member_a.digest,
                "parent_digest": None,
                "patch": member_patch("a"),
                "declared_executables": [],
            }
        ],
    )
    with pytest.raises(Exception, match="immutable"):
        db_session.execute(
            text(
                "UPDATE proposal_members SET artifact_type = 'workflow_graph' "
                "WHERE tenant_id = :tenant",
            ),
            {"tenant": registry_tenant},
        )


def test_composite_proposal_requires_at_least_one_member(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    primary = register_simple(registry_service, registry_tenant, "empty-composite")
    with pytest.raises(InvalidProposalError, match="at least one member"):
        registry_service.record_composite_proposal(
            tenant_id=registry_tenant,
            proposed_digest=primary.digest,
            strategy_id="strat_composite_v1",
            members=[],
        )


def test_composite_member_digest_must_resolve_to_a_registered_artifact(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    primary = register_simple(registry_service, registry_tenant, "unknown-member-composite")
    with pytest.raises(ArtifactNotFoundError):
        registry_service.record_composite_proposal(
            tenant_id=registry_tenant,
            proposed_digest=primary.digest,
            strategy_id="strat_composite_v1",
            members=[
                {
                    "artifact_type": "prompt_bundle",
                    "member_digest": f"sha256:{'d' * 64}",
                    "parent_digest": None,
                    "patch": {},
                    "declared_executables": [],
                }
            ],
        )


def test_composite_member_cannot_parent_itself(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    primary = register_simple(registry_service, registry_tenant, "self-parent-composite")
    member_a = register_simple(registry_service, registry_tenant, "self-parent-member")
    with pytest.raises(CircularMetadataError, match="cannot parent itself"):
        registry_service.record_composite_proposal(
            tenant_id=registry_tenant,
            proposed_digest=primary.digest,
            strategy_id="strat_composite_v1",
            members=[
                {
                    "artifact_type": "prompt_bundle",
                    "member_digest": member_a.digest,
                    "parent_digest": member_a.digest,
                    "patch": {},
                    "declared_executables": [],
                }
            ],
        )


def test_composite_member_parent_must_be_registered(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    primary = register_simple(registry_service, registry_tenant, "orphan-parent-composite")
    member_a = register_simple(registry_service, registry_tenant, "orphan-parent-member")
    with pytest.raises(ArtifactNotFoundError):
        registry_service.record_composite_proposal(
            tenant_id=registry_tenant,
            proposed_digest=primary.digest,
            strategy_id="strat_composite_v1",
            members=[
                {
                    "artifact_type": "prompt_bundle",
                    "member_digest": member_a.digest,
                    "parent_digest": f"sha256:{'e' * 64}",
                    "patch": {},
                    "declared_executables": [],
                }
            ],
        )


def test_composite_members_require_a_type_and_digest(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    primary = register_simple(registry_service, registry_tenant, "untyped-member-composite")
    with pytest.raises(InvalidProposalError, match="artifact_type"):
        registry_service.record_composite_proposal(
            tenant_id=registry_tenant,
            proposed_digest=primary.digest,
            strategy_id="strat_composite_v1",
            members=[{"member_digest": primary.digest, "patch": {}}],
        )


def test_composite_proposal_requires_a_strategy_id(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    primary = register_simple(registry_service, registry_tenant, "no-strategy-composite")
    with pytest.raises(InvalidProposalError, match="strategy_id"):
        registry_service.record_composite_proposal(
            tenant_id=registry_tenant,
            proposed_digest=primary.digest,
            strategy_id="",
            members=[
                {
                    "artifact_type": "prompt_bundle",
                    "member_digest": primary.digest,
                    "parent_digest": None,
                    "patch": {},
                    "declared_executables": [],
                }
            ],
        )


def test_multi_parent_edges_survive_a_reRead(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    """The single-digest single-parent proposal_records shape must not lose
    information: each member's parent edge is stored per member, so the
    composite's parent set (the union) is reconstructable from the rows."""
    parent_a = register_simple(registry_service, registry_tenant, "parent-a")
    parent_b = register_simple(registry_service, registry_tenant, "parent-b")
    member_a = register_simple(registry_service, registry_tenant, "child-a")
    member_b = register_simple(registry_service, registry_tenant, "child-b")
    proposal = registry_service.record_composite_proposal(
        tenant_id=registry_tenant,
        proposed_digest=parent_a.digest,
        strategy_id="strat_composite_v1",
        members=[
            {
                "artifact_type": "prompt_bundle",
                "member_digest": member_a.digest,
                "parent_digest": parent_a.digest,
                "patch": {},
                "declared_executables": [],
            },
            {
                "artifact_type": "workflow_graph",
                "member_digest": member_b.digest,
                "parent_digest": parent_b.digest,
                "patch": {},
                "declared_executables": [],
            },
        ],
    )
    assert proposal.parent_digest is None  # composite parents live on members
    rows = registry_service.get_proposal_members(
        tenant_id=registry_tenant, proposal_id=proposal.proposal_id
    )
    assert {row.parent_digest for row in rows} == {parent_a.digest, parent_b.digest}
