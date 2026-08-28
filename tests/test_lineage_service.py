"""Tests for `LineageService`: node/edge append and ancestry traversal."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.orm import Session

from evoruntime.lineage.exceptions import LineageNodeNotFoundError
from evoruntime.lineage.service import LineageService


@pytest.fixture
def service(db_session: Session) -> LineageService:
    return LineageService(db_session)


def test_append_node_defaults_metadata_to_empty_dict(service: LineageService) -> None:
    node = service.append_node(tenant_id="tnt_1", node_type="artifact", external_ref="art_1")
    assert node.node_metadata == {}
    assert node.tenant_id == "tnt_1"


def test_append_edge_requires_existing_nodes(service: LineageService) -> None:
    source = service.append_node(tenant_id="tnt_1", node_type="artifact", external_ref="art_1")

    with pytest.raises(LineageNodeNotFoundError):
        service.append_edge(
            tenant_id="tnt_1",
            source_node_id=source.id,
            target_node_id=uuid.uuid4(),
            edge_type="derived_from",
        )


def test_append_edge_rejects_cross_tenant_target(service: LineageService) -> None:
    """A node from a different tenant must be invisible to `append_edge`,
    even though the row exists — an edge crossing tenants would be a
    tenancy violation baked permanently into an append-only table.
    """
    source = service.append_node(tenant_id="tnt_1", node_type="artifact", external_ref="art_1")
    other_tenant_node = service.append_node(
        tenant_id="tnt_2", node_type="artifact", external_ref="art_2"
    )

    with pytest.raises(LineageNodeNotFoundError):
        service.append_edge(
            tenant_id="tnt_1",
            source_node_id=source.id,
            target_node_id=other_tenant_node.id,
            edge_type="derived_from",
        )


def test_resolve_upstream_returns_transitive_ancestors(service: LineageService) -> None:
    # grandparent -> parent -> child
    grandparent = service.append_node(tenant_id="tnt_1", node_type="dataset", external_ref="ds_1")
    parent = service.append_node(tenant_id="tnt_1", node_type="artifact", external_ref="art_1")
    child = service.append_node(tenant_id="tnt_1", node_type="artifact", external_ref="art_2")
    service.append_edge(
        tenant_id="tnt_1",
        source_node_id=grandparent.id,
        target_node_id=parent.id,
        edge_type="derived_from",
    )
    service.append_edge(
        tenant_id="tnt_1",
        source_node_id=parent.id,
        target_node_id=child.id,
        edge_type="derived_from",
    )

    ancestors = service.resolve_upstream(tenant_id="tnt_1", node_id=child.id)

    assert {node.id for node in ancestors} == {grandparent.id, parent.id}


def test_resolve_downstream_returns_transitive_descendants(service: LineageService) -> None:
    root = service.append_node(tenant_id="tnt_1", node_type="dataset", external_ref="ds_1")
    child = service.append_node(tenant_id="tnt_1", node_type="artifact", external_ref="art_1")
    grandchild = service.append_node(tenant_id="tnt_1", node_type="artifact", external_ref="art_2")
    service.append_edge(
        tenant_id="tnt_1", source_node_id=root.id, target_node_id=child.id, edge_type="derived_from"
    )
    service.append_edge(
        tenant_id="tnt_1",
        source_node_id=child.id,
        target_node_id=grandchild.id,
        edge_type="derived_from",
    )

    descendants = service.resolve_downstream(tenant_id="tnt_1", node_id=root.id)

    assert {node.id for node in descendants} == {child.id, grandchild.id}


def test_resolve_upstream_is_scoped_to_tenant(service: LineageService) -> None:
    parent = service.append_node(tenant_id="tnt_1", node_type="artifact", external_ref="art_1")
    child = service.append_node(tenant_id="tnt_1", node_type="artifact", external_ref="art_2")
    service.append_edge(
        tenant_id="tnt_1",
        source_node_id=parent.id,
        target_node_id=child.id,
        edge_type="derived_from",
    )

    with pytest.raises(LineageNodeNotFoundError):
        service.resolve_upstream(tenant_id="tnt_2", node_id=child.id)


def test_resolve_upstream_on_leaf_node_returns_empty(service: LineageService) -> None:
    leaf = service.append_node(tenant_id="tnt_1", node_type="artifact", external_ref="art_1")
    assert service.resolve_upstream(tenant_id="tnt_1", node_id=leaf.id) == []
