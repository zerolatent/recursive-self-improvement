"""Service-layer API for appending lineage and resolving provenance graphs.

Nodes and edges are append-only (enforced at the DB level by a trigger —
see the lineage-store migration), so this module only ever inserts; there
is no update/delete path for either table.
"""

from __future__ import annotations

import uuid
from typing import Literal

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from evoruntime.db.models.lineage import LineageEdge, LineageNode
from evoruntime.lineage.exceptions import LineageNodeNotFoundError

Direction = Literal["upstream", "downstream"]

#: Guards against runaway traversal on a deep or (accidentally) cyclic
#: graph; combined with the per-path visited-set check below, so cycles
#: terminate immediately rather than merely being capped by depth.
DEFAULT_MAX_TRAVERSAL_DEPTH = 50

_UPSTREAM_JOIN = (
    "JOIN lineage_nodes p ON p.id = e.source_node_id JOIN ancestry a ON e.target_node_id = a.id"
)
_DOWNSTREAM_JOIN = (
    "JOIN lineage_nodes p ON p.id = e.target_node_id JOIN ancestry a ON e.source_node_id = a.id"
)

_TRAVERSAL_SQL = """
WITH RECURSIVE ancestry AS (
    SELECT n.id, n.tenant_id, n.node_type, n.external_ref, n.node_metadata, n.created_at,
           0 AS depth, ARRAY[n.id] AS visited
    FROM lineage_nodes n
    WHERE n.id = :node_id AND n.tenant_id = :tenant_id

    UNION ALL

    SELECT p.id, p.tenant_id, p.node_type, p.external_ref, p.node_metadata, p.created_at,
           a.depth + 1, a.visited || p.id
    FROM lineage_edges e
    {join_clause}
    WHERE e.tenant_id = :tenant_id
      AND a.depth < :max_depth
      AND NOT (p.id = ANY(a.visited))
)
SELECT DISTINCT id, tenant_id, node_type, external_ref, node_metadata, created_at
FROM ancestry
WHERE id <> :node_id
ORDER BY id;
"""


class LineageService:
    """Appends provenance nodes/edges and resolves ancestry graphs."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def append_node(
        self,
        *,
        tenant_id: str,
        node_type: str,
        external_ref: str,
        metadata: dict[str, object] | None = None,
    ) -> LineageNode:
        node = LineageNode(
            tenant_id=tenant_id,
            node_type=node_type,
            external_ref=external_ref,
            node_metadata=metadata or {},
        )
        self._session.add(node)
        self._session.flush()
        return node

    def append_edge(
        self,
        *,
        tenant_id: str,
        source_node_id: uuid.UUID,
        target_node_id: uuid.UUID,
        edge_type: str,
        metadata: dict[str, object] | None = None,
    ) -> LineageEdge:
        """Record a directed edge `source -> target` (e.g. "derived_from").

        Both endpoints must already exist and belong to `tenant_id` —
        raises `LineageNodeNotFoundError` otherwise, since an edge to a
        node from another tenant (or no node at all) would be a tenancy
        violation baked permanently into an append-only table.
        """
        for node_id in (source_node_id, target_node_id):
            self._get_node_or_raise(tenant_id=tenant_id, node_id=node_id)

        edge = LineageEdge(
            tenant_id=tenant_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            edge_type=edge_type,
            edge_metadata=metadata or {},
        )
        self._session.add(edge)
        self._session.flush()
        return edge

    def resolve_upstream(
        self, *, tenant_id: str, node_id: uuid.UUID, max_depth: int = DEFAULT_MAX_TRAVERSAL_DEPTH
    ) -> list[LineageNode]:
        """Return every ancestor of `node_id` (nodes it was derived from,
        transitively), nearest to `max_depth` hops away.
        """
        return self._traverse(
            tenant_id=tenant_id, node_id=node_id, max_depth=max_depth, direction="upstream"
        )

    def resolve_downstream(
        self, *, tenant_id: str, node_id: uuid.UUID, max_depth: int = DEFAULT_MAX_TRAVERSAL_DEPTH
    ) -> list[LineageNode]:
        """Return every descendant of `node_id` (nodes derived from it,
        transitively), nearest to `max_depth` hops away.
        """
        return self._traverse(
            tenant_id=tenant_id, node_id=node_id, max_depth=max_depth, direction="downstream"
        )

    def _get_node_or_raise(self, *, tenant_id: str, node_id: uuid.UUID) -> LineageNode:
        node = self._session.execute(
            select(LineageNode).where(LineageNode.id == node_id, LineageNode.tenant_id == tenant_id)
        ).scalar_one_or_none()
        if node is None:
            raise LineageNodeNotFoundError(f"no lineage node {node_id} for tenant {tenant_id!r}")
        return node

    def _traverse(
        self, *, tenant_id: str, node_id: uuid.UUID, max_depth: int, direction: Direction
    ) -> list[LineageNode]:
        self._get_node_or_raise(tenant_id=tenant_id, node_id=node_id)
        join_clause = _UPSTREAM_JOIN if direction == "upstream" else _DOWNSTREAM_JOIN
        rows = self._session.execute(
            text(_TRAVERSAL_SQL.format(join_clause=join_clause)),
            {"node_id": str(node_id), "tenant_id": tenant_id, "max_depth": max_depth},
        ).all()
        return [
            LineageNode(
                id=row.id,
                tenant_id=row.tenant_id,
                node_type=row.node_type,
                external_ref=row.external_ref,
                node_metadata=row.node_metadata,
                created_at=row.created_at,
            )
            for row in rows
        ]
