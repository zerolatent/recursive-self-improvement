"""D4 acceptance: append-only is enforced at the database level, not just
in the ORM/service layer.

Connects as the same role the application uses (mirroring CI's `postgres`
role) and asserts a hand-written `UPDATE`/`DELETE` against `lineage_nodes`
or `lineage_edges` fails — proving the trigger fires regardless of which
code path attempts the mutation.
"""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Session

from evoruntime.lineage.service import LineageService


@pytest.fixture
def lineage_service(db_session: Session) -> LineageService:
    return LineageService(db_session)


def test_update_lineage_node_is_rejected(
    db_session: Session, lineage_service: LineageService
) -> None:
    node = lineage_service.append_node(
        tenant_id="tnt_1", node_type="artifact", external_ref="art_1"
    )
    db_session.commit()

    with pytest.raises(ProgrammingError, match="append-only table"):
        db_session.execute(
            text("UPDATE lineage_nodes SET node_type = 'mutated' WHERE id = :id"),
            {"id": str(node.id)},
        )
    db_session.rollback()


def test_delete_lineage_node_is_rejected(
    db_session: Session, lineage_service: LineageService
) -> None:
    node = lineage_service.append_node(
        tenant_id="tnt_1", node_type="artifact", external_ref="art_1"
    )
    db_session.commit()

    with pytest.raises(ProgrammingError, match="append-only table"):
        db_session.execute(text("DELETE FROM lineage_nodes WHERE id = :id"), {"id": str(node.id)})
    db_session.rollback()


def test_update_lineage_edge_is_rejected(
    db_session: Session, lineage_service: LineageService
) -> None:
    source = lineage_service.append_node(
        tenant_id="tnt_1", node_type="artifact", external_ref="art_1"
    )
    target = lineage_service.append_node(
        tenant_id="tnt_1", node_type="artifact", external_ref="art_2"
    )
    edge = lineage_service.append_edge(
        tenant_id="tnt_1",
        source_node_id=source.id,
        target_node_id=target.id,
        edge_type="derived_from",
    )
    db_session.commit()

    with pytest.raises(ProgrammingError, match="append-only table"):
        db_session.execute(
            text("UPDATE lineage_edges SET edge_type = 'mutated' WHERE id = :id"),
            {"id": str(edge.id)},
        )
    db_session.rollback()


def test_delete_lineage_edge_is_rejected(
    db_session: Session, lineage_service: LineageService
) -> None:
    source = lineage_service.append_node(
        tenant_id="tnt_1", node_type="artifact", external_ref="art_1"
    )
    target = lineage_service.append_node(
        tenant_id="tnt_1", node_type="artifact", external_ref="art_2"
    )
    edge = lineage_service.append_edge(
        tenant_id="tnt_1",
        source_node_id=source.id,
        target_node_id=target.id,
        edge_type="derived_from",
    )
    db_session.commit()

    with pytest.raises(ProgrammingError, match="append-only table"):
        db_session.execute(text("DELETE FROM lineage_edges WHERE id = :id"), {"id": str(edge.id)})
    db_session.rollback()


def test_insert_is_still_allowed(db_session: Session, lineage_service: LineageService) -> None:
    """The trigger only fires on UPDATE/DELETE — inserts (the only
    mutation append-only tables permit) must keep working.
    """
    node = lineage_service.append_node(
        tenant_id="tnt_1", node_type="artifact", external_ref="art_1"
    )
    db_session.commit()
    assert node.id is not None
