"""E1 acceptance: status events are append-only at the database level, and
the current status is a projection over the event stream — never a stored
column and never part of any digest."""

from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.orm import Session

from evoruntime.registry.errors import InvalidStatusEventError
from evoruntime.registry.service import RegistryService


def test_update_status_event_is_rejected(
    registry_service: RegistryService, registry_tenant: str, db_session: Session, register: object
) -> None:
    artifact = register("status-target")  # type: ignore[operator]
    event = registry_service.append_status_event(
        tenant_id=registry_tenant,
        artifact_digest=artifact.digest,
        kind="nominate",
        actor_identity="release-controller",
    )
    db_session.commit()

    with pytest.raises(ProgrammingError, match="append-only table"):
        db_session.execute(
            text("UPDATE artifact_status_events SET kind = 'reject' WHERE id = :id"),
            {"id": str(event.id)},
        )
    db_session.rollback()


def test_delete_status_event_is_rejected(
    registry_service: RegistryService, registry_tenant: str, db_session: Session, register: object
) -> None:
    artifact = register("delete-target")  # type: ignore[operator]
    event = registry_service.append_status_event(
        tenant_id=registry_tenant,
        artifact_digest=artifact.digest,
        kind="quarantine",
        actor_identity="evaluator",
        reason="leak finding",
    )
    db_session.commit()

    with pytest.raises(ProgrammingError, match="append-only table"):
        db_session.execute(
            text("DELETE FROM artifact_status_events WHERE id = :id"), {"id": str(event.id)}
        )
    db_session.rollback()


def test_unknown_kind_is_rejected_by_the_service(
    registry_service: RegistryService, registry_tenant: str, register: object
) -> None:
    artifact = register("bad-kind")  # type: ignore[operator]
    with pytest.raises(InvalidStatusEventError, match="not one of"):
        registry_service.append_status_event(
            tenant_id=registry_tenant,
            artifact_digest=artifact.digest,
            kind="promote",  # not one of the six PRD §9.2 kinds
            actor_identity="release-controller",
        )


def test_unknown_kind_is_rejected_by_a_database_check_constraint(
    registry_service: RegistryService, registry_tenant: str, db_session: Session, register: object
) -> None:
    """Even a hand-written INSERT cannot introduce an unknown kind — the
    CHECK constraint holds regardless of which code path writes."""
    artifact = register("db-kind")  # type: ignore[operator]
    # A raw INSERT executes immediately — the violation surfaces on execute.
    with pytest.raises(IntegrityError, match="ck_artifact_status_events_kind"):
        db_session.execute(
            text(
                "INSERT INTO artifact_status_events (id, tenant_id, event_id, artifact_digest, "
                "kind, actor_identity) VALUES (gen_random_uuid(), :tenant, 'ase_bad', :digest, "
                "'promote', 'someone')"
            ),
            {"tenant": registry_tenant, "digest": artifact.digest},
        )
    db_session.rollback()


def test_empty_actor_identity_is_rejected(
    registry_service: RegistryService, registry_tenant: str, register: object
) -> None:
    artifact = register("no-actor")  # type: ignore[operator]
    with pytest.raises(InvalidStatusEventError, match="actor_identity"):
        registry_service.append_status_event(
            tenant_id=registry_tenant,
            artifact_digest=artifact.digest,
            kind="nominate",
            actor_identity="",
        )


def test_status_event_for_unknown_artifact_is_rejected(
    registry_service: RegistryService, registry_tenant: str
) -> None:
    with pytest.raises(Exception, match="no artifact"):
        registry_service.append_status_event(
            tenant_id=registry_tenant,
            artifact_digest=f"sha256:{'7' * 64}",
            kind="nominate",
            actor_identity="release-controller",
        )


def test_all_six_kinds_are_accepted(
    registry_service: RegistryService, registry_tenant: str, register: object
) -> None:
    artifact = register("all-kinds")  # type: ignore[operator]
    for kind in ("nominate", "reject", "revoke", "expire", "quarantine", "supersede"):
        event = registry_service.append_status_event(
            tenant_id=registry_tenant,
            artifact_digest=artifact.digest,
            kind=kind,
            actor_identity="release-controller",
        )
        assert event.kind == kind
