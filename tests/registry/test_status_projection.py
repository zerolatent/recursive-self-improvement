"""E1 acceptance: current status is a projection over the append-only
event stream — the artifact_current_status view follows the latest event,
and no status is ever stored on the artifact row itself."""

from __future__ import annotations

import time
import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session

from evoruntime.registry.service import RegistryService


def test_status_is_none_before_any_event(
    registry_service: RegistryService, registry_tenant: str, register: object
) -> None:
    artifact = register("fresh")  # type: ignore[operator]
    assert (
        registry_service.current_status(tenant_id=registry_tenant, artifact_digest=artifact.digest)
        is None
    )


def test_projection_follows_the_latest_event(
    registry_service: RegistryService,
    registry_tenant: str,
    db_session: Session,
    register: object,
) -> None:
    artifact = register("lifecycle")  # type: ignore[operator]
    assert (
        registry_service.current_status(tenant_id=registry_tenant, artifact_digest=artifact.digest)
        is None
    )

    registry_service.append_status_event(
        tenant_id=registry_tenant,
        artifact_digest=artifact.digest,
        kind="nominate",
        actor_identity="trusted-selector",
    )
    db_session.commit()  # distinct created_at: the view orders on it
    assert (
        registry_service.current_status(tenant_id=registry_tenant, artifact_digest=artifact.digest)
        == "nominate"
    )

    registry_service.append_status_event(
        tenant_id=registry_tenant,
        artifact_digest=artifact.digest,
        kind="quarantine",
        actor_identity="evaluator",
        reason="leak finding",
    )
    assert (
        registry_service.current_status(tenant_id=registry_tenant, artifact_digest=artifact.digest)
        == "quarantine"
    )


def test_projection_is_per_tenant(registry_service: RegistryService, registry_tenant: str) -> None:
    """Two tenants registering byte-identical content have independent
    status streams; one tenant's events never leak into the other's
    projection."""
    other_tenant = f"tnt_{uuid.uuid4().hex[:12]}"
    # Same canonical bytes in both tenants -> same digest, different rows.
    body = f'{{"shared":"{uuid.uuid4().hex}"}}'.encode()
    mine = registry_service.register_artifact(
        tenant_id=registry_tenant, artifact_type="prompt_bundle", canonical_bytes=body
    )
    theirs = registry_service.register_artifact(
        tenant_id=other_tenant, artifact_type="prompt_bundle", canonical_bytes=body
    )
    assert mine.digest == theirs.digest

    registry_service.append_status_event(
        tenant_id=registry_tenant,
        artifact_digest=mine.digest,
        kind="nominate",
        actor_identity="trusted-selector",
    )

    assert (
        registry_service.current_status(tenant_id=registry_tenant, artifact_digest=mine.digest)
        == "nominate"
    )
    assert (
        registry_service.current_status(tenant_id=other_tenant, artifact_digest=theirs.digest)
        is None
    )


def test_projection_view_reflects_event_ordering(
    registry_service: RegistryService, registry_tenant: str, db_session: Session, register: object
) -> None:
    """The view orders by created_at then event_id: the newest event wins,
    and the projection exposes who acted and why."""
    artifact = register("view-ordering")  # type: ignore[operator]
    registry_service.append_status_event(
        tenant_id=registry_tenant,
        artifact_digest=artifact.digest,
        kind="nominate",
        actor_identity="trusted-selector",
    )
    db_session.commit()  # distinct created_at: the view orders on it
    time.sleep(0.01)
    registry_service.append_status_event(
        tenant_id=registry_tenant,
        artifact_digest=artifact.digest,
        kind="supersede",
        actor_identity="release-controller",
        reason="superseded by rel_2",
    )
    db_session.commit()

    row = db_session.execute(
        text(
            "SELECT current_status, last_actor_identity, last_reason FROM "
            "artifact_current_status WHERE tenant_id = :t AND artifact_digest = :d"
        ),
        {"t": registry_tenant, "d": artifact.digest},
    ).one()
    assert row.current_status == "supersede"
    assert row.last_actor_identity == "release-controller"
    assert row.last_reason == "superseded by rel_2"
