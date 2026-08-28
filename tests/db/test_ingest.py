"""Ingest persistence tests: chain assignment, duplicates, per-tenant isolation."""

from __future__ import annotations

import pytest
from sqlalchemy.orm import Session, sessionmaker

from evoruntime.core.events import parse_wire_envelope
from evoruntime.db.base import session_scope
from evoruntime.db.chain_verification import verify_chain
from evoruntime.db.ingest import DuplicateEventError, ingest_envelope
from evoruntime.db.models.events import Event
from tests.support.factories import make_raw_batch, make_raw_event


def test_first_event_chains_from_genesis(session_factory: sessionmaker[Session]) -> None:
    envelope = parse_wire_envelope(make_raw_event(0, tenant_id="tnt_a"))
    with session_scope(session_factory) as session:
        row = ingest_envelope(session, envelope)

    assert row.chain_seq == 1
    assert row.prev_hash == "0" * 64
    assert len(row.event_hash) == 64


def test_sequential_events_chain_in_order(session_factory: sessionmaker[Session]) -> None:
    tenant_id = "tnt_b"
    rows: list[Event] = []
    for raw in make_raw_batch(5, tenant_id=tenant_id):
        envelope = parse_wire_envelope(raw)
        with session_scope(session_factory) as session:
            rows.append(ingest_envelope(session, envelope))

    assert [row.chain_seq for row in rows] == [1, 2, 3, 4, 5]
    for previous, current in zip(rows, rows[1:], strict=False):
        assert current.prev_hash == previous.event_hash

    with session_factory() as session:
        result = verify_chain(session, tenant_id)
    assert result.valid
    assert result.event_count == 5


def test_duplicate_event_id_is_rejected(session_factory: sessionmaker[Session]) -> None:
    envelope = parse_wire_envelope(make_raw_event(0, tenant_id="tnt_c"))
    with session_scope(session_factory) as session:
        ingest_envelope(session, envelope)

    with pytest.raises(DuplicateEventError), session_scope(session_factory) as session:
        ingest_envelope(session, envelope)

    # The chain must be untouched by the rejected duplicate — still one row.
    with session_factory() as session:
        result = verify_chain(session, "tnt_c")
    assert result.event_count == 1


def test_tenants_chain_independently(session_factory: sessionmaker[Session]) -> None:
    # event_id is globally unique (not scoped per tenant), so the two
    # tenants' first events still need distinct indices.
    envelope_a = parse_wire_envelope(make_raw_event(0, tenant_id="tnt_x"))
    envelope_b = parse_wire_envelope(make_raw_event(1, tenant_id="tnt_y"))

    with session_scope(session_factory) as session:
        row_a = ingest_envelope(session, envelope_a)
    with session_scope(session_factory) as session:
        row_b = ingest_envelope(session, envelope_b)

    # Both are the first event in their own tenant's chain.
    assert row_a.chain_seq == 1
    assert row_b.chain_seq == 1
    assert row_a.prev_hash == row_b.prev_hash == "0" * 64
