"""Chain tamper-detection tests (spec D2 acceptance): a valid chain passes;
a single flipped byte and a swapped pair are both detected."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from evoruntime.core.events import parse_wire_envelope
from evoruntime.db.base import session_scope
from evoruntime.db.chain_verification import verify_chain
from evoruntime.db.ingest import ingest_envelope
from evoruntime.db.models.events import Event
from tests.support.factories import make_raw_batch


def _ingest_batch(session_factory: sessionmaker[Session], tenant_id: str, count: int) -> None:
    for raw in make_raw_batch(count, tenant_id=tenant_id):
        envelope = parse_wire_envelope(raw)
        with session_scope(session_factory) as session:
            ingest_envelope(session, envelope)


def test_untampered_chain_is_valid(session_factory: sessionmaker[Session]) -> None:
    tenant_id = "tnt_valid"
    _ingest_batch(session_factory, tenant_id, 10)

    with session_factory() as session:
        result = verify_chain(session, tenant_id)

    assert result.valid
    assert result.event_count == 10
    assert result.violations == ()


def test_empty_chain_is_valid(session_factory: sessionmaker[Session]) -> None:
    with session_factory() as session:
        result = verify_chain(session, "tnt_never_seen")

    assert result.valid
    assert result.event_count == 0


def test_flipped_byte_in_stored_field_is_detected(session_factory: sessionmaker[Session]) -> None:
    tenant_id = "tnt_flipped"
    _ingest_batch(session_factory, tenant_id, 10)

    # Mutate one stored envelope field post-ingest — this is the "single
    # flipped byte" scenario: the row's own event_hash was computed over the
    # original bytes and no longer matches once any field changes.
    with session_scope(session_factory) as session:
        target = session.execute(
            select(Event).where(Event.tenant_id == tenant_id, Event.chain_seq == 5)
        ).scalar_one()
        target.environment_digest = target.environment_digest[:-1] + (
            "0" if target.environment_digest[-1] != "0" else "1"
        )

    with session_factory() as session:
        result = verify_chain(session, tenant_id)

    assert not result.valid
    assert any(v.reason == "hash_mismatch" and v.chain_seq == 5 for v in result.violations)
    # Everything before the tampered row is unaffected.
    assert not any(v.chain_seq < 5 for v in result.violations)


def test_swapped_pair_is_detected(session_factory: sessionmaker[Session]) -> None:
    tenant_id = "tnt_swapped"
    _ingest_batch(session_factory, tenant_id, 10)

    # Swap the chain_seq of two adjacent rows — each row's own event_hash
    # still matches its own (untouched) prev_hash, so only the reorder check
    # (a row's prev_hash no longer matching what now precedes it) can catch
    # this; hash_mismatch alone would miss it entirely.
    with session_scope(session_factory) as session:
        row_a = session.execute(
            select(Event).where(Event.tenant_id == tenant_id, Event.chain_seq == 4)
        ).scalar_one()
        row_b = session.execute(
            select(Event).where(Event.tenant_id == tenant_id, Event.chain_seq == 5)
        ).scalar_one()
        seq_a, seq_b = row_a.chain_seq, row_b.chain_seq
        # The unique(tenant_id, chain_seq) constraint is checked immediately
        # (not deferred), so a direct in-place swap would transiently collide
        # mid-flush. Stage through a sentinel value neither row uses instead.
        row_a.chain_seq = -1
        session.flush()
        row_b.chain_seq = seq_a
        session.flush()
        row_a.chain_seq = seq_b
        session.flush()

    with session_factory() as session:
        result = verify_chain(session, tenant_id)

    assert not result.valid
    assert any(v.reason == "prev_hash_mismatch" for v in result.violations)
