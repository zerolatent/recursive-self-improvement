"""D2 acceptance: chain verification detects mutation/reorder at 10k-event
scale, not just the small fixtures in `test_chain_verification.py`.

Uses `insert_chain_fixture` (one bulk commit) rather than the real
`ingest_envelope` per-event path — verification correctness at scale is a
read-side property of `verify_chain` walking 10,000 rows, independent of how
slowly or quickly those rows were originally committed.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from evoruntime.db.base import session_scope
from evoruntime.db.chain_verification import verify_chain
from evoruntime.db.models.events import Event
from tests.support.factories import insert_chain_fixture

FIXTURE_SIZE = 10_000


def test_untampered_10k_chain_is_valid(session_factory: sessionmaker[Session]) -> None:
    tenant_id = "tnt_10kvalid"
    with session_factory() as session:
        insert_chain_fixture(session, tenant_id=tenant_id, count=FIXTURE_SIZE)

    with session_factory() as session:
        result = verify_chain(session, tenant_id)

    assert result.valid
    assert result.event_count == FIXTURE_SIZE
    assert result.violations == ()


def test_flipped_byte_in_10k_chain_is_detected(session_factory: sessionmaker[Session]) -> None:
    tenant_id = "tnt_10kflipped"
    with session_factory() as session:
        insert_chain_fixture(session, tenant_id=tenant_id, count=FIXTURE_SIZE)

    tampered_seq = FIXTURE_SIZE // 2
    with session_scope(session_factory) as session:
        target = session.execute(
            select(Event).where(Event.tenant_id == tenant_id, Event.chain_seq == tampered_seq)
        ).scalar_one()
        target.environment_digest = target.environment_digest[:-1] + (
            "0" if target.environment_digest[-1] != "0" else "1"
        )

    with session_factory() as session:
        result = verify_chain(session, tenant_id)

    assert not result.valid
    assert result.event_count == FIXTURE_SIZE
    assert any(
        v.reason == "hash_mismatch" and v.chain_seq == tampered_seq for v in result.violations
    )
    assert not any(v.chain_seq < tampered_seq for v in result.violations)


def test_swapped_pair_in_10k_chain_is_detected(session_factory: sessionmaker[Session]) -> None:
    tenant_id = "tnt_10kswapped"
    with session_factory() as session:
        insert_chain_fixture(session, tenant_id=tenant_id, count=FIXTURE_SIZE)

    seq_a, seq_b = FIXTURE_SIZE // 2, FIXTURE_SIZE // 2 + 1
    with session_scope(session_factory) as session:
        row_a = session.execute(
            select(Event).where(Event.tenant_id == tenant_id, Event.chain_seq == seq_a)
        ).scalar_one()
        row_b = session.execute(
            select(Event).where(Event.tenant_id == tenant_id, Event.chain_seq == seq_b)
        ).scalar_one()
        # unique(tenant_id, chain_seq) is checked immediately, so stage the
        # swap through a sentinel value neither row uses.
        row_a.chain_seq = -1
        session.flush()
        row_b.chain_seq = seq_a
        session.flush()
        row_a.chain_seq = seq_b
        session.flush()

    with session_factory() as session:
        result = verify_chain(session, tenant_id)

    assert not result.valid
    assert result.event_count == FIXTURE_SIZE
    assert any(v.reason == "prev_hash_mismatch" for v in result.violations)
