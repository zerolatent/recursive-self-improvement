"""Pure hash-chain function tests — no database involved."""

from __future__ import annotations

from evoruntime.core.events import parse_wire_envelope
from evoruntime.core.hashchain import (
    GENESIS_HASH,
    compute_event_hash,
    compute_event_hash_from_bytes,
)
from tests.support.factories import make_raw_event


def test_genesis_hash_is_64_hex_zeros() -> None:
    assert GENESIS_HASH == "0" * 64
    assert len(GENESIS_HASH) == 64


def test_hash_is_deterministic_for_same_envelope_and_prev_hash() -> None:
    envelope = parse_wire_envelope(make_raw_event(0))
    assert compute_event_hash(envelope, GENESIS_HASH) == compute_event_hash(envelope, GENESIS_HASH)


def test_hash_changes_with_prev_hash() -> None:
    envelope = parse_wire_envelope(make_raw_event(0))
    hash_a = compute_event_hash(envelope, GENESIS_HASH)
    hash_b = compute_event_hash(envelope, "1" * 64)
    assert hash_a != hash_b


def test_hash_changes_with_envelope_content() -> None:
    envelope_a = parse_wire_envelope(make_raw_event(0))
    envelope_b = parse_wire_envelope(make_raw_event(1))
    assert compute_event_hash(envelope_a, GENESIS_HASH) != compute_event_hash(
        envelope_b, GENESIS_HASH
    )


def test_compute_event_hash_from_bytes_matches_compute_event_hash() -> None:
    envelope = parse_wire_envelope(make_raw_event(0))
    prev_hash = "a" * 64
    assert compute_event_hash(envelope, prev_hash) == compute_event_hash_from_bytes(
        envelope.canonical_bytes(), prev_hash
    )


def test_chain_of_hashes_is_order_sensitive() -> None:
    """Swapping the order two events are chained in must change every
    downstream hash — this is what makes reordering detectable."""
    envelope_a = parse_wire_envelope(make_raw_event(0))
    envelope_b = parse_wire_envelope(make_raw_event(1))

    forward_first = compute_event_hash(envelope_a, GENESIS_HASH)
    forward_second = compute_event_hash(envelope_b, forward_first)

    reversed_first = compute_event_hash(envelope_b, GENESIS_HASH)
    reversed_second = compute_event_hash(envelope_a, reversed_first)

    assert forward_second != reversed_second
