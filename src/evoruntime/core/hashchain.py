"""Per-tenant tamper-evident hash chain (PRD §18.3 / spec D2).

Each event's `event_hash` is `sha256(canonical_envelope_bytes || prev_hash)`.
The chain is scoped per tenant: tenant A's events never reference tenant B's
hashes, so tenants can be verified (and their data deleted) independently.

These are pure functions over bytes/strings so they can be unit-tested
without a database and reused identically by the ingest path and the
verification path — the two must never compute the hash differently.
"""

from __future__ import annotations

import hashlib

from evoruntime.core.events import EventEnvelope

# Sentinel `prev_hash` for the first event in a tenant's chain. Same length
# as a real sha256 hex digest so chain rows have a uniform column shape.
GENESIS_HASH = "0" * 64


def compute_event_hash(envelope: EventEnvelope, prev_hash: str) -> str:
    """Compute the tamper-evident hash for `envelope` given its predecessor.

    `prev_hash` must be the previous event's `event_hash` in this tenant's
    chain, or `GENESIS_HASH` for the first event.
    """
    digest = hashlib.sha256()
    digest.update(envelope.canonical_bytes())
    digest.update(prev_hash.encode("ascii"))
    return digest.hexdigest()


def compute_event_hash_from_bytes(canonical_bytes: bytes, prev_hash: str) -> str:
    """Same computation as `compute_event_hash`, from already-canonicalized
    bytes.

    Used by chain verification, which recomputes hashes from bytes stored
    (or reconstructed) at ingest time rather than re-validating envelopes.
    """
    digest = hashlib.sha256()
    digest.update(canonical_bytes)
    digest.update(prev_hash.encode("ascii"))
    return digest.hexdigest()
