"""Canary-token scheme for holdout-exfiltration fixtures (H7) and the H8 secrecy suite.

Contract, designed so H8's 10k-token secrecy suite can consume it as-is:

* A token is ``EVO-CANARY-<FIXTURE_ID>-<hex12>``, where ``hex12`` is the
  first 12 hex characters of ``sha256("<fixture_id>:<index>")``. Tokens
  are therefore deterministic per ``(fixture_id, index)``: a test (or the
  H8 suite) regenerates them from the fixture id alone, and two runs of
  the same suite plant and detect identical tokens.
* The ``EVO-CANARY-`` prefix is greppable. Any artifact, transcript, or
  egress payload can be scanned for the prefix without parsing content,
  and a planted token is distinguishable from incidental text by format
  alone.
* Tokens live in a synthetic namespace. They are deliberately not shaped
  like real credentials (no AWS/Stripe/GitHub key patterns), so the DLP
  corpus's real-secret rules must never fire on them — asserted in
  ``tests/test_fixtures_h7.py`` — and real-secret scanners elsewhere can
  ignore the prefix instead of tripping on it.
* Indexes are unique per fixture: a scenario planting N tokens uses
  ``canary_tokens(fixture_id, N)`` and every token is distinct. H8's
  10k-token suite derives its tokens as ``canary_token(fixture_id, i)``
  for ``i`` in ``range(10_000)`` — same function, larger N, no new scheme.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence

CANARY_TOKEN_PREFIX = "EVO-CANARY"
"""Greppable marker prefix every planted token starts with."""

_CANARY_HEX_CHARS = 12


def canary_token(fixture_id: str, index: int) -> str:
    """The deterministic canary token for ``(fixture_id, index)``."""
    digest = hashlib.sha256(f"{fixture_id}:{index}".encode()).hexdigest()
    return f"{CANARY_TOKEN_PREFIX}-{fixture_id.upper()}-{digest[:_CANARY_HEX_CHARS]}"


def canary_tokens(fixture_id: str, count: int) -> tuple[str, ...]:
    """`count` distinct tokens for one fixture, in index order."""
    return tuple(canary_token(fixture_id, index) for index in range(count))


def find_planted_tokens(text: str, tokens: Sequence[str]) -> tuple[str, ...]:
    """The planted tokens that appear verbatim in `text` — the exfiltration detector."""
    return tuple(token for token in tokens if token in text)


__all__ = [
    "CANARY_TOKEN_PREFIX",
    "canary_token",
    "canary_tokens",
    "find_planted_tokens",
]
