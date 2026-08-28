"""Pure hygiene checks over memory entries (deliverable E6, FR-016).

Every check here is a pure function over the entry schema (plus an
explicit clock and trust allowlist) so the §17.3 fixture corpus exercises
the same code the service boundary runs. The service layer applies these
decisions; this module never touches the database — a hygiene rule that
needs a session is a hygiene rule you cannot unit-test against a fixture
list.

Three failure families, each with its own disposition:

- **poison** — the entry's provenance is not admitted (trust domain
  outside the allowlist) or the claim carries no supporting evidence at
  all. Quarantined at intake; a quarantined entry is retained for audit
  but never retrievable.
- **stale data** — the entry is past its `valid_until` TTL. Expired by
  the sweep, not deleted: the record of "this was once believed" is the
  audit trail that explains why behavior changed.
- **contradiction** — another live entry makes a different claim under
  the same claim key in an overlapping scope. The newcomer is quarantined
  pending resolution; the incumbent is untouched (a conflict must never
  silently overwrite live memory).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from evoruntime.memory.schemas import MemoryEntry

#: Trust domains whose entries may enter circulation. `candidate-proposed`
#: is admitted because suggestion-first mode is exactly the containment for
#: candidate-proposed memory — the promotion gates, not intake, decide
#: whether it ever reaches a prompt. Domains outside this set (an unverified
#: import, an unknown plugin) are poison until a policy admits them.
DEFAULT_TRUSTED_TRUST_DOMAINS = frozenset({"evaluator-attested", "candidate-proposed"})


@dataclass(frozen=True, slots=True)
class QuarantineDecision:
    """Whether intake should quarantine an entry, and why."""

    quarantine: bool
    reason: str | None

    @classmethod
    def allow(cls) -> QuarantineDecision:
        return cls(quarantine=False, reason=None)

    @classmethod
    def block(cls, reason: str) -> QuarantineDecision:
        return cls(quarantine=True, reason=reason)


def poison_reason(entry: MemoryEntry, *, trusted_domains: frozenset[str]) -> str | None:
    """Why the entry is poison, or None if its provenance is admissible."""
    if entry.provenance.trust_domain not in trusted_domains:
        return (
            "poison: trust domain "
            f"{entry.provenance.trust_domain!r} is not an admitted trust domain"
        )
    if not entry.supporting_evidence:
        return "poison: claim carries no supporting evidence"
    return None


def is_stale(entry: MemoryEntry, *, now: datetime) -> bool:
    """True when the entry is past its declared time validity (TTL)."""
    valid_until = entry.time_validity.valid_until
    return valid_until is not None and valid_until < now


def claims_conflict(first_key: str, first_statement: str, second: MemoryEntry) -> bool:
    """True when `second` is a competing claim under the same claim key."""
    return first_key == second.claim.key and first_statement != second.claim.statement


def intake_decision(
    entry: MemoryEntry,
    *,
    now: datetime,
    trusted_domains: frozenset[str] = DEFAULT_TRUSTED_TRUST_DOMAINS,
) -> QuarantineDecision:
    """The quarantine decision for a newly proposed entry."""
    poison = poison_reason(entry, trusted_domains=trusted_domains)
    if poison is not None:
        return QuarantineDecision.block(poison)
    if is_stale(entry, now=now):
        return QuarantineDecision.block(
            "stale data: entry is already past its declared time validity"
        )
    return QuarantineDecision.allow()
