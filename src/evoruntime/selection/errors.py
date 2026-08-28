"""Typed selection-plane errors (deliverable E4).

Collected in one module, like ``evoruntime.campaign.errors``, so the set of
failures a selection caller must handle is auditable in one place. The
splits that matter:

- ``NominationRuleError`` and ``InvalidPromotionPolicyError`` are
  construction-time refusals — a rule or policy document that cannot be
  trusted should never reach a freeze or a promotion decision.
- ``AlreadyFrozenError`` is the post-freeze immutability boundary: the
  strategy's edit rights end at freeze, and every attempt to exercise them
  afterwards is refused here.
- ``TierRejectedError`` is the §13.3 Phase 1 boundary: tier-3+ authority
  paths exist in the engine but are rejected loudly, never silently
  promoted.
- ``CasConflictError`` and ``PointerAuditError`` are the FR-011 pointer
  mechanics; identity denials themselves ride
  :class:`evoruntime.security.policy.PermissionDeniedError`.
"""

from __future__ import annotations


class SelectionError(Exception):
    """Base class for selection-plane failures."""


class NominationRuleError(SelectionError):
    """The preregistered nomination rule cannot be applied to the
    observations — an arm with no selection-partition data, for example.
    Fail closed: an arm without data gets no nominee, not a guess."""


class AlreadyFrozenError(SelectionError):
    """An edit was attempted after the selector froze the arm.

    Freeze is the moment the strategy loses edit rights (PRD §11.1.6):
    the nominee bytes are immutable from here on, and any proposed
    replacement is refused rather than recorded.
    """

    def __init__(self, arm_id: str, operation: str) -> None:
        self.arm_id = arm_id
        self.operation = operation
        super().__init__(
            f"arm {arm_id!r} is frozen — {operation} refused "
            "(the strategy lost edit rights at freeze)"
        )


class InvalidPromotionPolicyError(SelectionError):
    """A promotion policy document is malformed or out of range.

    The policy document is part of the campaign's preregistration; one
    with impossible thresholds would let a gate be argued after the fact,
    so it is refused at construction.
    """


class TierRejectedError(SelectionError):
    """A resolved release warrants tier-3+ authority, which Phase 1 rejects.

    The tier-3+ paths exist in the policy engine (they are computed, not
    absent) but no Phase 1 artifact class can reach them — the engine
    rejects the promotion loudly instead of silently promoting.
    """

    def __init__(self, tier: int, detail: str) -> None:
        self.tier = tier
        super().__init__(f"authority tier {tier} is rejected for Phase 1: {detail}")


class RecursiveClaimDeniedError(SelectionError):
    """A result was labeled 'recursive improvement' without the §12.6 gate.

    The label is a claim, not a description: until the gate's four
    conditions are satisfied (and Phase 1 enables claiming at all), the
    only honest label is 'artifact optimization'.
    """


class CasConflictError(SelectionError):
    """The compare-and-swap lost: the pointer moved since the caller read it.

    Carries the pointer's actual current digest so the caller can re-read
    and retry against reality instead of guessing.
    """

    def __init__(self, expected: str | None, actual: str | None) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"release-pointer CAS conflict: expected current digest {expected!r}, "
            f"but the pointer is at {actual!r}"
        )


class PointerAuditError(SelectionError):
    """A pointer operation could not be audited.

    FR-011 requires every CAS attempt — allowed or denied — to leave an
    audit record. An operation whose audit write failed is refused, not
    performed unaudited.
    """


__all__ = [
    "AlreadyFrozenError",
    "CasConflictError",
    "InvalidPromotionPolicyError",
    "NominationRuleError",
    "PointerAuditError",
    "RecursiveClaimDeniedError",
    "SelectionError",
    "TierRejectedError",
]
