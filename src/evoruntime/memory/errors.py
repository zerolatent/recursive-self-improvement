"""Typed errors for the memory hygiene module (deliverable E6)."""

from __future__ import annotations

from evoruntime.memory.gates import GateReport


class MemoryError(Exception):
    """Base class for memory hygiene failures."""


class MemoryNotFoundError(MemoryError):
    """No memory entry matches the requested identifier for this tenant."""


class PromotionBlockedError(MemoryError):
    """Promotion was refused because at least one hygiene gate failed.

    Carries the full gate report so the caller (and the audit log) can see
    exactly which gate failed and why — a bare "blocked" would invite a
    retry-with-different-numbers instead of a fix.
    """

    def __init__(self, report: GateReport) -> None:
        failed = ", ".join(report.failures)
        super().__init__(f"promotion blocked by hygiene gates: {failed}")
        self.report = report


class SupersessionTargetNotFoundError(MemoryError):
    """An entry declares it supersedes a memory id that does not exist in
    the tenant — the supersession link is dangling and promotion refuses
    rather than silently dropping the link."""
