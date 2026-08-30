"""Boundary vocabulary for the refusal ledger (Phase 3, G6).

A leaf module on purpose: both the ORM model
(:mod:`evoruntime.db.models.tenancy`) and the auditing helpers
(:mod:`evoruntime.tenancy.audit`) need these names, and neither may
import the other — the model module is imported by the db package
registry, the audit module by the control plane. Keeping the enum here
keeps the import graph acyclic.
"""

from __future__ import annotations

from enum import StrEnum

__all__ = ["RECURSIVE_CLAIMS_RESEARCH_ONLY", "RefusalBoundary", "SCAFFOLD_REQUIRES_RESEARCH"]


class RefusalBoundary(StrEnum):
    """Which of the four scaffold-mutation boundaries refused."""

    SPEC_CONSTRUCTION = "spec_construction"
    CAMPAIGN_CREATION = "campaign_creation"
    CANDIDATE_REGISTRATION = "candidate_registration"
    RELEASE_ACTIVATION = "release_activation"
    RECURSIVE_LABEL = "recursive_label"
    AUTO_PROMOTION = "auto_promotion"
    RETENTION = "retention"


SCAFFOLD_REQUIRES_RESEARCH = "scaffold_requires_research_tenant"
"""The one refusal reason every scaffold boundary raises."""

RECURSIVE_CLAIMS_RESEARCH_ONLY = "recursive_claims_research_only"
"""The refusal reason for the recursive-label boundary (G6)."""

AUTO_PROMOTION_REQUIRES_REVIEW = "auto_promotion_requires_review"
"""The refusal reason for the auto-promotion boundary (§21 decision 5):
the tenant's approval defaults do not make the tier auto-eligible, so
the promotion must go through two-person review-board approval."""
