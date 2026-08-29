"""Errors raised by the FR-014 control-plane service.

The HTTP layer (``evoruntime.server.errors``) maps these to status codes;
the service raises them with messages that are safe to show the caller —
they name the resource that was refused, never another tenant's data.
"""

from __future__ import annotations

from typing import Any


class CampaignApiError(RuntimeError):
    """Base class for FR-014 control-plane errors."""


class CampaignNotFoundError(CampaignApiError):
    """No campaign with that id in the caller's tenant."""


class ProposalNotFoundError(CampaignApiError):
    """No candidate proposal with that id in the caller's tenant."""


class ReleaseNotFoundError(CampaignApiError):
    """No release manifest with that digest in the caller's tenant."""


class EvidenceNotFoundError(CampaignApiError):
    """No evidence bundle with that id in the caller's tenant."""


class InvalidSpecError(CampaignApiError):
    """The campaign spec failed validation — it was never pinned."""


class InvalidCampaignTransitionError(CampaignApiError):
    """The requested lifecycle transition is not a legal edge from the
    campaign's current phase (the E3 state machine's verdict)."""


class ReleaseStateError(CampaignApiError):
    """The release is not in the state the operation requires (e.g.
    promoting a manifest that never went canary)."""


class AdapterNotConfiguredError(CampaignApiError):
    """The deployment has no artifact adapter configured, so semantic
    diffs cannot be computed. A deployment setting, not a caller error."""


class DiffUnavailableError(CampaignApiError):
    """A semantic diff was requested for a candidate with no parent —
    there is nothing to diff against."""


class ApprovalRequestNotFoundError(CampaignApiError):
    """No approval request with that id in the caller's tenant."""


class AdmissionRecordNotFoundError(CampaignApiError):
    """No signed admission record with that id in the caller's tenant."""


class CompensationPlanNotFoundError(CampaignApiError):
    """No compensation plan with that id in the caller's tenant."""


class AnalysisReportNotFoundError(CampaignApiError):
    """No static-analysis report with that id in the caller's tenant."""


class DiscoveryReportNotFoundError(CampaignApiError):
    """No discovery report with that id in the caller's tenant."""


class DiscoveryReportIntegrityError(CampaignApiError):
    """A stored discovery report's bytes no longer hash to its digest, or its
    signature no longer verifies — the record is detectably tampered, and
    reads refuse it rather than serving untrusted content."""


class ApprovalDeniedError(CampaignApiError):
    """A review-board decision or admission was refused by the
    two-person governance gate (FR-022 semantics).

    ``reason`` is a machine-readable denial code (self_approval,
    duplicate_approver, insufficient_approvals, ...) so callers and the
    CLI can branch on it; the message is the human explanation.
    """

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason


class TierPromotionRefusedError(CampaignApiError):
    """A tier-3/4 promotion was refused by the Phase 2 tier gate — the
    approval evidence is missing or malformed, and the promotion is
    never downgraded to a lower tier to compensate."""

    def __init__(self, tier: int, detail: str) -> None:
        super().__init__(detail)
        self.tier = tier


class RegistrationRefusedError(CampaignApiError):
    """Executable-candidate registration was refused by a pre-registration
    gate (FR-018 output admission or the F3 static-analysis gate).

    Carries the violation payloads so the API boundary can return them —
    a refusal without its violations would force the caller to guess
    which check failed.
    """

    def __init__(self, source: str, violations: list[dict[str, Any]]) -> None:
        summary = ", ".join(f"{v.get('code', '?')}@{v.get('path', '?')}" for v in violations)
        super().__init__(f"registration refused by {source}: {summary}")
        self.source = source
        self.violations = violations
