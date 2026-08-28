"""Errors raised by the FR-014 control-plane service.

The HTTP layer (``evoruntime.server.errors``) maps these to status codes;
the service raises them with messages that are safe to show the caller —
they name the resource that was refused, never another tenant's data.
"""

from __future__ import annotations


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


class ApprovalDeniedError(CampaignApiError):
    """The requested approval decision is not one the control plane
    records (decisions map onto the E1 status-event kinds)."""
