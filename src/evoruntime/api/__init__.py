"""FR-014 control-plane API: the service layer, HTTP client, and `evo` CLI.

This package is the campaign-facing half of deliverable E9:

- :mod:`evoruntime.api.service` — the application service the FastAPI
  routers call. It composes the E1 registry service (artifacts, proposals,
  attestations, status events, release manifests), the E3 lifecycle state
  machine, and the E2 adapter process contract into the campaign-facing
  resources FR-014 names: campaigns, candidates, semantic diffs, evidence,
  Pareto results, approvals, and rollback status.
- :mod:`evoruntime.api.client` — the thin HTTP client the `evo` CLI uses.
- :mod:`evoruntime.api.cli` — the `evo` golden-path CLI. Every command is
  one API call; the CLI holds no business logic (the concept doc's §3
  contract: the API is authoritative, the CLI is an interface to it).
"""

from __future__ import annotations

from evoruntime.api.errors import (
    AdapterNotConfiguredError,
    ApprovalDeniedError,
    CampaignApiError,
    CampaignNotFoundError,
    DiffUnavailableError,
    EvidenceNotFoundError,
    InvalidCampaignTransitionError,
    InvalidSpecError,
    ProposalNotFoundError,
    ReleaseNotFoundError,
    ReleaseStateError,
)
from evoruntime.api.service import CampaignApiService

__all__ = [
    "AdapterNotConfiguredError",
    "ApprovalDeniedError",
    "CampaignApiError",
    "CampaignNotFoundError",
    "CampaignApiService",
    "DiffUnavailableError",
    "EvidenceNotFoundError",
    "InvalidCampaignTransitionError",
    "InvalidSpecError",
    "ProposalNotFoundError",
    "ReleaseNotFoundError",
    "ReleaseStateError",
]
