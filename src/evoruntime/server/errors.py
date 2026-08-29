"""HTTP translation for dataset and control-plane errors.

Centralized so every endpoint answers the same way. In particular, both
"no such handle" and "wrong tenant" must render as 404 — the service
already collapses them, and this layer must not reintroduce a distinction
that would let a caller enumerate other tenants' handles.
"""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from evoruntime.api.errors import (
    AdapterNotConfiguredError,
    AdmissionRecordNotFoundError,
    AnalysisReportNotFoundError,
    ApprovalDeniedError,
    ApprovalRequestNotFoundError,
    CampaignApiError,
    CampaignNotFoundError,
    CompensationPlanNotFoundError,
    DiffUnavailableError,
    EvidenceNotFoundError,
    InvalidCampaignTransitionError,
    InvalidSpecError,
    ProposalNotFoundError,
    RegistrationRefusedError,
    ReleaseNotFoundError,
    ReleaseStateError,
    TierPromotionRefusedError,
)
from evoruntime.datasets.errors import (
    HandleNotFoundError,
    HoldoutAccessDeniedError,
    PartitionNotFoundError,
    PartitionStorageIdentityError,
)
from evoruntime.registry.errors import ArtifactNotFoundError


async def handle_not_found(_: Request, exc: Exception) -> JSONResponse:
    """Render a missing handle/partition as 404 without echoing internals."""
    return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": "not found"})


async def handle_campaign_not_found(_: Request, exc: Exception) -> JSONResponse:
    """Render a missing campaign/candidate/evidence/release as 404.

    The reason is echoed because it names only what the caller itself
    asked for (a tenant-scoped lookup that missed) — enough for the CLI
    to say which id was not found."""
    return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": str(exc)})


async def handle_access_denied(_: Request, exc: Exception) -> JSONResponse:
    """Render a holdout denial as 403, carrying the machine-readable reason.

    The reason is safe to return: the caller already knows it was refused,
    and an operator debugging a misconfigured workload needs to see
    `role_not_evaluator` rather than a blank 403.
    """
    if not isinstance(exc, HoldoutAccessDeniedError):  # pragma: no cover - registered per type
        raise exc
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": "holdout access denied", "reason": exc.reason.value},
    )


async def handle_bad_partition(_: Request, exc: Exception) -> JSONResponse:
    """Render an invalid partition operation as 400."""
    return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})


async def handle_invalid_transition(_: Request, exc: Exception) -> JSONResponse:
    """Render an illegal campaign lifecycle edge as 409 — the E3 state
    machine owns the edge table, and a conflict is the honest answer."""
    return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})


async def handle_invalid_spec(_: Request, exc: Exception) -> JSONResponse:
    """Render an invalid spec/manifest as 400 with the validation reason."""
    return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})


async def handle_release_state(_: Request, exc: Exception) -> JSONResponse:
    """Render an illegal release state move (promote non-canary, roll back
    a dead release) as 409."""
    return JSONResponse(status_code=status.HTTP_409_CONFLICT, content={"detail": str(exc)})


async def handle_diff_unavailable(_: Request, exc: Exception) -> JSONResponse:
    """Render an adapter that cannot produce a diff as 422."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, content={"detail": str(exc)}
    )


async def handle_adapter_not_configured(_: Request, exc: Exception) -> JSONResponse:
    """Render a deployment without an adapter as 503 — the endpoint exists,
    the deployment cannot serve it."""
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": str(exc)}
    )


async def handle_approval_denied(_: Request, exc: Exception) -> JSONResponse:
    """Render a two-person review-board refusal as 403 with its reason.

    Self-approval and duplicate-approver refusals are safe to echo: the
    caller made the request and needs to know which governance rule
    stopped it, not just that something did.
    """
    if not isinstance(exc, ApprovalDeniedError):  # pragma: no cover - registered per type
        raise exc
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": str(exc), "reason": exc.reason},
    )


async def handle_tier_promotion_refused(_: Request, exc: Exception) -> JSONResponse:
    """Render a tier gate refusal as 403 — the promotion is forbidden,
    not malformed: the two-person gate has not been satisfied."""
    if not isinstance(exc, TierPromotionRefusedError):  # pragma: no cover
        raise exc
    return JSONResponse(
        status_code=status.HTTP_403_FORBIDDEN,
        content={"detail": str(exc), "tier": exc.tier},
    )


async def handle_registration_refused(_: Request, exc: Exception) -> JSONResponse:
    """Render a pre-registration gate refusal as 422 with the violations.

    The violation payloads are the point of the refusal (F10): a caller
    whose executable candidate is refused must be able to see exactly
    which FR-018 admission rule or F3 static-analysis check failed.
    """
    if not isinstance(exc, RegistrationRefusedError):  # pragma: no cover
        raise exc
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": str(exc), "source": exc.source, "violations": exc.violations},
    )


async def handle_campaign_api_error(_: Request, exc: Exception) -> JSONResponse:
    """Fallback for remaining control-plane errors: 400 with the reason."""
    if not isinstance(exc, CampaignApiError):  # pragma: no cover - registered per type
        raise exc
    return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"detail": str(exc)})


def install_error_handlers(app: FastAPI) -> None:
    """Register the dataset and control-plane error handlers on the app."""
    app.add_exception_handler(HandleNotFoundError, handle_not_found)
    app.add_exception_handler(PartitionNotFoundError, handle_not_found)
    # Evidence and evaluations hang off registered artifacts; a dangling
    # digest is refused at the API boundary as 404, not left to the FK.
    app.add_exception_handler(ArtifactNotFoundError, handle_not_found)
    app.add_exception_handler(HoldoutAccessDeniedError, handle_access_denied)
    app.add_exception_handler(PartitionStorageIdentityError, handle_bad_partition)
    app.add_exception_handler(CampaignNotFoundError, handle_campaign_not_found)
    app.add_exception_handler(ProposalNotFoundError, handle_campaign_not_found)
    app.add_exception_handler(EvidenceNotFoundError, handle_campaign_not_found)
    app.add_exception_handler(ReleaseNotFoundError, handle_campaign_not_found)
    # F10 review-board records: a tenant-scoped lookup that misses is 404.
    app.add_exception_handler(ApprovalRequestNotFoundError, handle_campaign_not_found)
    app.add_exception_handler(AdmissionRecordNotFoundError, handle_campaign_not_found)
    app.add_exception_handler(CompensationPlanNotFoundError, handle_campaign_not_found)
    app.add_exception_handler(AnalysisReportNotFoundError, handle_campaign_not_found)
    app.add_exception_handler(ApprovalDeniedError, handle_approval_denied)
    app.add_exception_handler(TierPromotionRefusedError, handle_tier_promotion_refused)
    app.add_exception_handler(RegistrationRefusedError, handle_registration_refused)
    app.add_exception_handler(InvalidCampaignTransitionError, handle_invalid_transition)
    app.add_exception_handler(InvalidSpecError, handle_invalid_spec)
    app.add_exception_handler(ReleaseStateError, handle_release_state)
    app.add_exception_handler(DiffUnavailableError, handle_diff_unavailable)
    app.add_exception_handler(AdapterNotConfiguredError, handle_adapter_not_configured)
    app.add_exception_handler(CampaignApiError, handle_campaign_api_error)
