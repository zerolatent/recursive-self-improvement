"""HTTP translation for dataset errors.

Centralized so every endpoint answers the same way. In particular, both
"no such handle" and "wrong tenant" must render as 404 — the service
already collapses them, and this layer must not reintroduce a distinction
that would let a caller enumerate other tenants' handles.
"""

from __future__ import annotations

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from evoruntime.datasets.errors import (
    HandleNotFoundError,
    HoldoutAccessDeniedError,
    PartitionNotFoundError,
    PartitionStorageIdentityError,
)


async def handle_not_found(_: Request, exc: Exception) -> JSONResponse:
    """Render a missing handle/partition as 404 without echoing internals."""
    return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": "not found"})


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


def install_error_handlers(app: FastAPI) -> None:
    """Register the dataset error handlers on the application."""
    app.add_exception_handler(HandleNotFoundError, handle_not_found)
    app.add_exception_handler(PartitionNotFoundError, handle_not_found)
    app.add_exception_handler(HoldoutAccessDeniedError, handle_access_denied)
    app.add_exception_handler(PartitionStorageIdentityError, handle_bad_partition)
