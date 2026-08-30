"""FastAPI application factory for the evaluation-plane service."""

from __future__ import annotations

from fastapi import FastAPI

from evoruntime import __version__
from evoruntime.server import ingest
from evoruntime.server.dashboard import install_dashboard
from evoruntime.server.errors import install_error_handlers
from evoruntime.server.routers import (
    agents,
    approvals,
    campaigns,
    candidates,
    claims,
    datasets,
    discovery,
    evaluations,
    evidence,
    payloads,
    releases,
    traces,
)
from evoruntime.server.settings import get_settings


def create_app() -> FastAPI:
    """Build the FastAPI application.

    A factory (rather than a module-level singleton) keeps the app
    constructible with fresh settings per-call, which matters for testing
    and for future multi-worker startup hooks. Routers get their database
    access via `Depends(get_session_factory)` (see `server.dependencies`),
    so a test overrides `app.dependency_overrides[get_session_factory]`
    rather than needing a constructor parameter here.
    """
    settings = get_settings()
    app = FastAPI(title=settings.service_name, version=__version__)

    @app.get("/healthz", tags=["ops"])
    def healthz() -> dict[str, str]:
        """Liveness probe. Always 200 when the process can serve requests.

        This intentionally does not check downstream dependencies (e.g. the
        database) — a liveness probe answers "is this process alive", not
        "is the whole system healthy". A readiness probe can be added
        alongside dataset/ingest endpoints in a later deliverable.
        """
        return {"status": "ok"}

    install_error_handlers(app)
    app.include_router(datasets.router)
    app.include_router(ingest.router)
    app.include_router(campaigns.router)
    app.include_router(claims.router)
    app.include_router(candidates.router)
    app.include_router(agents.router)
    app.include_router(evidence.router)
    app.include_router(traces.router)
    app.include_router(discovery.router)
    app.include_router(payloads.router)
    app.include_router(evaluations.router)
    app.include_router(approvals.router)
    app.include_router(releases.router)
    install_dashboard(app)
    return app


app = create_app()
