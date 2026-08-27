"""FastAPI application factory for the evaluation-plane service."""

from __future__ import annotations

from fastapi import FastAPI

from evoruntime import __version__
from evoruntime.server.errors import install_error_handlers
from evoruntime.server.routers import datasets
from evoruntime.server.settings import get_settings


def create_app() -> FastAPI:
    """Build the FastAPI application.

    A factory (rather than a module-level singleton) keeps the app
    constructible with fresh settings per-call, which matters for testing
    and for future multi-worker startup hooks.
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
    return app


app = create_app()
