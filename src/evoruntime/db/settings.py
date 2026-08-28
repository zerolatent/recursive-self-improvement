"""Database connection configuration.

Kept separate from `evoruntime.server.settings` because Alembic, the
harness, and the server all need a database URL without pulling in
service-only configuration.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """Environment-driven database configuration."""

    model_config = SettingsConfigDict(
        env_prefix="EVORUNTIME_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5432/evoruntime"


@lru_cache
def get_database_settings() -> DatabaseSettings:
    """Return the process-wide database settings singleton."""
    return DatabaseSettings()
