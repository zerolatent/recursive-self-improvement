"""Runtime configuration for the evaluation-plane service.

Values are read from environment variables (or a local `.env` for
development); nothing here is a place for secrets to live in source.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-driven service configuration."""

    model_config = SettingsConfigDict(
        env_prefix="EVORUNTIME_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    service_name: str = "evoruntime-eval-plane"


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
