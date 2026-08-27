"""Environment-driven configuration for the lineage store: the payload
encryption master key and the deletion flow's SLO thresholds.

Kept separate from `evoruntime.db.settings` (connection config) and
`evoruntime.server.settings` (service config) so each settings object only
grows the knobs its own component actually needs.
"""

from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

#: PRD payload-deletion row: access revoked within 5 minutes of request.
DEFAULT_ACCESS_REVOCATION_SLA_SECONDS = 300

#: PRD payload-deletion row: hot derivatives purged within 24 hours.
DEFAULT_DERIVED_PURGE_SLA_SECONDS = 86_400


class LineageSettings(BaseSettings):
    """Configuration for payload encryption and the deletion flow's SLOs.

    `payload_master_key` is a base64-encoded 32-byte key read from the
    environment or a secrets store at runtime — it must never be committed
    (see `.env.example`). The SLA fields are deliberately overridable via
    environment variables so tests can shorten a 5-minute/24-hour SLO to
    something a test can observe deterministically without sleeping for
    real wall-clock minutes or hours.
    """

    model_config = SettingsConfigDict(
        env_prefix="EVORUNTIME_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    payload_master_key: str | None = None
    payload_key_version: str = "v1"
    access_revocation_sla_seconds: int = DEFAULT_ACCESS_REVOCATION_SLA_SECONDS
    derived_purge_sla_seconds: int = DEFAULT_DERIVED_PURGE_SLA_SECONDS


@lru_cache
def get_lineage_settings() -> LineageSettings:
    """Return the process-wide lineage settings singleton."""
    return LineageSettings()
