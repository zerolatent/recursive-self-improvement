"""Trace event envelope — the normative data contract for every event EvoRuntime
ingests (PRD §18.3).

This module defines the envelope exactly as specified: every field the PRD's
example JSON carries, with the tightest validation that fixture and PRD
examples support (id prefixes, digest formats, non-negative costs). Fields
the PRD leaves open-ended (`type`, `data_classification` values) are typed as
narrowly as the spec commits to and no narrower, so legitimate future event
types are not rejected by an over-eager enum.
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import AwareDatetime, Field, StringConstraints

from evoruntime.core.schemas import EvoRuntimeBaseModel

# sha256 hex digest, prefixed with "sha256:" as the PRD's example envelope
# uses for artifact/environment/payload digests.
#
# The patterns clients also need to validate against — a digest, a trace id,
# a task id — are public constants rather than private aliases: the adapter
# SDK checks the same shapes on the agent thread so a caller's typo surfaces
# at the call site, and a second hand-copied regex would be free to drift
# away from the envelope this one defines.
SHA256_DIGEST_PATTERN = r"^sha256:[0-9a-f]{64}$"
TRACE_ID_PATTERN = r"^trc_[A-Za-z0-9]+$"
TASK_ID_PATTERN = r"^tsk_[A-Za-z0-9]+$"

_Sha256Digest = Annotated[str, StringConstraints(pattern=SHA256_DIGEST_PATTERN)]

_TenantId = Annotated[str, StringConstraints(pattern=r"^tnt_[A-Za-z0-9]+$")]
_AgentId = Annotated[str, StringConstraints(pattern=r"^agt_[A-Za-z0-9]+$")]
_ReleaseId = Annotated[str, StringConstraints(pattern=r"^rel_[A-Za-z0-9]+$")]
_CampaignId = Annotated[str, StringConstraints(pattern=r"^cmp_[A-Za-z0-9]+$")]
_TraceId = Annotated[str, StringConstraints(pattern=TRACE_ID_PATTERN)]
_TaskId = Annotated[str, StringConstraints(pattern=TASK_ID_PATTERN)]
_EventId = Annotated[str, StringConstraints(pattern=r"^evt_[A-Za-z0-9]+$")]

# Dotted event type, e.g. "tool.completed", "model.call", "artifact.loaded".
_EventType = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$")]

# Object storage URI for the out-of-line payload body.
_PayloadUri = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9+.-]*://.+$")]


class DataClassification(StrEnum):
    """Sensitivity label carried by every event (PRD §18.3).

    Values follow the common four-tier scheme the spec's own example
    ("internal") is drawn from; this is the narrowest enum that covers the
    spec's example without inventing an unconfirmed fifth tier.
    """

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class ModelInfo(EvoRuntimeBaseModel):
    """Identifies the model backing a `model.*`-family event."""

    provider: str = Field(min_length=1)
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)


class CostInfo(EvoRuntimeBaseModel):
    """Resource cost attributed to a single event."""

    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    usd: float = Field(ge=0)


class EventEnvelope(EvoRuntimeBaseModel):
    """The trace event envelope, normative per PRD §18.3.

    Every field in the PRD's example JSON is represented; nothing is
    optional except `campaign_id` (explicitly nullable in the example) and
    `payload_uri`/`payload_digest`, which do not apply to synchronous events
    with no out-of-line payload body.
    """

    event_id: _EventId
    occurred_at: AwareDatetime
    tenant_id: _TenantId
    agent_id: _AgentId
    release_id: _ReleaseId
    campaign_id: _CampaignId | None = None
    trace_id: _TraceId
    task_id: _TaskId
    type: _EventType
    schema_version: int = Field(ge=1)
    artifact_digests: tuple[_Sha256Digest, ...] = Field(default_factory=tuple)
    model: ModelInfo
    environment_digest: _Sha256Digest
    cost: CostInfo
    data_classification: DataClassification
    payload_uri: _PayloadUri | None = None
    payload_digest: _Sha256Digest | None = None

    def canonical_bytes(self) -> bytes:
        """Deterministic UTF-8 JSON encoding used as hash-chain input.

        Pydantic v2 serializes fields in declaration order (not input-dict
        order), so two envelopes with identical values always canonicalize
        to identical bytes regardless of how they were constructed — this
        is what makes the hash chain (core.hashchain) reproducible and
        tamper detection unambiguous.
        """
        return self.model_dump_json(by_alias=True).encode("utf-8")


def parse_wire_envelope(raw: bytes | str | dict[str, Any]) -> EventEnvelope:
    """Validate a raw event as it arrives over the wire (JSON).

    Always use this — never `EventEnvelope.model_validate()` — for events
    sourced from JSON (HTTP request bodies, JSONL fixtures, queue messages).

    `EventEnvelope` is `strict=True` (PRD §18.3 tamper evidence depends on
    validation being exact, not coercive). But strict mode behaves
    differently depending on *how* pydantic is asked to validate: a JSON
    parser (FastAPI's, `json.loads`, ...) turns an ISO datetime into a
    `str`, a JSON array into a `list`, an enum value into a `str` — before
    pydantic ever sees the payload. Validating those already-parsed Python
    values with `model_validate` runs pydantic's *Python-mode* strict
    checks, which reject exactly those shapes, even though they are exactly
    what a schema-conformant JSON payload looks like once decoded.
    `model_validate_json` runs *JSON-mode* strict checks instead: it still
    rejects genuinely wrong types, but accepts the representations JSON's
    limited type system makes unavoidable (str->datetime, list->tuple,
    str->enum). A `dict` argument here is JSON-native data that has already
    been decoded once (e.g. by FastAPI) — it is re-serialized so it goes
    through JSON-mode validation rather than Python-mode.
    """
    if isinstance(raw, dict):
        raw = json.dumps(raw)
    return EventEnvelope.model_validate_json(raw)


def utcnow() -> datetime:
    """Timezone-aware current time, for fixtures and defaults."""
    from datetime import UTC

    return datetime.now(UTC)
