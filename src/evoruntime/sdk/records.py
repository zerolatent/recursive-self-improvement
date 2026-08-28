"""In-flight event records: what the agent thread captures, and how it becomes
a normative :class:`~evoruntime.core.events.EventEnvelope`.

The split here is the SDK's central performance decision. `PendingEvent` is a
slotted dataclass with no validation and no I/O — constructing one is the
*entire* cost an agent thread pays to emit an event (PRD FR-001: the SDK must
never make the agent wait on telemetry). Turning that into a validated
envelope — pydantic strict validation, canonical JSON, sha256 of the payload
body, id generation — happens later on the SDK's background thread, where
latency is invisible to the agent.

The payload body carries the parts of an event the envelope has no field for:
a tool's name, an artifact's kind, a claimed outcome's verdict. The envelope
(PRD §18.3) is deliberately closed — it forbids extra fields so tamper
evidence is unambiguous — so those details live out of line, addressed by
`payload_uri` and bound to the envelope by `payload_digest`. Phase 0 has no
object-store upload endpoint (D2 ingests envelopes only), so the SDK keeps
bodies in its own journal against the digest the envelope commits to; the
upload path that resolves `object://` for real is Phase 1 work.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256

from evoruntime.core.events import CostInfo, DataClassification, EventEnvelope, ModelInfo
from evoruntime.core.ids import new_id

DetailValue = str | int | float | bool | None
"""JSON scalar admissible in an event's out-of-line detail body."""

Details = Mapping[str, DetailValue]

ENVELOPE_SCHEMA_VERSION = 1

ZERO_COST = CostInfo(input_tokens=0, output_tokens=0, usd=0.0)
"""Cost attributed to events that consume no model tokens (tool, artifact,
outcome). Zero is a measurement, not a placeholder: a tool call genuinely
spends no model budget, and the harness sums `cost` across a whole trace to
enforce equal-resource arms (PRD §12.4), so omitting it is not an option and
inventing a nonzero value would corrupt the comparison."""


@dataclass(frozen=True, slots=True)
class TraceContext:
    """The per-adapter constants every event of a session inherits.

    Frozen and built once at adapter construction so the background thread
    never reads adapter attributes that the agent thread could be mutating.
    """

    tenant_id: str
    agent_id: str
    release_id: str
    environment_digest: str
    data_classification: DataClassification
    campaign_id: str | None = None
    schema_version: int = ENVELOPE_SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class PendingEvent:
    """One emitted event, as captured on the agent thread.

    Deliberately holds already-constructed `ModelInfo`/`CostInfo` objects
    rather than raw scalars: the common events (tool, artifact, outcome)
    reuse the adapter's shared instances, so the emit path allocates nothing
    but this dataclass.
    """

    occurred_at: datetime
    trace_id: str
    task_id: str
    type: str
    model: ModelInfo
    cost: CostInfo
    artifact_digests: tuple[str, ...]
    details: Details


@dataclass(frozen=True, slots=True)
class BuiltEvent:
    """A validated envelope plus the payload bytes its digest commits to."""

    envelope: EventEnvelope
    payload_body: bytes


def canonical_detail_body(details: Details) -> bytes:
    """Encode an event's details as deterministic UTF-8 JSON.

    Sorted keys and separator-tight encoding, for the same reason
    `EventEnvelope.canonical_bytes` fixes field order: the bytes are hashed,
    and a hash over a non-deterministic encoding detects re-serialization as
    tampering.
    """
    return json.dumps(dict(details), sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_digest(body: bytes) -> str:
    """Return the `sha256:<hex>` digest form the envelope schema requires."""
    return f"sha256:{sha256(body).hexdigest()}"


def payload_uri(context: TraceContext, trace_id: str, event_id: str) -> str:
    """Address the detail body occupies in the trace object store.

    Content is addressed by *location* here and bound by digest in the
    envelope, matching the PRD's example envelope (`object://traces/...`).
    """
    return f"object://traces/{context.tenant_id}/{trace_id}/{event_id}.json"


def build_event(
    context: TraceContext, pending: PendingEvent, *, event_id: str | None = None
) -> BuiltEvent:
    """Validate a captured event into its normative envelope.

    Raises:
        pydantic.ValidationError: the event violates the envelope schema —
            an unparseable task id, a malformed digest, a negative token
            count. The caller (the flush worker) counts and logs these
            rather than dropping them silently; they are a bug in the
            calling agent, and a silently discarded trace event is exactly
            the kind of invisible gap the evaluation plane cannot tolerate.
    """
    resolved_event_id = event_id or new_id("evt")
    body = canonical_detail_body(pending.details)
    envelope = EventEnvelope(
        event_id=resolved_event_id,
        occurred_at=pending.occurred_at,
        tenant_id=context.tenant_id,
        agent_id=context.agent_id,
        release_id=context.release_id,
        campaign_id=context.campaign_id,
        trace_id=pending.trace_id,
        task_id=pending.task_id,
        type=pending.type,
        schema_version=context.schema_version,
        artifact_digests=pending.artifact_digests,
        model=pending.model,
        environment_digest=context.environment_digest,
        cost=pending.cost,
        data_classification=context.data_classification,
        payload_uri=payload_uri(context, pending.trace_id, resolved_event_id),
        payload_digest=sha256_digest(body),
    )
    return BuiltEvent(envelope=envelope, payload_body=body)
