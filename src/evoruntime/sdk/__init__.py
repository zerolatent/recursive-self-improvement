"""The agent adapter SDK — the only surface a coding-agent author touches.

Two things live here, and the boundary between them is the point of the
package. `Adapter`/`Trace` let an agent *say* what it did, cheaply and
without ever blocking on telemetry. `OutcomeAttestation` lets an external
verifier *attest* what actually happened, signed with a key the agent's own
identity cannot read (PRD FR-001; spec D3).

Everything an agent author needs is re-exported here so the import in the
spec's sample (`from evoruntime.sdk import Adapter, OutcomeAttestation`)
works as written; the submodules stay importable for the harness and tests
that need the internals (buffer counters, journal recovery, transports).
"""

from evoruntime.sdk.adapter import (
    DEFAULT_BUFFER_MAX_EVENTS,
    DEFAULT_FLUSH_INTERVAL_S,
    Adapter,
    AdapterStats,
    Trace,
)
from evoruntime.sdk.attestation import ATTESTATION_DOMAIN, OutcomeAttestation, attestation_payload
from evoruntime.sdk.buffer import BufferCounters, EventBuffer
from evoruntime.sdk.journal import EventJournal, JournalRecord, RecoveredJournal, recover
from evoruntime.sdk.records import PendingEvent, TraceContext, build_event
from evoruntime.sdk.transport import (
    HttpIngestTransport,
    IngestResult,
    IngestTransport,
    TransportError,
)

__all__ = [
    "ATTESTATION_DOMAIN",
    "DEFAULT_BUFFER_MAX_EVENTS",
    "DEFAULT_FLUSH_INTERVAL_S",
    "Adapter",
    "AdapterStats",
    "BufferCounters",
    "EventBuffer",
    "EventJournal",
    "HttpIngestTransport",
    "IngestResult",
    "IngestTransport",
    "JournalRecord",
    "OutcomeAttestation",
    "PendingEvent",
    "RecoveredJournal",
    "Trace",
    "TraceContext",
    "TransportError",
    "attestation_payload",
    "build_event",
    "recover",
]
