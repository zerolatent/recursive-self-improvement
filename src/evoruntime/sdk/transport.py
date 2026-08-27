"""Delivery of validated envelopes to the D2 batched ingest API.

Deliberately built on `urllib.request` rather than a third-party HTTP
client. This SDK is imported *into other people's agent processes*; every
dependency it adds is a version constraint imposed on code it does not own,
and a telemetry client is never worth a dependency conflict in the workload
being measured. The request shape here is small enough that the stdlib is
sufficient.

Encoding is done by concatenating each envelope's own canonical bytes rather
than re-serializing a list of models. The envelope's canonical encoding is
what the hash chain is computed over (`EventEnvelope.canonical_bytes`), so
using anything else on the wire would risk the ingest side hashing a
different byte sequence than the SDK signed off on.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol

from evoruntime.core.events import EventEnvelope
from evoruntime.security.identities import WorkloadIdentity

INGEST_PATH = "/v1/events:ingest"
DEFAULT_TIMEOUT_S = 5.0

IDENTITY_HEADER = "x-evoruntime-identity"
ROLE_HEADER = "x-evoruntime-role"
TENANT_HEADER = "x-evoruntime-tenant"


class TransportError(RuntimeError):
    """A batch could not be delivered: network failure, timeout, or 5xx.

    Always retryable in principle — the flush worker keeps the batch and
    backs off. Per-event refusals (bad schema, duplicate) are *not* this;
    they come back inside a successful response as `IngestResult.rejected`,
    because a rejected event must never be retried forever.
    """


@dataclass(frozen=True, slots=True)
class RejectedEventInfo:
    """One event the server refused, with the reason it gave."""

    index: int
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class IngestResult:
    """Per-item outcome of one batch, mirroring D2's `IngestBatchResponse`."""

    accepted_event_ids: tuple[str, ...] = ()
    rejected: tuple[RejectedEventInfo, ...] = field(default=())


class IngestTransport(Protocol):
    """How the flush worker delivers a batch. Swappable for tests and for
    future transports (gRPC, a local collector sidecar)."""

    def send(self, envelopes: Sequence[EventEnvelope]) -> IngestResult:
        """Deliver a batch, or raise :class:`TransportError`."""
        ...

    def close(self) -> None:
        """Release any transport-held resources."""
        ...


def encode_batch(envelopes: Sequence[EventEnvelope]) -> bytes:
    """Encode envelopes as the ingest endpoint's `{"events": [...]}` body."""
    body = b",".join(envelope.canonical_bytes() for envelope in envelopes)
    return b'{"events":[' + body + b"]}"


def decode_result(raw: bytes) -> IngestResult:
    """Parse an ingest response body.

    Raises:
        TransportError: the response is not the documented shape. A
            malformed response is treated as a delivery failure rather than
            an empty success, so a misrouted request (a proxy's HTML error
            page, say) cannot be mistaken for "the server accepted nothing".
    """
    try:
        parsed: Any = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TransportError(f"ingest response was not JSON: {exc}") from exc
    if not isinstance(parsed, dict) or "accepted_event_ids" not in parsed:
        raise TransportError("ingest response missing accepted_event_ids")
    accepted = tuple(str(event_id) for event_id in parsed.get("accepted_event_ids", []))
    rejected = tuple(
        RejectedEventInfo(
            index=int(item.get("index", -1)),
            error_type=str(item.get("error_type", "unknown")),
            message=str(item.get("message", "")),
        )
        for item in parsed.get("rejected", [])
    )
    return IngestResult(accepted_event_ids=accepted, rejected=rejected)


class HttpIngestTransport:
    """POSTs batches to the evaluation plane's ingest endpoint over HTTP."""

    def __init__(
        self,
        endpoint: str,
        *,
        tenant_id: str,
        identity: WorkloadIdentity,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        path: str = INGEST_PATH,
    ) -> None:
        self._url = endpoint.rstrip("/") + path
        self._timeout_s = timeout_s
        # Identity headers are sent even though D2's ingest route does not
        # yet enforce them (only the dataset routes do). They cost nothing,
        # and when ingest gains authentication the SDK will already be
        # presenting the identity the mesh is expected to verify — this is
        # not a claim that ingest is currently authenticated.
        self._headers = {
            "content-type": "application/json",
            IDENTITY_HEADER: identity.subject,
            ROLE_HEADER: identity.role.value,
            TENANT_HEADER: tenant_id,
        }

    def send(self, envelopes: Sequence[EventEnvelope]) -> IngestResult:
        request = urllib.request.Request(
            self._url, data=encode_batch(envelopes), headers=self._headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_s) as response:
                return decode_result(response.read())
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:512]
            raise TransportError(f"ingest returned HTTP {exc.code}: {detail}") from exc
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise TransportError(f"ingest request to {self._url} failed: {exc}") from exc

    def close(self) -> None:
        """No-op: `urlopen` holds no connection across calls."""


class DiscardingIngestTransport:
    """Accepts every batch and delivers it nowhere.

    For offline agent runs and for benchmarks that measure the SDK's own
    cost without a server in the loop. It reports the batch as accepted
    (not rejected) so the journal's ack path behaves exactly as it does in
    production; what it does *not* do is pretend a network exists.
    """

    def __init__(self) -> None:
        self.batches: list[tuple[EventEnvelope, ...]] = []

    def send(self, envelopes: Sequence[EventEnvelope]) -> IngestResult:
        batch = tuple(envelopes)
        self.batches.append(batch)
        return IngestResult(accepted_event_ids=tuple(e.event_id for e in batch))

    def close(self) -> None:
        """No-op."""
