"""`Trace.register_payload` — the H2 digest-emission contract, end to end.

The fixture coding agent (H1) composes against this surface, so these tests
pin the contract: upload happens synchronously through the payload
transport, the returned digest is the content digest the server stores the
bytes under, and the digest is recorded in the trace (and the envelope's
`artifact_digests`) only after the upload succeeded.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from evoruntime.core.events import DataClassification
from evoruntime.sdk.adapter import EVENT_ARTIFACT_LOADED
from evoruntime.sdk.records import canonical_detail_body, sha256_digest
from evoruntime.sdk.transport import DiscardingPayloadTransport, PayloadUploadError
from tests.sdk.support import RecordingTransport, make_adapter

FLUSH_TIMEOUT_S = 10.0


def _expected_digest(content: bytes) -> str:
    return f"sha256:{hashlib.sha256(content).hexdigest()}"


class FailingPayloadTransport:
    """Refuses every upload, as an unreachable payload endpoint would."""

    def __init__(self) -> None:
        self.attempts = 0

    def upload(self, content: bytes, *, classification: DataClassification) -> None:
        self.attempts += 1
        raise PayloadUploadError("payload endpoint unreachable (simulated)")

    def close(self) -> None:
        return None


def test_register_payload_uploads_and_records_the_digest(tmp_path: Path) -> None:
    ingest = RecordingTransport()
    payloads = DiscardingPayloadTransport()

    with make_adapter(tmp_path, ingest, payload_transport=payloads) as adapter:
        with adapter.trace(task_id="tsk_patch001") as trace:
            content = b"diff --git a/app.py b/app.py\n..."
            digest = trace.register_payload(content, classification=DataClassification.CONFIDENTIAL)
        assert adapter.flush(FLUSH_TIMEOUT_S)

    # The bytes went to the payload path under the requested classification.
    assert payloads.uploads == [(content, DataClassification.CONFIDENTIAL)]
    # The returned digest is the content digest the server stores under.
    assert digest == _expected_digest(content)
    # And the trace recorded it via artifact_loaded, in the envelope's
    # artifact_digests — the digest chain is constructible end to end. The
    # envelope is closed, so kind/digest live in the out-of-line detail body
    # bound to the envelope by payload_digest.
    artifact_events = [e for e in ingest.envelopes if e.type == EVENT_ARTIFACT_LOADED]
    assert len(artifact_events) == 1
    assert artifact_events[0].artifact_digests == (digest,)
    body = canonical_detail_body({"kind": "payload", "digest": digest})
    assert artifact_events[0].payload_digest == sha256_digest(body)


def test_register_payload_failure_records_nothing(tmp_path: Path) -> None:
    ingest = RecordingTransport()
    payloads = FailingPayloadTransport()

    with make_adapter(tmp_path, ingest, payload_transport=payloads) as adapter:
        with (
            adapter.trace(task_id="tsk_patch002") as trace,
            pytest.raises(PayloadUploadError),
        ):
            trace.register_payload(b"never stored")
        assert adapter.flush(FLUSH_TIMEOUT_S)

    assert payloads.attempts == 1
    # A digest is never emitted for content that never landed: no
    # artifact_loaded event, no dangling reference in the trace.
    assert [e for e in ingest.envelopes if e.type == EVENT_ARTIFACT_LOADED] == []


def test_upload_payload_after_close_raises(tmp_path: Path) -> None:
    adapter = make_adapter(tmp_path, RecordingTransport())
    adapter.close()

    with pytest.raises(RuntimeError, match="adapter is closed"):
        adapter.upload_payload(b"too late", classification=DataClassification.INTERNAL)
