"""The §10.2 plugin process contracts over stdio JSON-RPC.

**Why stdio JSON-RPC and not gRPC** (locked decision, documented per the
spec's "gRPC/stdio process contract" allowance): plugins are untrusted,
language-neutral subprocesses. gRPC would buy streaming and schema codegen
we do not need — every §10.2 call is a single request/response — while
costing a protobuf toolchain, a generated-stub compatibility surface, and
HTTP/2 framing on a pipe. Line-delimited JSON-RPC 2.0 over stdin/stdout is
debuggable with `cat`, needs no codegen in any plugin language, and makes
the failure modes (a hung child, a malformed line) explicit and testable.
If a Phase 2 transport needs streaming, this module's transport seam
(:class:`JsonRpcTransport`) is where it plugs in.

**Trust posture.** The plugin is untrusted code in its own process. The
runtime side (:class:`StrategyPluginClient`, :class:`AdapterPluginClient`)
never deserializes plugin-native checkpoint bytes: ``checkpoint`` returns
opaque bytes that are hashed, handed to a content-addressed store, and
referenced by a schema-bound :class:`CheckpointRef` (FR-010 discipline).
The runtime round-trips :class:`SearchState` without interpreting it.

**Environment.** Plugins are spawned with a scrubbed environment
(:func:`clean_plugin_env`): no evaluator keys, no egress allowlist, no
workload identity — a plugin that needs brokered model traffic goes through
:mod:`evoruntime.security.egress`, never through inherited credentials.
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import selectors
import subprocess
import sys
from collections.abc import Callable, Mapping
from typing import Any, Protocol, runtime_checkable

from pydantic import Field, model_validator

from evoruntime.core.schemas import EvoRuntimeBaseModel

JSONRPC_VERSION = "2.0"

# JSON-RPC error codes. -32700/-32601/-32603 are the standard codes; the
# -32000..-32099 server-error range carries the plugin-contract codes.
_ERROR_PARSE = -32700
_ERROR_METHOD_NOT_FOUND = -32601
_ERROR_INTERNAL = -32603

_MAX_MESSAGE_BYTES = 64 * 1024 * 1024  # a single JSON-RPC message cap

# Environment variables a plugin process may inherit. Everything else —
# signing keys, egress allowlists, workload identity — is scrubbed.
_PASSTHROUGH_ENV_VARS = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR")
_PLUGIN_ENV_PREFIX = "EVORUNTIME_PLUGIN_"


def clean_plugin_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build the environment a plugin process is spawned with.

    Only neutral variables and explicitly namespaced ``EVORUNTIME_PLUGIN_*``
    configuration survive. This is the clean-environment guarantee the FR-004
    conformance suite asserts: evaluator signing keys, the egress allowlist,
    and workload identity never reach plugin code.
    """
    env = {k: v for k, v in os.environ.items() if k in _PASSTHROUGH_ENV_VARS}
    env.update({k: v for k, v in os.environ.items() if k.startswith(_PLUGIN_ENV_PREFIX)})
    if extra:
        env.update(extra)
    return env


# ---------------------------------------------------------------------------
# Wire data contracts. All models are frozen and strict like every
# EvoRuntime schema; bytes travel base64-encoded because the transport is
# line-delimited JSON.
# ---------------------------------------------------------------------------


class ReadOnlyCampaignContext(EvoRuntimeBaseModel):
    """What a strategy may know about the campaign it runs in."""

    campaign_id: str
    artifact_type: str
    mutable_paths: tuple[str, ...] = Field(default=())
    runtime_version: str


class SearchState(EvoRuntimeBaseModel):
    """Opaque plugin-owned search state.

    The runtime stores and returns this verbatim; it never interprets the
    contents. (Checkpoint bytes are held to an even stricter standard —
    see :class:`CheckpointRef`.)
    """

    data: dict[str, Any]


class ArtifactRef(EvoRuntimeBaseModel):
    """A content-addressed reference to an existing artifact."""

    digest: str
    artifact_type: str


class RedactedEvidenceBundle(EvoRuntimeBaseModel):
    """Evidence that has already been through DLP redaction (FR-015).

    The exact redacted-trace schema lands with E8; the strategy contract
    only requires that the bundle is opaque, identified, and redacted
    upstream — a strategy never sees raw traces.
    """

    bundle_id: str
    redacted_items: tuple[dict[str, Any], ...] = Field(default=())


class RemainingBudget(EvoRuntimeBaseModel):
    """What the campaign still allows this plugin to spend."""

    proposals_remaining: int = Field(ge=0)
    wall_clock_minutes_remaining: float = Field(ge=0)
    model_tokens_remaining: int = Field(ge=0)
    # Phase 2 F6: headroom for F1-isolated executable runs. Defaults to a
    # finite sentinel so payloads written before this field existed still
    # parse; the campaign meter always populates it explicitly.
    sandbox_executions_remaining: int = Field(default=0, ge=0)


class ProposalMember(EvoRuntimeBaseModel):
    """One typed member of a (possibly composite) proposal (Phase 2, F4).

    A composite proposal mutates several artifacts in one atomic candidate:
    each member names the artifact class it edits, the adapter-specific
    patch for it, and — for executable classes — the executables it
    declares (the F2 admission surface). Order is significant: the
    composite artifact digest is computed over the ordered member set
    (see :mod:`evoruntime.plugins.composite`), so reordering members is a
    different candidate, not a cosmetic change.
    """

    artifact_type: str
    patch: dict[str, Any]
    declared_executables: tuple[str, ...] = Field(default=())


class Proposal(EvoRuntimeBaseModel):
    """One candidate the strategy proposes.

    A proposal carries either a single mutation (the Phase 1 shape:
    ``artifact_type`` + ``patch``) or an ordered tuple of typed members
    (the Phase 2 composite shape). A composite proposal must not also
    carry a conflicting singular type: if both are present, the singular
    ``artifact_type`` is the primary member's type and must agree with
    ``members[0]``.
    """

    proposal_id: str
    artifact_type: str = ""
    patch: dict[str, Any] = Field(default_factory=dict)
    members: tuple[ProposalMember, ...] = Field(default=())
    rationale: str = ""

    @model_validator(mode="after")
    def _validate_mutation_shape(self) -> Proposal:
        if not self.members:
            if not self.artifact_type:
                raise ValueError(
                    "a proposal must mutate something: declare members (composite) "
                    "or artifact_type + patch (single-artifact)"
                )
            return self
        if self.artifact_type and self.artifact_type != self.members[0].artifact_type:
            raise ValueError(
                f"proposal artifact_type {self.artifact_type!r} does not match the "
                f"primary member {self.members[0].artifact_type!r} — the singular "
                "field, when present, names the primary member"
            )
        return self

    @property
    def is_composite(self) -> bool:
        """True when this proposal carries an explicit ordered member set."""
        return bool(self.members)

    def typed_members(self) -> tuple[ProposalMember, ...]:
        """The proposal's members, normalizing the Phase 1 singular shape.

        A single-artifact proposal is the one-member composite; every
        downstream consumer (digests, masks, registry) sees one shape.
        """
        if self.members:
            return self.members
        return (ProposalMember(artifact_type=self.artifact_type, patch=dict(self.patch)),)


class DevEvaluationResult(EvoRuntimeBaseModel):
    """Development-evaluation feedback — never holdout results (§11.1)."""

    result_id: str
    passed: bool
    metrics: dict[str, float] = Field(default_factory=dict)


class CheckpointRef(EvoRuntimeBaseModel):
    """Schema-bound reference to stored, opaque checkpoint bytes.

    The runtime hashes the plugin's checkpoint bytes, stores them
    content-addressed, and keeps only this ref. It never deserializes the
    bytes — ``schema_id`` says which plugin schema can read them later.
    """

    digest: str
    schema_id: str
    size_bytes: int = Field(ge=0)


class CandidateBundle(EvoRuntimeBaseModel):
    """A candidate handed to an adapter for validation/rendering.

    Phase 2 (F4): a bundle may hold files of several artifact types. The
    top-level ``artifact_type`` is the primary member's class; per-file
    ``artifact_type`` entries (when present) name each file's class, and
    ``artifact_types`` declares the ordered member classes (primary
    first). The mutation-mask wrapper uses the per-file type to pick the
    mask each file is checked against.
    """

    artifact_type: str
    files: tuple[dict[str, Any], ...] = Field(default=())
    artifact_types: tuple[str, ...] = Field(default=())

    @model_validator(mode="after")
    def _validate_types(self) -> CandidateBundle:
        if self.artifact_types and self.artifact_types[0] != self.artifact_type:
            raise ValueError(
                f"bundle artifact_type {self.artifact_type!r} does not match the "
                f"first declared type {self.artifact_types[0]!r} — the primary "
                "type comes first"
            )
        return self

    @property
    def member_types(self) -> tuple[str, ...]:
        """The bundle's member types: declared types when given, else the
        per-file types in first-appearance order, else the primary type."""
        if self.artifact_types:
            return self.artifact_types
        seen: list[str] = []
        for entry in self.files:
            if isinstance(entry, dict):
                file_type = entry.get("artifact_type")
                if isinstance(file_type, str) and file_type and file_type not in seen:
                    seen.append(file_type)
        return tuple(seen) if seen else (self.artifact_type,)


class CanonicalBytes(EvoRuntimeBaseModel):
    """Canonical artifact bytes plus their content digest."""

    data_b64: str
    digest: str
    media_type: str = "application/octet-stream"


class ValidationReport(EvoRuntimeBaseModel):
    """Adapter verdict on a candidate."""

    accepted: bool
    violations: tuple[str, ...] = Field(default=())


class Diff(EvoRuntimeBaseModel):
    """Semantic diff between base content and a candidate."""

    unified: str


class Digest(EvoRuntimeBaseModel):
    """A content digest (``sha256:...``)."""

    value: str


class _BytesPayload(EvoRuntimeBaseModel):
    """Wire form for byte payloads (checkpoint bytes)."""

    data_b64: str
    schema_id: str = ""


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PluginProtocolError(RuntimeError):
    """Base class for plugin process-contract failures."""


class PluginProcessDiedError(PluginProtocolError):
    """The plugin process exited before completing the request."""


class PluginRequestTimeoutError(PluginProtocolError):
    """The plugin did not answer within its wall-clock budget."""


class PluginProtocolViolationError(PluginProtocolError):
    """The plugin spoke malformed JSON-RPC or returned a malformed result."""


class BudgetExceededError(PluginProtocolError):
    """The plugin returned more proposals than its remaining budget allows."""


class PluginMethodError(PluginProtocolError):
    """The plugin answered with a JSON-RPC error."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        self.code = code
        self.plugin_message = message
        self.data = data
        super().__init__(f"plugin error {code}: {message}")


class PluginHandlerError(Exception):
    """Raised by a plugin-side handler to return a JSON-RPC error."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"plugin handler error {code}: {message}")


# ---------------------------------------------------------------------------
# Transport
# ---------------------------------------------------------------------------


@runtime_checkable
class JsonRpcTransport(Protocol):
    """One round-trip JSON-RPC channel. The seam that keeps the protocol
    testable without a real subprocess (and the seam a future streaming
    transport would implement)."""

    def request(self, method: str, params: dict[str, Any], *, timeout_s: float) -> Any: ...

    def close(self) -> None: ...


class StdioJsonRpcTransport:
    """Speaks line-delimited JSON-RPC 2.0 with a plugin subprocess.

    Each request writes one JSON line to the plugin's stdin and reads one
    JSON line from stdout, under a per-request deadline enforced with
    ``selectors`` so a hung plugin cannot hang the runtime.
    """

    def __init__(
        self,
        command: tuple[str, ...],
        *,
        env: Mapping[str, str] | None = None,
        spawn: Callable[..., Any] | None = None,
    ) -> None:
        self._command = tuple(command)
        self._env = dict(env) if env is not None else clean_plugin_env()
        self._spawn = spawn or _popen
        self._proc: Any = None
        self._next_id = 0

    def _ensure_started(self) -> Any:
        if self._proc is None or self._proc.poll() is not None:
            self._proc = self._spawn(
                self._command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._env,
            )
        return self._proc

    def request(self, method: str, params: dict[str, Any], *, timeout_s: float) -> Any:
        proc = self._ensure_started()
        self._next_id += 1
        request_id = self._next_id
        line = json.dumps(
            {"jsonrpc": JSONRPC_VERSION, "id": request_id, "method": method, "params": params},
            separators=(",", ":"),
        )
        assert proc.stdin is not None and proc.stdout is not None
        try:
            proc.stdin.write(f"{line}\n".encode())
            proc.stdin.flush()
        except (BrokenPipeError, ValueError) as exc:
            raise PluginProcessDiedError(
                f"plugin process died writing request {method!r}: {exc}"
            ) from exc
        return self._read_response(proc, request_id, method, timeout_s)

    def _read_response(self, proc: Any, request_id: int, method: str, timeout_s: float) -> Any:
        selector = selectors.DefaultSelector()
        assert proc.stdout is not None
        selector.register(proc.stdout, selectors.EVENT_READ)
        try:
            if not selector.select(timeout_s):
                self.close()
                raise PluginRequestTimeoutError(
                    f"plugin did not answer {method!r} within {timeout_s:.3f}s"
                )
            raw = proc.stdout.readline()
        finally:
            selector.close()
        if not raw:
            self.close()
            raise PluginProcessDiedError(f"plugin process closed stdout during {method!r}")
        if len(raw) > _MAX_MESSAGE_BYTES:
            raise PluginProtocolViolationError(f"plugin response to {method!r} exceeds message cap")
        return _parse_response(raw, request_id, method)

    def close(self) -> None:
        if self._proc is None:
            return
        with contextlib.suppress(OSError):
            self._proc.kill()
        self._proc = None


def _popen(*args: Any, **kwargs: Any) -> Any:
    return subprocess.Popen(*args, **kwargs)


def _parse_response(raw: bytes, request_id: int, method: str) -> Any:

    try:
        message = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PluginProtocolViolationError(
            f"plugin returned unparseable JSON for {method!r}"
        ) from exc
    if not isinstance(message, dict) or message.get("jsonrpc") != JSONRPC_VERSION:
        raise PluginProtocolViolationError(f"plugin response for {method!r} is not JSON-RPC 2.0")
    if message.get("id") != request_id:
        raise PluginProtocolViolationError(f"plugin response id mismatch for {method!r}")
    if "error" in message:
        error = message["error"]
        if not isinstance(error, dict):
            raise PluginProtocolViolationError(f"plugin error for {method!r} is malformed")
        raise PluginMethodError(
            int(error.get("code", _ERROR_INTERNAL)),
            str(error.get("message", "unspecified plugin error")),
            error.get("data"),
        )
    if "result" not in message:
        raise PluginProtocolViolationError(f"plugin response for {method!r} has no result")
    return message["result"]


# ---------------------------------------------------------------------------
# Runtime-side clients implementing the §10.2 contracts
# ---------------------------------------------------------------------------


class CheckpointStore(Protocol):
    """Content-addressed sink for opaque checkpoint bytes."""

    def store(self, data: bytes, *, schema_id: str) -> str: ...


class InMemoryCheckpointStore:
    """Minimal content-addressed store (sha256-keyed) for tests and tools."""

    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}

    def store(self, data: bytes, *, schema_id: str) -> str:
        digest = f"sha256:{hashlib.sha256(data).hexdigest()}"
        self._blobs[digest] = data
        return digest

    def load(self, digest: str) -> bytes:
        return self._blobs[digest]


def _result_dict(result: Any, method: str) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise PluginProtocolViolationError(f"plugin result for {method!r} is not an object")
    return result


class StrategyPluginClient:
    """Runtime-side ImprovementStrategy over the process contract."""

    def __init__(
        self,
        transport: JsonRpcTransport,
        *,
        checkpoint_store: CheckpointStore,
        request_timeout_s: float = 60.0,
    ) -> None:
        self._transport = transport
        self._store = checkpoint_store
        self._timeout_s = request_timeout_s

    def initialize(self, context: ReadOnlyCampaignContext) -> SearchState:
        result = self._transport.request(
            "strategy/initialize",
            {"context": context.model_dump(mode="json")},
            timeout_s=self._timeout_s,
        )
        return _validate_result(SearchState, result, "strategy/initialize")

    def propose(
        self,
        state: SearchState,
        parents: list[ArtifactRef],
        evidence: RedactedEvidenceBundle | None,
        budget: RemainingBudget,
    ) -> list[Proposal]:
        result = self._transport.request(
            "strategy/propose",
            {
                "state": state.model_dump(mode="json"),
                "parents": [p.model_dump(mode="json") for p in parents],
                "evidence": evidence.model_dump(mode="json") if evidence else None,
                "budget": budget.model_dump(mode="json"),
            },
            timeout_s=self._timeout_s,
        )
        raw_proposals = _result_dict(result, "strategy/propose").get("proposals")
        if not isinstance(raw_proposals, list):
            raise PluginProtocolViolationError("strategy/propose result lacks a proposals list")
        if len(raw_proposals) > budget.proposals_remaining:
            raise BudgetExceededError(
                f"plugin returned {len(raw_proposals)} proposals but only "
                f"{budget.proposals_remaining} remain in budget"
            )
        # JSON cannot represent tuples: a composite proposal's member set
        # arrives as a list of member objects. Coerce the list to the
        # tuple shape the frozen Proposal schema declares before
        # validation — lax mode does not reach nested tuple fields.
        proposals: list[Proposal] = []
        for item in raw_proposals:
            if isinstance(item, dict) and isinstance(item.get("members"), list):
                item = {**item, "members": tuple(item["members"])}
            proposals.append(Proposal.model_validate(item, strict=False))
        return proposals

    def observe(self, state: SearchState, result: DevEvaluationResult) -> SearchState:
        response = self._transport.request(
            "strategy/observe",
            {
                "state": state.model_dump(mode="json"),
                "result": result.model_dump(mode="json"),
            },
            timeout_s=self._timeout_s,
        )
        return _validate_result(SearchState, response, "strategy/observe")

    def checkpoint(self, state: SearchState) -> CheckpointRef:
        result = self._transport.request(
            "strategy/checkpoint",
            {"state": state.model_dump(mode="json")},
            timeout_s=self._timeout_s,
        )
        payload = _validate_result(_BytesPayload, result, "strategy/checkpoint")
        raw = base64.b64decode(payload.data_b64, validate=True)
        # The runtime's entire relationship with these bytes is: hash, store,
        # reference. It never deserializes them (FR-010 / spec E2).
        digest = self._store.store(raw, schema_id=payload.schema_id)
        return CheckpointRef(digest=digest, schema_id=payload.schema_id, size_bytes=len(raw))

    def close(self) -> None:
        self._transport.close()


class AdapterPluginClient:
    """Runtime-side ArtifactAdapter over the process contract."""

    def __init__(self, transport: JsonRpcTransport, *, request_timeout_s: float = 60.0) -> None:
        self._transport = transport
        self._timeout_s = request_timeout_s

    def validate(self, candidate: CandidateBundle) -> ValidationReport:
        result = self._transport.request(
            "adapter/validate",
            {"candidate": candidate.model_dump(mode="json")},
            timeout_s=self._timeout_s,
        )
        return _validate_result(ValidationReport, result, "adapter/validate")

    def render(self, base: CanonicalBytes, patch: dict[str, Any]) -> CanonicalBytes:
        result = self._transport.request(
            "adapter/render",
            {"base": base.model_dump(mode="json"), "patch": patch},
            timeout_s=self._timeout_s,
        )
        return _validate_result(CanonicalBytes, result, "adapter/render")

    def semantic_diff(self, base: CanonicalBytes, candidate: CanonicalBytes) -> Diff:
        result = self._transport.request(
            "adapter/semantic_diff",
            {
                "base": base.model_dump(mode="json"),
                "candidate": candidate.model_dump(mode="json"),
            },
            timeout_s=self._timeout_s,
        )
        return _validate_result(Diff, result, "adapter/semantic_diff")

    def fingerprint(self, candidate: CanonicalBytes) -> Digest:
        result = self._transport.request(
            "adapter/fingerprint",
            {"candidate": candidate.model_dump(mode="json")},
            timeout_s=self._timeout_s,
        )
        return _validate_result(Digest, result, "adapter/fingerprint")

    def close(self) -> None:
        self._transport.close()


# ---------------------------------------------------------------------------
# Plugin-side dispatcher
# ---------------------------------------------------------------------------

_METHOD_TABLE: dict[str, str] = {
    "strategy/initialize": "initialize",
    "strategy/propose": "propose",
    "strategy/observe": "observe",
    "strategy/checkpoint": "checkpoint",
    "adapter/validate": "validate",
    "adapter/render": "render",
    "adapter/semantic_diff": "semantic_diff",
    "adapter/fingerprint": "fingerprint",
}


def _validate_result[ModelT: EvoRuntimeBaseModel](
    model: type[ModelT], result: dict[str, Any], method: str
) -> ModelT:
    """Validate a JSON-RPC result into a schema.

    The wire is JSON, which cannot represent tuples — validate lax so lists
    coerce to the tuple fields the frozen EvoRuntime schemas declare.
    """
    return model.model_validate(_result_dict(result, method), strict=False)


def serve(
    handler: Any,
    *,
    stdin: Any = None,
    stdout: Any = None,
    max_requests: int | None = None,
) -> None:
    """Run the plugin side of the contract: read requests, dispatch, reply.

    ``handler`` is any object exposing ``initialize``/``propose``/... (for a
    strategy) or ``validate``/``render``/... (for an adapter) methods that
    accept and return JSON-compatible values. Runs until stdin closes or
    ``max_requests`` is reached.
    """
    input_stream = stdin if stdin is not None else sys.stdin.buffer
    input_stream = stdin if stdin is not None else sys.stdin.buffer
    output_stream = stdout if stdout is not None else sys.stdout.buffer
    for served, raw_line in enumerate(input_stream, start=1):
        response = _dispatch_line(raw_line, handler)
        output_stream.write((json.dumps(response, separators=(",", ":")) + "\n").encode())
        output_stream.flush()
        if max_requests is not None and served >= max_requests:
            break


def _dispatch_line(raw_line: bytes, handler: Any) -> dict[str, Any]:
    try:
        message = json.loads(raw_line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _error_response(None, _ERROR_PARSE, "parse error")
    request_id = message.get("id") if isinstance(message, dict) else None
    method = message.get("method") if isinstance(message, dict) else None
    attr = _METHOD_TABLE.get(method) if isinstance(method, str) else None
    if attr is None:
        return _error_response(request_id, _ERROR_METHOD_NOT_FOUND, f"unknown method {method!r}")
    params = message.get("params") or {}
    try:
        result = getattr(handler, attr)(**_kwargs_for(attr, params))
    except PluginHandlerError as exc:
        return _error_response(request_id, exc.code, exc.message, exc.data)
    except Exception as exc:  # noqa: BLE001 — the boundary reports, never crashes silently
        return _error_response(request_id, _ERROR_INTERNAL, f"{type(exc).__name__}: {exc}")
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "result": result}


def _kwargs_for(attr: str, params: dict[str, Any]) -> dict[str, Any]:
    """Map JSON-RPC params onto handler keyword arguments."""
    if attr == "initialize":
        return {"context": params.get("context", {})}
    if attr == "propose":
        return {
            "state": params.get("state", {}),
            "parents": params.get("parents", []),
            "evidence": params.get("evidence", {}),
            "budget": params.get("budget", {}),
        }
    if attr == "observe":
        return {"state": params.get("state", {}), "result": params.get("result", {})}
    if attr == "checkpoint":
        return {"state": params.get("state", {})}
    if attr == "validate":
        return {"candidate": params.get("candidate", {})}
    if attr == "render":
        return {"base": params.get("base", {}), "patch": params.get("patch", {})}
    if attr == "semantic_diff":
        return {"base": params.get("base", {}), "candidate": params.get("candidate", {})}
    return {"candidate": params.get("candidate", {})}


def _error_response(request_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": JSONRPC_VERSION, "id": request_id, "error": error}
