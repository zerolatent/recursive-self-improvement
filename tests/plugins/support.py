"""Shared helpers for the E2 plugin test suite."""

from __future__ import annotations

import sys
from pathlib import Path

from evoruntime.plugins.manifest import (
    CompatibilityRange,
    PluginArtifactType,
    PluginEntrypoint,
    PluginKind,
    PluginManifest,
    Reproducibility,
    ResourceLimits,
)
from evoruntime.plugins.protocol import (
    CandidateBundle,
    CanonicalBytes,
    ReadOnlyCampaignContext,
    RemainingBudget,
    clean_plugin_env,
)

TESTS_DIR = Path(__file__).resolve().parent
REFERENCE_PLUGIN = TESTS_DIR / "reference_plugin.py"

RUNTIME_VERSION = "1.0.0"


def reference_command() -> tuple[str, ...]:
    return (sys.executable, str(REFERENCE_PLUGIN))


def reference_env(mode: str) -> dict[str, str]:
    """A clean plugin environment carrying only the behavior-mode flag."""
    return clean_plugin_env({"EVORUNTIME_PLUGIN_MODE": mode})


def make_context() -> ReadOnlyCampaignContext:
    return ReadOnlyCampaignContext(
        campaign_id="camp-1",
        artifact_type="prompt_bundle",
        mutable_paths=("prompt_bundle/",),
        runtime_version=RUNTIME_VERSION,
    )


def make_budget(proposals_remaining: int = 5) -> RemainingBudget:
    return RemainingBudget(
        proposals_remaining=proposals_remaining,
        wall_clock_minutes_remaining=10.0,
        model_tokens_remaining=100_000,
    )


def make_manifest(**overrides: object) -> PluginManifest:
    fields: dict[str, object] = {
        "plugin_id": "ref-strategy",
        "version": "1.0.0",
        "kind": PluginKind.STRATEGY,
        "entrypoint": PluginEntrypoint(transport="stdio-jsonrpc", command=("python", "plugin.py")),
        "artifact_types": (PluginArtifactType.PROMPT_BUNDLE,),
        "compatibility": CompatibilityRange(min_runtime="1.0.0", max_runtime="2.0.0"),
        "limits": ResourceLimits(
            wall_clock_minutes=30.0, cpu=2.0, memory_gib=4.0, model_tokens=100_000, proposals=10
        ),
        "reproducibility": Reproducibility(
            pinned_image="ghcr.io/acme/ref-strategy@sha256:" + "ab" * 32, seed=7
        ),
    }
    fields.update(overrides)
    return PluginManifest.model_validate(fields)


def make_candidate(content: bytes = b"candidate body") -> CandidateBundle:
    return CandidateBundle(artifact_type="prompt_bundle", files=())


def make_canonical(content: bytes = b"base body") -> CanonicalBytes:
    import base64
    import hashlib

    return CanonicalBytes(
        data_b64=base64.b64encode(content).decode(),
        digest=f"sha256:{hashlib.sha256(content).hexdigest()}",
        media_type="text/plain",
    )


def rewrite_archive(files: dict[str, bytes]) -> bytes:
    """Re-tar a parsed OCI layout deterministically (test helper for tampering)."""
    import io
    import tarfile

    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(files):
            info = tarfile.TarInfo(name=path)
            info.size = len(files[path])
            info.mtime = 0
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(files[path]))
    return buffer.getvalue()
