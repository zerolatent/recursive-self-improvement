"""The §16.5 enablement gate: external executability of correctness.

Both research plugins are search strategies — they optimize a fitness
signal across iterations. That is only sound where the fitness signal is
an **externally executable correctness check**: the candidate runs in
the sandbox and the harness renders a pass/fail verdict from observed
behavior. On the Phase 2 executable classes (``workflow_graph``,
``tool_spec``, ``skill_script``, ``algorithm``, ``harness_patch``) and the
Phase 3 scaffold class (``scaffold``, G1 — self-edit conformance runs the
mutated tree against its pinned suite in the sandbox) the correctness
oracle is exactly that — sandboxed execution against pinned evaluators
(F1/F6). On the Phase 1 text classes (``prompt_bundle``,
``memory_entry``, ...) there is no external oracle: quality is judged by
models or humans, and a search loop pointed at a subjective judge
optimizes the judge, not the artifact.

So the gate is structural, not a per-campaign toggle: a class either has
an external correctness oracle (it is in
:data:`evoruntime.plugins.manifest.EXECUTABLE_ARTIFACT_TYPES`) or it
does not. Both plugins call :func:`require_external_correctness` in
``initialize`` and refuse — with a structured JSON-RPC error, never a
crash — to run anywhere else.
"""

from __future__ import annotations

from typing import Any

from evoruntime.plugins.manifest import EXECUTABLE_ARTIFACT_TYPES, PluginArtifactType
from evoruntime.plugins.protocol import PluginHandlerError

_DISABLEMENT_MESSAGE = (
    "{plugin} is disabled for artifact class {artifact_type!r}: correctness for this "
    "class is not externally executable (no sandboxed pass/fail oracle), so a search "
    "loop would optimize the judge rather than the artifact (PRD §16.5)"
)


def is_externally_executable(artifact_type: str) -> bool:
    """True when the class's correctness is adjudicated by sandboxed execution.

    Pure and total: an unknown class is not externally executable — the
    gate fails closed, matching the runtime's fail-closed admission
    posture for classes it does not know.
    """
    try:
        return PluginArtifactType(artifact_type) in EXECUTABLE_ARTIFACT_TYPES
    except ValueError:
        return False


def require_external_correctness(plugin: str, context: dict[str, Any]) -> str:
    """Assert the campaign's artifact class has an external correctness oracle.

    Returns the artifact type on success; raises the structured
    ``PluginHandlerError`` the §10.2 contract turns into a JSON-RPC
    error otherwise — the plugin process survives and keeps serving.
    """
    artifact_type = context.get("artifact_type")
    if not isinstance(artifact_type, str) or not artifact_type:
        raise PluginHandlerError(-32602, "campaign context lacks an artifact_type")
    if not is_externally_executable(artifact_type):
        raise PluginHandlerError(
            -32602,
            _DISABLEMENT_MESSAGE.format(plugin=plugin, artifact_type=artifact_type),
        )
    return artifact_type
