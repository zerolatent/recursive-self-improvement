"""E2 — plugin protocol, manifest, and admission (PRD §10).

Public surface:
- :mod:`.protocol` — ImprovementStrategy / ArtifactAdapter process contracts
  over stdio JSON-RPC, plus the plugin-side dispatcher.
- :mod:`.manifest` — the §10.4 manifest schema and effective-grant intersection.
- :mod:`.admission` — the pure-function malformed-output gate (FR-018).
- :mod:`.packaging` — signed OCI packaging with SBOM.
- :mod:`.static_analysis` — the F3 static-analysis execution gate (Phase 2).
- :mod:`.privileged` — the FR-022 privileged admission path.
"""

from evoruntime.plugins.admission import (
    AdmissionDecision,
    AdmissionViolation,
    ArchiveInfo,
    OutputEntry,
    OutputKind,
    ViolationCode,
    admit_output,
)
from evoruntime.plugins.manifest import (
    CompatibilityRange,
    EffectiveGrant,
    NetworkMode,
    PermissionRequest,
    PluginArtifactType,
    PluginEntrypoint,
    PluginKind,
    PluginManifest,
    Reproducibility,
    ResourceLimits,
    check_compatibility,
    effective_grant,
    validate_manifest,
)
from evoruntime.plugins.protocol import (
    AdapterPluginClient,
    BudgetExceededError,
    CheckpointRef,
    InMemoryCheckpointStore,
    Proposal,
    RemainingBudget,
    SearchState,
    StrategyPluginClient,
    clean_plugin_env,
)
from evoruntime.plugins.static_analysis import (
    AnalysisViolation,
    AnalysisViolationCode,
    ExecutionGate,
    Severity,
    StaticAnalysisBlockedError,
    StaticAnalysisGate,
    StaticAnalysisReport,
    analyze_files,
)

__all__ = [
    "AdapterPluginClient",
    "AdmissionDecision",
    "AdmissionViolation",
    "AnalysisViolation",
    "AnalysisViolationCode",
    "ArchiveInfo",
    "BudgetExceededError",
    "CheckpointRef",
    "CompatibilityRange",
    "EffectiveGrant",
    "ExecutionGate",
    "InMemoryCheckpointStore",
    "NetworkMode",
    "OutputEntry",
    "OutputKind",
    "PermissionRequest",
    "PluginArtifactType",
    "PluginEntrypoint",
    "PluginKind",
    "PluginManifest",
    "Proposal",
    "RemainingBudget",
    "Reproducibility",
    "ResourceLimits",
    "SearchState",
    "Severity",
    "StrategyPluginClient",
    "StaticAnalysisBlockedError",
    "StaticAnalysisGate",
    "StaticAnalysisReport",
    "ViolationCode",
    "admit_output",
    "analyze_files",
    "check_compatibility",
    "clean_plugin_env",
    "effective_grant",
    "validate_manifest",
]
