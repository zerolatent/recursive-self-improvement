"""Static-analysis gate (Phase 2, F3) — a pure function, like admission.

Executable candidates must be analyzed *before* any execution: the gate
runs on the PROPOSE→DEV_EVALUATE edge of the campaign state machine and a
blocker violation rejects the candidate pre-execution. Like
:mod:`evoruntime.plugins.admission` the analysis is pure — it consumes
candidate file payloads (path + text content) and the mutation mask's
allowed paths, and returns a verdict. No I/O, no clock, no randomness,
which is what makes the fixture corpus decisive and the gate safe to run
inside the transition path itself.

The taxonomy is deliberately small and stable: every code names a class of
behavior that static analysis can actually prove from source text, not a
vibe. Blockers are things the runtime refuses to execute at all (network
egress, subprocess spawning, dynamic execution, writes outside the
mutation mask, source that cannot be analyzed). Warnings are things the
runtime records but allows — today only write calls whose target cannot
be resolved statically, which is the honest limit of static analysis
rather than a hidden blocker.

Verdicts are tamper-evident: the report's canonical JSON bytes hash to a
``verdict_digest``, and the persistence path signs those bytes with the
evaluator's Ed25519 key (:mod:`evoruntime.security.signing`). A verdict
whose bytes no longer hash to their digest, or whose signature no longer
verifies, is refused — not trusted.

Coordination note (F2 runs in parallel): this module analyzes *artifact
payloads* — ``{"path": ..., "content": ...}`` file entries, the shape
``CandidateBundle.files`` already uses — and mask allowed-path tuples. It
never references Phase 2 executable artifact-type enum values, so the two
deliverables merge cleanly; the only shared surface is the file/mask
shape.
"""

from __future__ import annotations

import ast
import hashlib
import json
from enum import StrEnum
from typing import Any, Protocol

from pydantic import Field

from evoruntime.core.schemas import EvoRuntimeBaseModel
from evoruntime.security.protected_modules import ProtectedModulesDocument

ANALYSIS_SCHEMA_ID = "evoruntime.analysis.report/v1"
"""Schema id for the canonical verdict bytes a digest/signature covers."""

_DIGEST_PREFIX = "sha256:"


class Severity(StrEnum):
    """How a violation treats the candidate: refuse execution, or record only."""

    BLOCKER = "blocker"
    WARNING = "warning"


class AnalysisViolationCode(StrEnum):
    """Static-analysis violation taxonomy (Phase 2 F3).

    Stable string codes — downstream records and API payloads reference
    these values, so renaming one is a breaking change, not a refactor.
    """

    NETWORK_IMPORT = "network_import"
    SUBPROCESS_SPAWN = "subprocess_spawn"
    DYNAMIC_EXEC = "dynamic_exec"
    MASK_PATH_WRITE = "mask_path_write"
    UNPARSEABLE_SOURCE = "unparseable_source"
    OPAQUE_PATH_WRITE = "opaque_path_write"
    PROTECTED_MODULE_IMPORT = "protected_module_import"
    PROTECTED_MODULE_WRITE = "protected_module_write"


#: Module roots whose import means the candidate wants network egress.
#: Matched on the root package only — ``urllib.request`` trips via ``urllib``.
_NETWORK_MODULE_ROOTS = frozenset(
    {
        "socket",
        "ssl",
        "urllib",
        "http",
        "httplib",
        "requests",
        "httpx",
        "aiohttp",
        "ftplib",
        "telnetlib",
        "smtplib",
        "xmlrpc",
        "socketserver",
        "websockets",
    }
)

#: Module roots whose import means the candidate spawns OS processes.
_SUBPROCESS_MODULE_ROOTS = frozenset({"subprocess", "pty", "multiprocessing"})

#: Builtin callables that execute dynamically-derived code.
_DYNAMIC_BUILTINS = frozenset({"eval", "exec", "compile", "__import__"})

#: ``os``/``pathlib``/``shutil`` attributes that mutate the filesystem.
_FS_MUTATING_ATTRS = frozenset(
    {
        "system",
        "popen",
        "remove",
        "unlink",
        "rmdir",
        "rename",
        "replace",
        "mkdir",
        "makedirs",
        "write_text",
        "write_bytes",
        "copy",
        "copy2",
        "copytree",
        "move",
        "rmtree",
    }
)

#: ``open`` mode characters that mean the call writes (or may write).
_WRITE_MODE_CHARS = frozenset({"w", "a", "x", "+"})


class AnalysisViolation(EvoRuntimeBaseModel):
    """One finding, tied to the file and line that caused it."""

    code: AnalysisViolationCode
    severity: Severity
    path: str
    detail: str = ""
    line: int = Field(default=0, ge=0)


class StaticAnalysisReport(EvoRuntimeBaseModel):
    """The gate's verdict over one candidate's files.

    ``blocked`` is derived, never stored: any blocker violation refuses
    the candidate. Warnings ride along in the record but never block.
    """

    candidate_digest: str
    artifact_type: str
    violations: tuple[AnalysisViolation, ...] = Field(default=())

    @property
    def blocked(self) -> bool:
        """True when any violation is a blocker — the candidate must not run."""
        return any(v.severity is Severity.BLOCKER for v in self.violations)

    @property
    def outcome(self) -> str:
        """Persistence verdict: ``block`` or ``pass`` (warnings still pass)."""
        return "block" if self.blocked else "pass"

    def canonical_bytes(self) -> bytes:
        """Canonical JSON of the verdict body — the bytes a digest/signature covers.

        Excludes everything derived (the digest itself) so the signed body
        is exactly what the analyzer produced, in a byte-stable form.
        """
        body = {
            "schema_id": ANALYSIS_SCHEMA_ID,
            "candidate_digest": self.candidate_digest,
            "artifact_type": self.artifact_type,
            "violations": [
                {
                    "code": v.code.value,
                    "severity": v.severity.value,
                    "path": v.path,
                    "detail": v.detail,
                    "line": v.line,
                }
                for v in self.violations
            ],
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @property
    def verdict_digest(self) -> str:
        """Content address of the canonical verdict bytes."""
        return _DIGEST_PREFIX + hashlib.sha256(self.canonical_bytes()).hexdigest()


class MaskLike(Protocol):
    """Structural type for a mutation mask — :class:`MutationMask` satisfies it."""

    @property
    def allowed_paths(self) -> tuple[str, ...]: ...


def analyze_files(
    files: tuple[dict[str, Any], ...] | list[dict[str, Any]],
    *,
    masks: tuple[MaskLike, ...] = (),
    artifact_type: str = "",
    candidate_digest: str = "",
    protected_modules: ProtectedModulesDocument | None = None,
) -> StaticAnalysisReport:
    """Statically analyze a candidate's file payloads against the mutation masks.

    Pure: same inputs, same verdict, no side effects. Three planes are checked:

    - **Mask awareness** — every file path must sit inside some mask's
      allowed paths, and every statically-resolvable write target inside
      the source must too. A write outside the mask is a
      ``MASK_PATH_WRITE`` blocker; a write whose target cannot be resolved
      statically is an ``OPAQUE_PATH_WRITE`` warning (the limit of static
      analysis, recorded rather than hidden).
    - **Protected modules** (Phase 3, G2) — a file path or write target
      that maps under a protected module root is a
      ``PROTECTED_MODULE_WRITE`` blocker, and an import of a protected
      module is a ``PROTECTED_MODULE_IMPORT`` blocker — both regardless
      of what the mutation mask allows, because the deny-list bounds the
      mask, not the other way around. ``protected_modules=None`` applies
      the shipped default deny-list; a scaffold-mutation campaign pins
      its own signed document here.
    - **Source scanning** — Python files are parsed and their imports and
      calls checked against the taxonomy. Source that does not parse is
      itself a blocker: code the gate cannot analyze is code the runtime
      does not run.

    Non-Python files get the mask and protected-path checks only — their
    content is not executable Python, so import/call scanning does not
    apply.
    """
    allowed = frozenset(p for mask in masks for p in mask.allowed_paths)
    protected = (
        protected_modules if protected_modules is not None else ProtectedModulesDocument.default()
    )
    violations: list[AnalysisViolation] = []
    for index, entry in enumerate(files):
        path = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(path, str) or not path:
            violations.append(
                AnalysisViolation(
                    code=AnalysisViolationCode.MASK_PATH_WRITE,
                    severity=Severity.BLOCKER,
                    path=f"<file #{index}>",
                    detail="file entry declares no path — cannot be mask-checked",
                )
            )
            continue
        if path not in allowed:
            violations.append(_mask_violation(path, allowed))
        protected_root = protected.covers_path(path)
        if protected_root is not None:
            violations.append(
                _protected_write_violation(
                    path=path,
                    root=protected_root,
                    protected=protected,
                    detail=(
                        f"candidate carries {path!r}, which maps under the protected "
                        f"module {protected_root} — the deny-list bounds the mutation "
                        "mask, not the other way around"
                    ),
                )
            )
        content = entry.get("content")
        if isinstance(content, str) and path.endswith(".py"):
            violations.extend(_scan_source(path, content, allowed, protected))
    return StaticAnalysisReport(
        candidate_digest=candidate_digest,
        artifact_type=artifact_type,
        violations=tuple(violations),
    )


def _protected_write_violation(
    *,
    path: str,
    root: str,
    protected: ProtectedModulesDocument,
    detail: str,
    line: int = 0,
) -> AnalysisViolation:
    return AnalysisViolation(
        code=AnalysisViolationCode.PROTECTED_MODULE_WRITE,
        severity=Severity.BLOCKER,
        path=path,
        detail=f"{detail} ({protected.reason_for(root)})",
        line=line,
    )


def _mask_violation(path: str, allowed: frozenset[str]) -> AnalysisViolation:
    return AnalysisViolation(
        code=AnalysisViolationCode.MASK_PATH_WRITE,
        severity=Severity.BLOCKER,
        path=path,
        detail=(
            f"path is outside the mutation mask (declared: {', '.join(sorted(allowed))})"
            if allowed
            else "no mutation mask declared — every path is outside the mask"
        ),
    )


def _scan_source(
    path: str, source: str, allowed: frozenset[str], protected: ProtectedModulesDocument
) -> list[AnalysisViolation]:
    """Parse one Python file and run the import/call scanners over its AST."""
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [
            AnalysisViolation(
                code=AnalysisViolationCode.UNPARSEABLE_SOURCE,
                severity=Severity.BLOCKER,
                path=path,
                detail=f"source does not parse — refusing unanalyzable code: {exc.msg}",
                line=exc.lineno or 0,
            )
        ]
    violations: list[AnalysisViolation] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            violations.extend(_check_import(path, node, protected))
        elif isinstance(node, ast.Call):
            violations.extend(_check_call(path, node, allowed, protected))
    return violations


def _module_root(name: str | None) -> str:
    return (name or "").split(".")[0]


def _check_import(
    path: str, node: ast.Import | ast.ImportFrom, protected: ProtectedModulesDocument
) -> list[AnalysisViolation]:
    violations: list[AnalysisViolation] = []
    names: list[str] = []
    if isinstance(node, ast.Import):
        names = [alias.name for alias in node.names]
    elif node.module:  # relative imports (level > 0) have no absolute module to classify
        names = [node.module]
    for name in names:
        root = _module_root(name)
        line = node.lineno
        protected_root = protected.covers(name)
        if protected_root is not None:
            violations.append(
                AnalysisViolation(
                    code=AnalysisViolationCode.PROTECTED_MODULE_IMPORT,
                    severity=Severity.BLOCKER,
                    path=path,
                    detail=(
                        f"imports {name!r} — {protected_root} is a protected module "
                        f"({protected.reason_for(protected_root)}); candidates never "
                        "import the runtime's protected planes"
                    ),
                    line=line,
                )
            )
        elif root in _NETWORK_MODULE_ROOTS:
            violations.append(
                AnalysisViolation(
                    code=AnalysisViolationCode.NETWORK_IMPORT,
                    severity=Severity.BLOCKER,
                    path=path,
                    detail=f"imports {name!r} — candidates get no direct network egress",
                    line=line,
                )
            )
        elif root in _SUBPROCESS_MODULE_ROOTS:
            violations.append(
                AnalysisViolation(
                    code=AnalysisViolationCode.SUBPROCESS_SPAWN,
                    severity=Severity.BLOCKER,
                    path=path,
                    detail=f"imports {name!r} — candidates may not spawn processes",
                    line=line,
                )
            )
    return violations


def _check_call(
    path: str, node: ast.Call, allowed: frozenset[str], protected: ProtectedModulesDocument
) -> list[AnalysisViolation]:
    target = node.func
    if isinstance(target, ast.Name):
        return _check_named_call(path, target.id, node, allowed, protected)
    if isinstance(target, ast.Attribute):
        return _check_attribute_call(path, target, node, allowed, protected)
    return []


def _check_named_call(
    path: str,
    name: str,
    node: ast.Call,
    allowed: frozenset[str],
    protected: ProtectedModulesDocument,
) -> list[AnalysisViolation]:
    if name in _DYNAMIC_BUILTINS:
        return [
            AnalysisViolation(
                code=AnalysisViolationCode.DYNAMIC_EXEC,
                severity=Severity.BLOCKER,
                path=path,
                detail=f"calls {name}() — dynamically-derived code is unanalyzable",
                line=node.lineno,
            )
        ]
    if name == "open":
        return _check_open_call(path, node, allowed, protected)
    return []


def _check_attribute_call(
    path: str,
    attr: ast.Attribute,
    node: ast.Call,
    allowed: frozenset[str],
    protected: ProtectedModulesDocument,
) -> list[AnalysisViolation]:
    dotted = _dotted_name(attr)
    root, _, leaf = dotted.rpartition(".")
    if dotted == "importlib.import_module" or dotted == "importlib.reload":
        return [
            AnalysisViolation(
                code=AnalysisViolationCode.DYNAMIC_EXEC,
                severity=Severity.BLOCKER,
                path=path,
                detail=f"calls {dotted}() — dynamically-derived code is unanalyzable",
                line=node.lineno,
            )
        ]
    if root in ("os",) and leaf in ("system", "popen", "spawnl", "spawnle", "spawnv", "spawnve"):
        return [
            AnalysisViolation(
                code=AnalysisViolationCode.SUBPROCESS_SPAWN,
                severity=Severity.BLOCKER,
                path=path,
                detail=f"calls {dotted}() — candidates may not spawn processes",
                line=node.lineno,
            )
        ]
    fs_roots = ("os", "shutil", "pathlib")
    if leaf in _FS_MUTATING_ATTRS and (root.endswith("Path") or root in fs_roots):
        return _check_write_target(path, dotted, node, allowed, protected)
    return []


def _check_open_call(
    path: str, node: ast.Call, allowed: frozenset[str], protected: ProtectedModulesDocument
) -> list[AnalysisViolation]:
    mode = _literal_str(node.args[1]) if len(node.args) > 1 else "r"
    if mode is None or not (set(mode) & _WRITE_MODE_CHARS):
        return []
    return _check_write_target(path, "open", node, allowed, protected)


def _check_write_target(
    path: str,
    call: str,
    node: ast.Call,
    allowed: frozenset[str],
    protected: ProtectedModulesDocument,
) -> list[AnalysisViolation]:
    if not node.args:
        return []
    target = _literal_str(node.args[0])
    if target is None:
        return [
            AnalysisViolation(
                code=AnalysisViolationCode.OPAQUE_PATH_WRITE,
                severity=Severity.WARNING,
                path=path,
                detail=(
                    f"{call}() writes to a value static analysis cannot resolve — "
                    "recorded, not proven safe"
                ),
                line=node.lineno,
            )
        ]
    protected_root = protected.covers_path(target)
    if protected_root is not None:
        return [
            _protected_write_violation(
                path=path,
                root=protected_root,
                protected=protected,
                detail=(
                    f"{call}() writes to {target!r}, which maps under the protected "
                    f"module {protected_root} — the deny-list bounds the mutation "
                    "mask, not the other way around"
                ),
                line=node.lineno,
            )
        ]
    if target not in allowed:
        return [_mask_violation(target, allowed)]
    return []


def _literal_str(node: ast.expr) -> str | None:
    """The string value of an AST node, when it is a literal (or negative number form)."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _dotted_name(attr: ast.Attribute) -> str:
    """Flatten an attribute chain to its dotted form (``os.path.join``)."""
    parts: list[str] = []
    node: ast.expr = attr
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


class StaticAnalysisBlockedError(RuntimeError):
    """Raised when a candidate carries blocker violations — it must not run.

    Carries the full report so the caller (orchestrator, API layer) can
    surface the violation payload without re-running the analysis.
    """

    def __init__(self, report: StaticAnalysisReport) -> None:
        blockers = [v for v in report.violations if v.severity is Severity.BLOCKER]
        summary = ", ".join(f"{v.code.value}@{v.path}" for v in blockers)
        super().__init__(f"candidate blocked pre-execution by static analysis: {summary}")
        self.report = report


class ExecutionGate(Protocol):
    """What the orchestrator consults before the PROPOSE→DEV_EVALUATE edge.

    Implementations raise on refusal; a clean return approves the edge.
    The orchestrator never interprets gate state — it either gets a clean
    return or the exception propagates and the transition is not recorded.
    """

    def approve_execution(self) -> None: ...


class StaticAnalysisGate:
    """Execution gate backed by a static-analysis report provider.

    The provider (not the gate) knows which candidate is pending — the
    orchestrator holds no candidates, so the wiring closure captures the
    pending proposal's report. The gate's only job is the refusal rule:
    any blocker violation raises :class:`StaticAnalysisBlockedError`
    *before* the edge is taken, which is what makes "no execution before
    analysis" a structural property of the machine rather than a
    convention.
    """

    def __init__(self, report_provider: Any) -> None:
        self._report_provider = report_provider

    def approve_execution(self) -> None:
        """Refuse the edge while the pending candidate carries blockers.

        Raises:
            StaticAnalysisBlockedError: the pending candidate's report has
                at least one blocker violation.
        """
        report: StaticAnalysisReport = self._report_provider()
        if report.blocked:
            raise StaticAnalysisBlockedError(report)


__all__ = [
    "ANALYSIS_SCHEMA_ID",
    "AnalysisViolation",
    "AnalysisViolationCode",
    "ExecutionGate",
    "MaskLike",
    "Severity",
    "StaticAnalysisBlockedError",
    "StaticAnalysisGate",
    "StaticAnalysisReport",
    "analyze_files",
]
