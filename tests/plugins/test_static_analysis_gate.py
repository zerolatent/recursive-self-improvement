"""F3 gate semantics: blocker/warning severity, tamper-evident verdicts, mask awareness."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evoruntime.plugins.static_analysis import (
    AnalysisViolation,
    AnalysisViolationCode,
    Severity,
    StaticAnalysisBlockedError,
    StaticAnalysisGate,
    StaticAnalysisReport,
    analyze_files,
)
from evoruntime.security.signing import DetachedSignature, sign, verify


class _Mask:
    def __init__(self, allowed_paths: tuple[str, ...]) -> None:
        self._allowed_paths = allowed_paths

    @property
    def allowed_paths(self) -> tuple[str, ...]:
        return self._allowed_paths


CLEAN_FILES = ({"path": "scripts/apply.py", "content": "RULES = {'tool_use': 'file tools'}\n"},)
MASK = (_Mask(("scripts/apply.py",)),)


def _report(violations: tuple[AnalysisViolation, ...]) -> StaticAnalysisReport:
    return StaticAnalysisReport(
        candidate_digest="sha256:" + "0" * 64,
        artifact_type="skill_package",
        violations=violations,
    )


def test_clean_candidate_passes_with_no_violations() -> None:
    report = analyze_files(CLEAN_FILES, masks=MASK, artifact_type="skill_package")
    assert not report.blocked
    assert report.outcome == "pass"
    assert report.violations == ()


def test_blocker_violation_blocks_and_warning_does_not() -> None:
    blocker = _report(
        (
            AnalysisViolation(
                code=AnalysisViolationCode.NETWORK_IMPORT,
                severity=Severity.BLOCKER,
                path="scripts/apply.py",
            ),
        )
    )
    warning = _report(
        (
            AnalysisViolation(
                code=AnalysisViolationCode.OPAQUE_PATH_WRITE,
                severity=Severity.WARNING,
                path="scripts/apply.py",
            ),
        )
    )
    assert blocker.blocked and blocker.outcome == "block"
    assert not warning.blocked and warning.outcome == "pass"


def test_mask_aware_path_check_rejects_out_of_mask_file() -> None:
    files = ({"path": "config/settings.yaml", "content": "mode: overwrite\n"},)
    report = analyze_files(files, masks=MASK, artifact_type="skill_package")
    assert report.blocked
    assert report.violations[0].code is AnalysisViolationCode.MASK_PATH_WRITE
    assert report.violations[0].path == "config/settings.yaml"


def test_mask_aware_path_check_rejects_out_of_mask_write_call() -> None:
    files = (
        {
            "path": "scripts/apply.py",
            "content": 'with open("config/settings.yaml", "w") as handle:\n    handle.write("x")\n',
        },
    )
    report = analyze_files(files, masks=MASK, artifact_type="skill_package")
    assert report.blocked
    assert any(
        v.code is AnalysisViolationCode.MASK_PATH_WRITE and v.path == "config/settings.yaml"
        for v in report.violations
    )


def test_write_inside_mask_is_allowed() -> None:
    files = (
        {
            "path": "scripts/apply.py",
            "content": 'with open("scripts/apply.py", "w") as handle:\n    handle.write("x")\n',
        },
    )
    report = analyze_files(files, masks=MASK, artifact_type="skill_package")
    assert not report.blocked


def test_unparseable_source_is_a_blocker() -> None:
    files = ({"path": "scripts/apply.py", "content": "def broken(:\n"},)
    report = analyze_files(files, masks=MASK, artifact_type="skill_package")
    assert report.blocked
    assert report.violations[0].code is AnalysisViolationCode.UNPARSEABLE_SOURCE


def test_verdict_digest_binds_the_canonical_bytes() -> None:
    report = _report(())
    digest = report.verdict_digest
    assert digest.startswith("sha256:")
    # Any change to the verdict body changes the digest.
    tampered = _report(
        (
            AnalysisViolation(
                code=AnalysisViolationCode.OPAQUE_PATH_WRITE,
                severity=Severity.WARNING,
                path="scripts/apply.py",
            ),
        )
    )
    assert tampered.verdict_digest != digest


def test_verdict_signature_detects_tampering() -> None:
    """Sign the verdict bytes, then prove any edit breaks verification."""
    report = analyze_files(CLEAN_FILES, masks=MASK, artifact_type="skill_package")
    private_key = Ed25519PrivateKey.generate()
    detached = sign(private_key, report.canonical_bytes())
    assert verify(detached, report.canonical_bytes())

    # Tamper: a different verdict body under the same signature fails.
    tampered_bytes = report.canonical_bytes()[:-1] + b" "
    assert not verify(detached, tampered_bytes)

    # Tamper: a signature from a different key fails against the original
    # signer's public key — the key is pinned by the record, not by the
    # attacker-chosen signature payload.
    other = sign(Ed25519PrivateKey.generate(), report.canonical_bytes())
    assert not verify(
        DetachedSignature(signature=other.signature, public_key=detached.public_key),
        report.canonical_bytes(),
    )


def test_gate_approves_clean_candidate() -> None:
    report = analyze_files(CLEAN_FILES, masks=MASK, artifact_type="skill_package")
    gate = StaticAnalysisGate(lambda: report)
    gate.approve_execution()  # clean return = approved


def test_gate_refuses_blocked_candidate_pre_execution() -> None:
    files = ({"path": "scripts/apply.py", "content": "import socket\n"},)
    report = analyze_files(files, masks=MASK, artifact_type="skill_package")
    gate = StaticAnalysisGate(lambda: report)
    with pytest.raises(StaticAnalysisBlockedError) as excinfo:
        gate.approve_execution()
    assert excinfo.value.report is report
    assert any(
        v.code is AnalysisViolationCode.NETWORK_IMPORT for v in excinfo.value.report.violations
    )
