"""analysis_reports persistence: append-only trigger, outcome CHECK, tamper evidence.

Runs against real PostgreSQL (the migrations install the append-only
trigger; `Base.metadata.create_all` would prove nothing about it). Each
test scopes itself to a fresh tenant_id — the table is undeletable by
design, so tests cannot truncate it.
"""

from __future__ import annotations

import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from evoruntime.db.models.analysis import AnalysisReport
from evoruntime.plugins.static_analysis import StaticAnalysisReport, analyze_files
from evoruntime.security.signing import DetachedSignature, sign, verify

TENANT = "tnt_f3_analysis"
CANDIDATE_DIGEST = "sha256:" + "0" * 64


def _persisted_report(session: Session, *, tenant: str, outcome: str) -> StaticAnalysisReport:
    """Analyze a candidate, sign the verdict, and append the record."""
    files = ({"path": "prompts/system.md", "content": "RULES = {}\n"},)
    report = analyze_files(files, artifact_type="prompt_bundle", candidate_digest=CANDIDATE_DIGEST)
    detached = sign(Ed25519PrivateKey.generate(), report.canonical_bytes())
    session.add(
        AnalysisReport(
            tenant_id=tenant,
            report_id=str(uuid.uuid4()),
            campaign_id="cmp_f3",
            candidate_digest=CANDIDATE_DIGEST,
            artifact_type="prompt_bundle",
            outcome=outcome,
            violations=[v.model_dump(mode="json") for v in report.violations],
            verdict_digest=report.verdict_digest,
            signature=detached.signature,
            signer_public_key=detached.public_key,
        )
    )
    session.flush()
    return report


def test_append_only_trigger_refuses_update(db_session: Session) -> None:
    tenant = f"{TENANT}_{uuid.uuid4().hex[:8]}"
    _persisted_report(db_session, tenant=tenant, outcome="pass")

    with pytest.raises(IntegrityError, match="immutable"):
        db_session.execute(
            AnalysisReport.__table__.update()
            .where(AnalysisReport.tenant_id == tenant)
            .values(outcome="block")
        )
    db_session.rollback()


def test_append_only_trigger_refuses_delete(db_session: Session) -> None:
    tenant = f"{TENANT}_{uuid.uuid4().hex[:8]}"
    _persisted_report(db_session, tenant=tenant, outcome="pass")

    with pytest.raises(IntegrityError, match="immutable"):
        db_session.execute(
            AnalysisReport.__table__.delete().where(AnalysisReport.tenant_id == tenant)
        )
    db_session.rollback()


def test_outcome_check_constraint(db_session: Session) -> None:
    tenant = f"{TENANT}_{uuid.uuid4().hex[:8]}"
    with pytest.raises(IntegrityError):
        _persisted_report(db_session, tenant=tenant, outcome="maybe")
    db_session.rollback()


def test_stored_verdict_is_tamper_evident(db_session: Session) -> None:
    """The stored digest and signature verify against the canonical verdict bytes."""
    tenant = f"{TENANT}_{uuid.uuid4().hex[:8]}"
    report = _persisted_report(db_session, tenant=tenant, outcome="pass")

    row = db_session.query(AnalysisReport).filter(AnalysisReport.tenant_id == tenant).one()
    assert row.verdict_digest == report.verdict_digest
    # Rebuild the detached signature from the stored columns and verify it
    # against the same canonical bytes the digest covers.
    stored = DetachedSignature(signature=row.signature, public_key=row.signer_public_key)
    assert verify(stored, report.canonical_bytes())
    assert row.outcome == "pass"
