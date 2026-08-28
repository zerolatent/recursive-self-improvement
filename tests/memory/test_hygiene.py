"""Hygiene intake tests (§17.3 memory-hygiene row, FR-016).

Every poison fixture — unadmitted trust domain, unsupported claim,
already-stale data, contradiction with live memory — must land in
QUARANTINED at intake, with a reason naming why. The suite-level
invariant is the 100% figure: no fixture in this module ever reaches
ACTIVE, and the incumbent in a conflict is never demoted by a
newcomer's arrival.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from evoruntime.memory.schemas import (
    Claim,
    MemoryScope,
    MemoryStatus,
    Sensitivity,
    TimeValidity,
)
from tests.memory.conftest import make_entry, propose


def test_clean_entry_lands_as_suggestion(memory_service, memory_tenant) -> None:
    row = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    assert row.status == MemoryStatus.SUGGESTION
    assert row.status_reason is None


def test_poison_untrusted_trust_domain_quarantined(memory_service, memory_tenant) -> None:
    clean = make_entry(tenant=memory_tenant)
    entry = make_entry(
        tenant=memory_tenant,
        provenance=clean.provenance.model_copy(update={"trust_domain": "unverified-web-scrape"}),
    )
    row = propose(memory_service, memory_tenant, entry)
    assert row.status == MemoryStatus.QUARANTINED
    assert row.status_reason is not None
    assert "poison" in row.status_reason


def test_poison_no_supporting_evidence_quarantined(memory_service, memory_tenant) -> None:
    entry = make_entry(tenant=memory_tenant, supporting_evidence=())
    row = propose(memory_service, memory_tenant, entry)
    assert row.status == MemoryStatus.QUARANTINED
    assert row.status_reason is not None
    assert "supporting evidence" in row.status_reason


def test_stale_entry_quarantined_at_intake(memory_service, memory_tenant) -> None:
    entry = make_entry(
        tenant=memory_tenant,
        time_validity=TimeValidity(
            valid_from=datetime.now(UTC) - timedelta(days=30),
            valid_until=datetime.now(UTC) - timedelta(days=1),
        ),
    )
    row = propose(memory_service, memory_tenant, entry)
    assert row.status == MemoryStatus.QUARANTINED
    assert row.status_reason is not None
    assert "stale" in row.status_reason


def test_contradiction_with_live_entry_quarantined(memory_service, memory_tenant) -> None:
    incumbent = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    assert incumbent.status == MemoryStatus.SUGGESTION

    challenger = make_entry(
        tenant=memory_tenant,
        claim=Claim(
            key=incumbent.claim_key,
            statement="the repo prefers setUp methods over factory fixtures",
        ),
    )
    row = propose(memory_service, memory_tenant, challenger)
    assert row.status == MemoryStatus.QUARANTINED
    assert row.status_reason is not None
    assert "conflict" in row.status_reason
    assert incumbent.memory_id in row.status_reason


def test_conflict_never_demotes_the_incumbent(memory_service, memory_tenant) -> None:
    incumbent = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    challenger = make_entry(
        tenant=memory_tenant,
        claim=Claim(
            key=incumbent.claim_key,
            statement="the opposite of whatever the incumbent says",
        ),
    )
    propose(memory_service, memory_tenant, challenger)
    memory_service._session.expire_all()  # re-read from the database
    reloaded = memory_service.get_entry(tenant_id=memory_tenant, memory_id=incumbent.memory_id)
    assert reloaded.status == MemoryStatus.SUGGESTION


def test_same_claim_key_and_statement_is_not_a_conflict(memory_service, memory_tenant) -> None:
    first = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    corroborating = make_entry(tenant=memory_tenant)  # identical claim, fresh evidence
    row = propose(memory_service, memory_tenant, corroborating)
    assert row.status == MemoryStatus.SUGGESTION
    assert first.status == MemoryStatus.SUGGESTION


def test_conflict_is_scoped_to_subject_environment_task_type(memory_service, memory_tenant) -> None:
    incumbent = propose(memory_service, memory_tenant, make_entry(tenant=memory_tenant))
    elsewhere = make_entry(
        tenant=memory_tenant,
        claim=Claim(
            key=incumbent.claim_key,
            statement="contradicts the incumbent, but in a different scope",
        ),
        scope=MemoryScope(
            subject=f"repo_{memory_tenant}",
            environment="production",
            task_type="code-review",
        ),
    )
    row = propose(memory_service, memory_tenant, elsewhere)
    assert row.status == MemoryStatus.SUGGESTION


def test_hygiene_fixture_matrix_all_quarantined_or_suggestion(
    memory_service, memory_tenant
) -> None:
    """The §17.3 acceptance shape: every poison fixture quarantined, the
    clean fixture a suggestion — 100%, no exceptions, no ACTIVE rows."""
    clean = make_entry(tenant=memory_tenant)
    fixtures = {
        "poison-trust-domain": make_entry(
            tenant=memory_tenant,
            provenance=clean.provenance.model_copy(update={"trust_domain": "anonymous-forum"}),
        ),
        "poison-no-evidence": make_entry(tenant=memory_tenant, supporting_evidence=()),
        "stale": make_entry(
            tenant=memory_tenant,
            time_validity=TimeValidity(
                valid_from=datetime.now(UTC) - timedelta(days=10),
                valid_until=datetime.now(UTC) - timedelta(hours=1),
            ),
        ),
        "clean": clean,
    }
    rows = {name: propose(memory_service, memory_tenant, entry) for name, entry in fixtures.items()}
    assert rows["poison-trust-domain"].status == MemoryStatus.QUARANTINED
    assert rows["poison-no-evidence"].status == MemoryStatus.QUARANTINED
    assert rows["stale"].status == MemoryStatus.QUARANTINED
    assert rows["clean"].status == MemoryStatus.SUGGESTION
    for row in rows.values():
        assert row.status != MemoryStatus.ACTIVE


@pytest.mark.parametrize("sensitivity", ["public", "internal", "sensitive", "restricted"])
def test_sensitivity_does_not_bypass_intake_filters(
    memory_service, memory_tenant, sensitivity
) -> None:
    """A poison entry stays poison regardless of its DLP classification."""
    entry = make_entry(
        tenant=memory_tenant,
        supporting_evidence=(),
        sensitivity=Sensitivity(sensitivity),
    )
    row = propose(memory_service, memory_tenant, entry)
    assert row.status == MemoryStatus.QUARANTINED
