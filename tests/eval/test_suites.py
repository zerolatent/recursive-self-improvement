"""Transfer-suite tests (F7): construction validation, per-family pinning,
per-family paired results, fail-closed family failure, and the evaluated-
scope ledger."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

import pytest

from evoruntime.datasets.partitions import PartitionKind
from evoruntime.eval import (
    EvalTask,
    FamilyOutcome,
    InMemoryTaskSource,
    ScriptedAgent,
    SuiteDefinitionError,
    SuiteFamily,
    TransferFamilyKind,
    TransferSuite,
    TransferSuiteResult,
    evaluated_transfer_scopes,
    run_transfer_suite,
)
from evoruntime.eval.errors import TaskSourceError
from tests.eval.conftest import (
    frozen_clock,
    make_tasks,
    scripted_outcomes,
    three_arm_experiment,
    uniform_backends,
)

ARM_IDS = ("incumbent", "retry", "one-shot")


def _family(
    name: str,
    kind: TransferFamilyKind,
    *,
    harness_id: str = "pytest-harness-v1",
    backend_id: str = "model-a",
    dataset: str = "ds_repo_repair_dev_v1",
    scope: str = "",
) -> SuiteFamily:
    experiment = three_arm_experiment(
        name=f"exp-{name}", dataset=dataset, bootstrap_iterations=2_000
    )
    return SuiteFamily(
        name=name,
        kind=kind,
        experiment=experiment,
        harness_id=harness_id,
        backend_id=backend_id,
        scope=scope,
    )


DEFAULT_ARM_SUCCESSES: dict[str, int] = {"incumbent": 6, "retry": 9, "one-shot": 3}
DOMAIN_ARM_SUCCESSES: dict[str, int] = {"incumbent": 6, "retry": 3, "one-shot": 3}


def _wiring(
    families: Sequence[SuiteFamily],
    *,
    successes: Mapping[str, int] = DEFAULT_ARM_SUCCESSES,
    domain_successes: Mapping[str, int] = DOMAIN_ARM_SUCCESSES,
    drop: str | None = None,
) -> tuple[dict[str, dict[str, ScriptedAgent]], dict[str, InMemoryTaskSource]]:
    """Arm backends and task sources for each family, keyed by family name.

    `successes` / `domain_successes` map arm id -> how many of the family's
    tasks that arm's script claims success on, so tests can make the
    candidate arm differ from the incumbent by a known amount.
    """
    backends: dict[str, dict[str, ScriptedAgent]] = {}
    sources: dict[str, InMemoryTaskSource] = {}
    for family in families:
        if family.name == drop:
            continue
        family_tasks = (
            make_tasks(prefix="dom")
            if family.kind is TransferFamilyKind.ADJACENT_DOMAIN
            else make_tasks()
        )
        counts = (
            domain_successes if family.kind is TransferFamilyKind.ADJACENT_DOMAIN else successes
        )
        backends[family.name] = uniform_backends(family_tasks, counts)
        sources[family.name] = InMemoryTaskSource(family_tasks)
    return backends, sources  # type: ignore[return-value]


class TestSuiteConstruction:
    def test_valid_three_family_suite(self) -> None:
        suite = TransferSuite(
            name="transfer-2026-08",
            families=[
                _family("xharness", TransferFamilyKind.CROSS_HARNESS, harness_id="alt-harness"),
                _family("xmodel", TransferFamilyKind.CROSS_MODEL, backend_id="model-b"),
                _family("adjacent", TransferFamilyKind.ADJACENT_DOMAIN),
            ],
        )
        assert suite.families_by_name["xmodel"].backend_id == "model-b"
        assert suite.scopes == ("adjacent", "xharness", "xmodel")

    def test_scope_defaults_to_family_name(self) -> None:
        family = _family("xharness", TransferFamilyKind.CROSS_HARNESS)
        assert family.scope == "xharness"

    def test_explicit_scope_overrides_default(self) -> None:
        family = _family("xharness", TransferFamilyKind.CROSS_HARNESS, scope="harness/alt")
        assert family.scope == "harness/alt"

    def test_empty_family_set_refused(self) -> None:
        with pytest.raises(SuiteDefinitionError, match="at least one family"):
            TransferSuite(name="empty", families=[])

    def test_duplicate_family_names_refused(self) -> None:
        with pytest.raises(SuiteDefinitionError, match="duplicate suite family name"):
            TransferSuite(
                name="dup",
                families=[
                    _family("xharness", TransferFamilyKind.CROSS_HARNESS),
                    _family("xharness", TransferFamilyKind.CROSS_MODEL),
                ],
            )

    def test_duplicate_scopes_refused(self) -> None:
        with pytest.raises(SuiteDefinitionError, match="duplicate suite family scope"):
            TransferSuite(
                name="dup-scope",
                families=[
                    _family("a", TransferFamilyKind.CROSS_HARNESS, scope="shared"),
                    _family("b", TransferFamilyKind.CROSS_MODEL, scope="shared"),
                ],
            )

    def test_empty_harness_pin_refused(self) -> None:
        with pytest.raises(SuiteDefinitionError, match="harness_id"):
            _family("xharness", TransferFamilyKind.CROSS_HARNESS, harness_id="")

    def test_empty_backend_pin_refused(self) -> None:
        with pytest.raises(SuiteDefinitionError, match="backend_id"):
            _family("xmodel", TransferFamilyKind.CROSS_MODEL, backend_id="")


class TestRunSuite:
    def test_every_family_runs_under_its_own_pins(self) -> None:
        families = [
            _family("xharness", TransferFamilyKind.CROSS_HARNESS, harness_id="alt-harness"),
            _family("xmodel", TransferFamilyKind.CROSS_MODEL, backend_id="model-b"),
            _family("adjacent", TransferFamilyKind.ADJACENT_DOMAIN),
        ]
        suite = TransferSuite(name="transfer-2026-08", families=families)
        backends, sources = _wiring(families)

        result = run_transfer_suite(
            suite, backends=backends, task_sources=sources, clock_factory=frozen_clock
        )

        assert len(result.evaluated_families) == 3
        assert result.failed_families == ()
        # Each family's result is its own experiment's, not a shared one.
        for family in families:
            outcome = result.outcomes[family.name]
            assert outcome.evaluated
            assert outcome.result is not None
            assert outcome.result.experiment.name == f"exp-{family.name}"

    def test_adjacent_domain_family_runs_its_own_task_set(self) -> None:
        families = [
            _family("xharness", TransferFamilyKind.CROSS_HARNESS),
            _family("adjacent", TransferFamilyKind.ADJACENT_DOMAIN),
        ]
        suite = TransferSuite(name="mixed-tasks", families=families)
        backends, sources = _wiring(families)

        result = run_transfer_suite(
            suite, backends=backends, task_sources=sources, clock_factory=frozen_clock
        )

        main = result.outcomes["xharness"].result
        adjacent = result.outcomes["adjacent"].result
        assert main is not None and adjacent is not None
        assert all(task_id.startswith("tsk_") for task_id in main.task_ids)
        assert all(task_id.startswith("dom_") for task_id in adjacent.task_ids)

    def test_missing_family_wiring_fails_before_any_run(self) -> None:
        families = [
            _family("xharness", TransferFamilyKind.CROSS_HARNESS),
            _family("xmodel", TransferFamilyKind.CROSS_MODEL),
        ]
        suite = TransferSuite(name="wired-wrong", families=families)
        backends, sources = _wiring(families, drop="xmodel")

        with pytest.raises(SuiteDefinitionError, match="xmodel"):
            run_transfer_suite(
                suite, backends=backends, task_sources=sources, clock_factory=frozen_clock
            )

    def test_arm_wiring_mismatch_fails_before_any_run(self) -> None:
        family = _family("xharness", TransferFamilyKind.CROSS_HARNESS)
        suite = TransferSuite(name="arm-wiring", families=[family])
        tasks = make_tasks()
        backends = {"xharness": {"incumbent": ScriptedAgent(scripted_outcomes(tasks, 6))}}
        sources = {"xharness": InMemoryTaskSource(tasks)}

        with pytest.raises(SuiteDefinitionError, match="no backend for arm"):
            run_transfer_suite(
                suite, backends=backends, task_sources=sources, clock_factory=frozen_clock
            )

    def test_family_failure_is_recorded_and_others_still_run(self) -> None:
        families = [
            _family("xharness", TransferFamilyKind.CROSS_HARNESS),
            _family("xmodel", TransferFamilyKind.CROSS_MODEL),
        ]
        suite = TransferSuite(name="one-fails", families=families)
        backends, sources = _wiring(families)
        sources["xmodel"] = _FailingSource()  # type: ignore[assignment]

        result = run_transfer_suite(
            suite, backends=backends, task_sources=sources, clock_factory=frozen_clock
        )

        assert result.outcomes["xharness"].evaluated
        failed = result.outcomes["xmodel"]
        assert not failed.evaluated
        assert failed.error is not None
        assert "TaskSourceError" in failed.error
        assert failed.family.name == "xmodel"

    def test_non_taxonomy_error_propagates(self) -> None:
        family = _family("xharness", TransferFamilyKind.CROSS_HARNESS)
        suite = TransferSuite(name="bug-not-finding", families=[family])
        tasks = make_tasks()

        class ExplodingSource:
            def load(self, dataset: str, partition: PartitionKind) -> tuple[EvalTask, ...]:
                raise TypeError("a bug in the source, not a harness finding")

        with pytest.raises(TypeError, match="a bug"):
            run_transfer_suite(
                suite,
                backends={"xharness": uniform_backends(tasks, dict.fromkeys(ARM_IDS, 6))},
                task_sources={"xharness": ExplodingSource()},  # type: ignore[dict-item]
                clock_factory=frozen_clock,
            )


class TestEvaluatedScopes:
    def test_only_evaluated_families_contribute_scopes(self) -> None:
        families = [
            _family("xharness", TransferFamilyKind.CROSS_HARNESS),
            _family("xmodel", TransferFamilyKind.CROSS_MODEL),
            _family("adjacent", TransferFamilyKind.ADJACENT_DOMAIN),
        ]
        suite = TransferSuite(name="partial", families=families)
        backends, sources = _wiring(families)
        sources["xmodel"] = _FailingSource()  # type: ignore[assignment]

        result = run_transfer_suite(
            suite, backends=backends, task_sources=sources, clock_factory=frozen_clock
        )

        assert evaluated_transfer_scopes(result) == ("adjacent", "xharness")

    def test_all_families_failed_yields_empty_scope_set(self) -> None:
        families = [_family("xharness", TransferFamilyKind.CROSS_HARNESS)]
        suite = TransferSuite(name="all-fail", families=families)
        backends, sources = _wiring(families)
        sources["xharness"] = _FailingSource()  # type: ignore[assignment]

        result = run_transfer_suite(
            suite, backends=backends, task_sources=sources, clock_factory=frozen_clock
        )

        assert evaluated_transfer_scopes(result) == ()

    def test_result_missing_a_family_outcome_is_refused(self) -> None:
        families = [
            _family("xharness", TransferFamilyKind.CROSS_HARNESS),
            _family("xmodel", TransferFamilyKind.CROSS_MODEL),
        ]
        suite = TransferSuite(name="incomplete", families=families)
        backends, sources = _wiring(families)
        full = run_transfer_suite(
            suite, backends=backends, task_sources=sources, clock_factory=frozen_clock
        )
        partial = TransferSuiteResult(suite=suite, outcomes={"xharness": full.outcomes["xharness"]})

        with pytest.raises(SuiteDefinitionError, match="missing outcome"):
            evaluated_transfer_scopes(partial)

    def test_outcome_must_record_result_or_error(self) -> None:
        family = _family("xharness", TransferFamilyKind.CROSS_HARNESS)
        with pytest.raises(SuiteDefinitionError, match="exactly one"):
            FamilyOutcome(family=family)


class TestPairingPreserved:
    def test_each_family_pairs_over_its_own_task_set(self) -> None:
        """The D6 discipline survives the suite: per family, the delta is a
        paired bootstrap over that family's tasks, and the observed delta
        is the mean per-task difference — not a pooled or shrunk sample."""
        families = [
            _family("xharness", TransferFamilyKind.CROSS_HARNESS),
            _family("adjacent", TransferFamilyKind.ADJACENT_DOMAIN),
        ]
        suite = TransferSuite(name="pairing", families=families)
        backends, sources = _wiring(families)

        result = run_transfer_suite(
            suite, backends=backends, task_sources=sources, clock_factory=frozen_clock
        )

        for family in families:
            outcome = result.outcomes[family.name]
            assert outcome.result is not None
            comparison = outcome.result.delta["retry"]
            baseline = outcome.result.primary["incumbent"]
            candidate = outcome.result.primary["retry"]
            # Paired over the family's full task set — one pairing unit per task.
            assert len(outcome.result.task_ids) == len(baseline.task_scores)
            # The observed paired delta is the difference of the per-task means.
            assert comparison.bootstrap.observed_delta == pytest.approx(
                candidate.success_rate - baseline.success_rate
            )

    def test_family_results_are_independent(self) -> None:
        """One family's outcome never leaks into another's statistics."""
        families = [
            _family("xharness", TransferFamilyKind.CROSS_HARNESS),
            _family("adjacent", TransferFamilyKind.ADJACENT_DOMAIN),
        ]
        suite = TransferSuite(name="independence", families=families)
        backends, sources = _wiring(families)

        result = run_transfer_suite(
            suite, backends=backends, task_sources=sources, clock_factory=frozen_clock
        )

        main = result.outcomes["xharness"].result
        adjacent = result.outcomes["adjacent"].result
        assert main is not None and adjacent is not None
        assert main.delta["retry"].bootstrap.observed_delta > 0.0
        assert adjacent.delta["retry"].bootstrap.observed_delta < 0.0


class _FailingSource:
    """A task source that always fails — the stand-in for a broken dataset."""

    def load(self, dataset: str, partition: PartitionKind) -> tuple[EvalTask, ...]:
        raise TaskSourceError(f"dataset {dataset} unavailable")
