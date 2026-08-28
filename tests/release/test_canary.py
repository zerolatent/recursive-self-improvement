"""E5 canary tests: the §17.3 P0 fixed-horizon canary thresholds —
≥200 paired eligible tasks, candidate allocation ≤5%, 24-hour observation
horizon (compressed clock), deterministic severity-1 guardrail events stop
the canary immediately and roll back, candidate state stays namespaced."""

from __future__ import annotations

from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from tests.release.conftest import digest, make_manifest

from evoruntime.release import (
    CANDIDATE_NAMESPACE,
    INCUMBENT_NAMESPACE,
    CanaryConfig,
    CanaryHarness,
    CanaryOutcome,
    CompressedClock,
    GuardrailEvent,
    InProcessFleetSimulator,
    InvalidCanaryConfigError,
    NoActiveReleaseError,
    ReleaseController,
    SignedReleaseManifest,
)
from evoruntime.security.signing import generate_signing_key


def _setup(
    controller: ReleaseController,
    fleet: InProcessFleetSimulator,
    clock: CompressedClock,
    signing_key: Ed25519PrivateKey,
    *,
    config: CanaryConfig | None = None,
) -> tuple[SignedReleaseManifest, SignedReleaseManifest, CanaryHarness]:
    """Activate the incumbent and build the harness; the harness itself
    activates the candidate when ``run`` is called."""
    incumbent = make_manifest(signing_key, artifact_digests=[digest(1), digest(2)])
    controller.activate(incumbent)
    candidate = make_manifest(
        signing_key,
        artifact_digests=[digest(3), digest(4)],
        prior_release_digest=incumbent.manifest_digest,
    )
    harness = CanaryHarness(
        controller=controller, fleet=fleet, clock=clock, config=config or CanaryConfig()
    )
    return incumbent, candidate, harness


class TestFixedHorizon:
    def test_canary_completes_full_horizon_and_promotes(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        _, candidate, harness = _setup(controller, fleet, clock, signing_key)

        result = harness.run(candidate)

        assert result.outcome is CanaryOutcome.COMPLETED
        assert result.paired_tasks == 200
        assert controller.active_digest() == candidate.manifest_digest
        assert result.rolled_back_to is None

    def test_observation_horizon_is_at_least_24_hours(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        _, candidate, harness = _setup(controller, fleet, clock, signing_key)

        result = harness.run(candidate)

        assert result.observation_elapsed >= timedelta(hours=24)

    def test_candidate_allocation_never_exceeds_5_percent(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        # Run several seeds — the candidate slice is drawn per canary;
        # the ≤5% cap is a property of the config, not of the draw. Each
        # seed gets a fresh fleet: sessions are pinned for their lifetime,
        # so a reused simulator would collide session ids across runs.
        for seed in range(5):
            run_fleet = InProcessFleetSimulator(
                worker_count=fleet.worker_count,
                latency_sampler=lambda: 60.0,
                clock=clock,
            )
            _, candidate, harness = _setup(
                controller, run_fleet, clock, signing_key, config=CanaryConfig(seed=seed)
            )

            result = harness.run(candidate)

            assert result.candidate_allocation <= 0.05, (
                f"seed {seed}: allocation {result.candidate_allocation:.3f} exceeds 5%"
            )

    def test_digest_reporting_is_100_percent(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        _, candidate, harness = _setup(controller, fleet, clock, signing_key)

        result = harness.run(candidate)

        assert result.digest_report_coverage == 1.0


class TestSeverityOneStop:
    def test_severity_1_event_stops_immediately_and_rolls_back(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent, candidate, harness = _setup(controller, fleet, clock, signing_key)

        result = harness.run(
            candidate,
            guardrail_events=(GuardrailEvent(severity=1, kind="unsafe-edit", task_index=5),),
        )

        assert result.outcome is CanaryOutcome.ROLLED_BACK
        assert result.paired_tasks == 6  # tasks 0–5, stopped mid-horizon
        assert result.rolled_back_to == incumbent.manifest_digest
        assert controller.active_digest() == incumbent.manifest_digest
        assert result.stopped_reason is not None and "severity-1" in result.stopped_reason

    def test_severity_2_event_does_not_stop_the_canary(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        _, candidate, harness = _setup(controller, fleet, clock, signing_key)

        result = harness.run(
            candidate,
            guardrail_events=(GuardrailEvent(severity=2, kind="degraded-output", task_index=7),),
        )

        assert result.outcome is CanaryOutcome.COMPLETED
        assert result.paired_tasks == 200
        assert result.stopped_reason is None

    def test_fleet_converges_back_to_incumbent_after_severity_1_rollback(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        _, candidate, harness = _setup(controller, fleet, clock, signing_key)

        result = harness.run(
            candidate,
            guardrail_events=(GuardrailEvent(severity=1, kind="unsafe-edit", task_index=5),),
        )
        clock.advance(300.0)  # compressed: fleet convergence window

        assert result.outcome is CanaryOutcome.ROLLED_BACK
        assert fleet.converged_fraction() == 1.0
        assert fleet.p99_convergence_seconds() <= 300.0


class TestNamespacing:
    def test_candidate_writes_stay_out_of_incumbent_memory(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        _, candidate, harness = _setup(controller, fleet, clock, signing_key)

        result = harness.run(candidate)

        assert result.outcome is CanaryOutcome.COMPLETED
        incumbent_keys = fleet.memory_keys(namespace=INCUMBENT_NAMESPACE)
        candidate_keys = fleet.memory_keys(namespace=CANDIDATE_NAMESPACE)
        # Every candidate-arm write landed in the candidate namespace; no
        # incumbent-namespace entry references the candidate manifest.
        assert len(candidate_keys) == result.candidate_sessions
        assert len(incumbent_keys) + len(candidate_keys) == result.paired_tasks
        for key in incumbent_keys:
            entry = fleet.read_state(key, namespace=INCUMBENT_NAMESPACE)
            assert entry is not None
            assert entry["manifest"] != candidate.manifest_digest


class TestConfigValidation:
    """§17.3 P0 thresholds are enforced at construction, not at runtime."""

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("min_paired_tasks", 199),
            ("max_candidate_allocation", 0.06),
            ("observation_horizon", timedelta(hours=23)),
        ],
    )
    def test_below_threshold_config_refused(self, field: str, value: object) -> None:
        kwargs: dict[str, object] = {field: value}
        with pytest.raises(InvalidCanaryConfigError):
            CanaryConfig(**kwargs)  # type: ignore[arg-type]

    def test_defaults_meet_the_p0_thresholds(self) -> None:
        config = CanaryConfig()

        assert config.min_paired_tasks >= 200
        assert config.max_candidate_allocation <= 0.05
        assert config.observation_horizon >= timedelta(hours=24)

    def test_canary_requires_an_active_release(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
    ) -> None:
        candidate = make_manifest(generate_signing_key(), artifact_digests=[digest(3)])
        harness = CanaryHarness(
            controller=controller, fleet=fleet, clock=clock, config=CanaryConfig()
        )

        with pytest.raises(NoActiveReleaseError):
            harness.run(candidate)

    def test_canary_refuses_candidate_equal_to_incumbent(
        self,
        controller: ReleaseController,
        fleet: InProcessFleetSimulator,
        clock: CompressedClock,
        signing_key: Ed25519PrivateKey,
    ) -> None:
        incumbent = make_manifest(signing_key, artifact_digests=[digest(1)])
        controller.activate(incumbent)
        harness = CanaryHarness(
            controller=controller, fleet=fleet, clock=clock, config=CanaryConfig()
        )

        with pytest.raises(InvalidCanaryConfigError, match="currently active"):
            harness.run(incumbent)
