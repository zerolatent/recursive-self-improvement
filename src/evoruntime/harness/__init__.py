"""Conformance threshold harnesses (Phase 4 deliverable H8, PRD §17.3).

These are harnesses, not features: they measure the §17.3 thresholds the
unit suites only assert at small scale. Each runner takes a profile
(``evoruntime.harness.profiles``) so the same code path runs a scaled CI
profile and the full-scale soak documented in ``docs/phase4-verification.md``
— the spec's locked decision is that scale thresholds get a scaled CI
profile plus a documented soak, never full-scale CI.
"""

from evoruntime.harness.fault_injection import LossRateResult, run_loss_rate_probe
from evoruntime.harness.load import LoadResult, run_load_probe
from evoruntime.harness.profiles import (
    FAULT_INJECTION_CI_PROFILE,
    FAULT_INJECTION_SOAK_PROFILE,
    LOAD_CI_PROFILE,
    LOAD_SOAK_PROFILE,
    SECRECY_PROFILE,
    FaultInjectionProfile,
    LoadProfile,
    SecrecyProfile,
)
from evoruntime.harness.secrecy import (
    CanaryTokenScheme,
    Emission,
    LeakFinding,
    LeakScanResult,
    generate_adversarial_emissions,
    plant_canary,
    scan_for_leaks,
)

__all__ = [
    "FAULT_INJECTION_CI_PROFILE",
    "FAULT_INJECTION_SOAK_PROFILE",
    "LOAD_CI_PROFILE",
    "LOAD_SOAK_PROFILE",
    "SECRECY_PROFILE",
    "CanaryTokenScheme",
    "Emission",
    "FaultInjectionProfile",
    "LeakFinding",
    "LeakScanResult",
    "LoadProfile",
    "LossRateResult",
    "LoadResult",
    "SecrecyProfile",
    "generate_adversarial_emissions",
    "plant_canary",
    "run_load_probe",
    "run_loss_rate_probe",
    "scan_for_leaks",
]
