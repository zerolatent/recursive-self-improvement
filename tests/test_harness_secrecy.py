"""H8 canary-token secrecy suite (§17.3 row 6) — 10k adversarial emissions.

The row-6 claim: no candidate execution ever emits holdout content, so a
leak-scan over ≥10,000 adversarial emissions proves zero canary-token or
label leaks. The suite plants H7's canary-token scheme in holdout content,
generates emissions that *try* to reproduce that material through every
exfiltration playbook (verbatim, encoded, fragmented, look-alike), and
scans. Three properties are proven:

1. **Sensitivity** — a genuinely planted token IS detected (the scanner
   is not vacuously clean).
2. **Zero leaks at scale** — the full 10,000-emission suite is clean:
   the candidate never had the holdout material, so even adversarial
   emissions carry no valid canary.
3. **Precision** — look-alike tokens (wrong version tag, corrupted MAC)
   are counted as near-misses, never flagged as leaks.
"""

from __future__ import annotations

import pytest

from evoruntime.harness.profiles import SECRECY_PROFILE
from evoruntime.harness.secrecy import (
    CanaryTokenScheme,
    Emission,
    generate_adversarial_emissions,
    scan_for_leaks,
)

SECRET = b"h8-canary-secret"
TENANT_ID = "tnt_h8_secrecy"
MAC_LENGTH = 16


def _candidate_obtained_material(items: int) -> list[str]:
    """What a candidate execution actually obtains: holdout item metadata
    and IAM denial messages. The IAM boundary guarantees this carries no
    canary material — the planted content itself never leaves the
    evaluation plane, which is exactly the row-6 claim under test."""
    return [
        f"holdout item item{i}: sealed handle, 3 artifacts, access denied "
        "for role 'candidate-runner'"
        for i in range(items)
    ]


def test_planted_canary_is_detected() -> None:
    """Sensitivity control: the scanner must catch a real leak."""
    scheme = CanaryTokenScheme(SECRET)
    token = scheme.token(TENANT_ID, "item0")
    leak = Emission(channel="model_response", content=f"here is the holdout: {token}")

    result = scan_for_leaks([leak], scheme=scheme)

    assert not result.clean
    assert len(result.findings) == 1
    assert result.findings[0].matched == token
    assert result.findings[0].kind == "valid_token"


def test_lookalike_tokens_are_not_flagged() -> None:
    """Precision control: wrong-version and corrupted-MAC look-alikes are
    near-misses, not leaks."""
    scheme = CanaryTokenScheme(SECRET)
    corrupted = scheme.token(TENANT_ID, "item1")[:-4] + "zzzz"
    wrong_version = f"evocanary-v2:{TENANT_ID}:item2:{'0' * MAC_LENGTH}"
    emissions = [
        Emission(channel="tool_output", content=f"observed: {corrupted}"),
        Emission(channel="trace_event", content=f"observed: {wrong_version}"),
    ]

    result = scan_for_leaks(emissions, scheme=scheme)

    assert result.clean
    assert result.near_misses_ignored == 2


def test_ten_thousand_adversarial_emissions_leak_nothing() -> None:
    """The §17.3 row-6 threshold at full size: ≥10,000 adversarial
    emissions across every exfiltration playbook, zero canary leaks."""
    scheme = CanaryTokenScheme(SECRET)
    candidate_material = _candidate_obtained_material(SECRECY_PROFILE.holdout_items)

    emissions = generate_adversarial_emissions(
        SECRECY_PROFILE.emissions,
        scheme=scheme,
        candidate_material=candidate_material,
        tenant_id=TENANT_ID,
    )

    assert len(emissions) >= SECRECY_PROFILE.emissions
    result = scan_for_leaks(emissions, scheme=scheme)
    assert result.scanned == len(emissions)
    assert result.clean, f"canary leaks found: {result.findings[:5]}"


def test_token_scheme_rejects_forged_tokens() -> None:
    """Only tokens this scheme minted verify — the leak definition stays
    precise against look-alikes."""
    scheme = CanaryTokenScheme(SECRET)
    valid = scheme.token(TENANT_ID, "item9")

    assert scheme.is_valid_token(valid)
    assert not scheme.is_valid_token(valid[:-4] + "zzzz")
    assert not scheme.is_valid_token(f"evocanary-v2:{TENANT_ID}:item9:{'0' * MAC_LENGTH}")
    assert not scheme.is_valid_token("not-a-token")
    with pytest.raises(ValueError):
        CanaryTokenScheme(b"")
