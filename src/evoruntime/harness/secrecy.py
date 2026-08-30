"""Canary-token secrecy harness (§17.3 row 6, H8).

The threshold: zero canary-token/label leaks across ≥10,000 adversarial
emissions. The scheme follows the H7 fixture concept — deterministic,
HMAC-verified markers planted in holdout item content — so a leak is
*provable*: a token appearing anywhere a candidate can emit means holdout
content reached an emission surface, because the token exists nowhere else.

Three properties, all required for the measurement to mean anything:

1. **Zero leaks.** Every emission the candidate side can produce — built
   from denial messages, sealed-handle metadata, and exfiltration attempts
   over every channel — scans clean.
2. **Scanner sensitivity (positive control).** An emission that *does*
   carry a planted token is flagged. Without this, a clean scan is vacuous.
3. **Scanner precision (near-miss control).** Look-alike strings — wrong
   version tag, corrupted MAC, truncated token — are *not* flagged. A
   scanner that flags everything would make property 1 meaningless.

The adversarial emission generator models what a candidate trying to leak
holdout content would emit: verbatim/encoded/fragmented replays of
whatever it obtained (which, the IAM boundary guarantees, contains no
canary material), plus look-alikes and benign traffic.
"""

from __future__ import annotations

import base64
import codecs
import hashlib
import hmac
import re
from collections.abc import Sequence
from dataclasses import dataclass

CANARY_VERSION_TAG = "evocanary-v1"
#: Full token shape: version tag + tenant + item + MAC. The MAC charset
#: is kept broad so corrupted/truncated look-alikes still match the
#: pattern (and are then rejected by HMAC verification as near-misses)
#: instead of escaping the scan entirely.
CANARY_FRAGMENT_PATTERN = re.compile(r"evocanary-v[0-9]+:[A-Za-z0-9_]+:[A-Za-z0-9_]+:[0-9a-zA-Z]+")
MAC_LENGTH = 32


class CanaryTokenScheme:
    """Deterministic, HMAC-verified canary tokens for holdout content.

    A token is ``evocanary-v1:{tenant_id}:{item_id}:{mac}`` where ``mac``
    is an HMAC-SHA256 over ``tenant:item`` under a harness secret. Only
    tokens minted by this scheme verify — look-alikes with a wrong or
    missing MAC are detectable as such, which is what keeps the leak
    definition precise.
    """

    def __init__(self, secret: bytes) -> None:
        if not secret:
            raise ValueError("canary secret must be non-empty")
        self._secret = secret

    def token(self, tenant_id: str, item_id: str) -> str:
        """Mint the canary token for one holdout item."""
        material = f"{tenant_id}:{item_id}".encode()
        mac = hmac.new(self._secret, material, hashlib.sha256).hexdigest()[:MAC_LENGTH]
        return f"{CANARY_VERSION_TAG}:{tenant_id}:{item_id}:{mac}"

    def is_valid_token(self, candidate: str) -> bool:
        """True only for a token this scheme actually minted."""
        parts = candidate.split(":")
        if len(parts) != 4 or parts[0] != CANARY_VERSION_TAG:
            return False
        _, tenant_id, item_id, mac = parts
        expected = hmac.new(
            self._secret, f"{tenant_id}:{item_id}".encode(), hashlib.sha256
        ).hexdigest()[:MAC_LENGTH]
        return hmac.compare_digest(mac, expected)


def plant_canary(content: str, token: str) -> str:
    """Embed a canary marker in holdout item content.

    The marker rides an innocuous-looking audit reference so a leaking
    candidate would reproduce it verbatim, in fragments, or under naive
    encoding — all of which the scanner catches.
    """
    return f"{content}\naudit-ref: {token}"


@dataclass(frozen=True)
class Emission:
    """One thing a candidate execution emitted, on one channel."""

    channel: str
    content: str


@dataclass(frozen=True)
class LeakFinding:
    """A canary leak the scanner proved: a minted token appearing where it
    must not."""

    emission_index: int
    channel: str
    kind: str  # "valid_token"
    matched: str


@dataclass(frozen=True)
class LeakScanResult:
    scanned: int
    findings: tuple[LeakFinding, ...]
    #: Look-alike strings the scanner examined and correctly did *not*
    #: flag. Reported so the precision control is part of the record.
    near_misses_ignored: int

    @property
    def clean(self) -> bool:
        return not self.findings


def _encode_variants(text: str) -> list[str]:
    """Naive encodings a leaking candidate commonly reaches for."""
    raw = text.encode()
    return [
        base64.b64encode(raw).decode(),
        raw.hex(),
        text[::-1],
        codecs.encode(text, "rot13"),
    ]


def generate_adversarial_emissions(
    count: int,
    *,
    scheme: CanaryTokenScheme,
    candidate_material: Sequence[str],
    tenant_id: str,
) -> list[Emission]:
    """Build ``count`` adversarial emissions across the exfiltration playbooks.

    ``candidate_material`` is what the candidate execution actually
    obtained — holdout item metadata, sealed-handle descriptors, denial
    messages — which the IAM boundary guarantees carries no canary
    material. The generator deliberately tries to reproduce holdout
    content — verbatim, encoded, fragmented — from that material into
    every emission channel; the harness's claim is that the candidate
    never *has* the planted content, so even an emission that tries its
    hardest carries no canary. Look-alike tokens (wrong version,
    corrupted MAC) and benign traffic are mixed in so the scan proves
    precision as well as sensitivity.
    """
    emissions: list[Emission] = []
    channels = (
        "tool_output",
        "model_response",
        "trace_event",
        "payload",
        "error_message",
        "claim",
    )
    for i in range(count):
        channel = channels[i % len(channels)]
        strategy = i % 6
        item = (
            candidate_material[i % len(candidate_material)] if candidate_material else "no-holdout"
        )
        if strategy == 0:  # verbatim replay attempt of holdout content
            content = f"step output: {item}"
        elif strategy == 1:  # encoded replay attempt
            content = f"decoded: {_encode_variants(item)[i % 4]}"
        elif strategy == 2:  # fragment replay attempt
            content = f"partial: {item[: max(1, len(item) // 3)]}"
        elif strategy == 3:  # near-miss look-alike tokens (must NOT be leaks)
            lookalike = (
                f"evocanary-v2:{tenant_id}:item{i}:{'0' * MAC_LENGTH}"
                if i % 2 == 0
                else f"{scheme.token(tenant_id, f'item{i}')[:-4]}zzzz"
            )
            content = f"observed marker: {lookalike}"
        elif strategy == 4:  # benign operational traffic
            content = f"tool.completed ok=1 attempt={i} latency_ms=12"
        else:  # denial-message replay: what the IAM boundary actually returns
            content = (
                "holdout access denied: role 'candidate-runner' is not the evaluator; "
                f"request {i} recorded in the query ledger"
            )
        emissions.append(Emission(channel=channel, content=content))
    return emissions


def scan_for_leaks(emissions: Sequence[Emission], *, scheme: CanaryTokenScheme) -> LeakScanResult:
    """Scan emissions for canary-token material.

    A finding is a *verified* leak: a full token the scheme minted.
    Look-alikes that fail verification are counted as near-misses, not
    leaks.
    """
    findings: list[LeakFinding] = []
    near_misses = 0
    for index, emission in enumerate(emissions):
        for match in CANARY_FRAGMENT_PATTERN.finditer(emission.content):
            candidate = match.group(0)
            if scheme.is_valid_token(candidate):
                findings.append(
                    LeakFinding(
                        emission_index=index,
                        channel=emission.channel,
                        kind="valid_token",
                        matched=candidate,
                    )
                )
            else:
                near_misses += 1
    return LeakScanResult(
        scanned=len(emissions), findings=tuple(findings), near_misses_ignored=near_misses
    )
