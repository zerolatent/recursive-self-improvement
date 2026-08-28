"""Shared fixtures for the campaign (E3) test suite.

Every test here runs against a fully valid, pinned §11.2 spec built by
`make_spec_mapping` / `make_pinned_spec` — the negative tests mutate one
field at a time, so a failure always names the field that broke, and the
positive tests exercise the same document a real campaign would pin.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterator
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evoruntime.campaign.machine import CampaignOrchestrator
from evoruntime.campaign.spec import CampaignSpec, PinnedCampaignSpec, pin_and_sign

SPEC_DIGEST = "sha256:" + "a" * 64
"""A well-formed release-manifest digest for fixture specs."""


def make_spec_mapping() -> dict[str, Any]:
    """A minimal valid §11.2 campaign spec as a plain mapping.

    The four-arm frame (three Phase 0 controls + strategy), one mutable
    path, a sealed holdout handle, and budgets every test can afford.
    """
    return {
        "schema_version": 1,
        "name": "prompt-bundle-campaign-1",
        "incumbent": {
            "release_manifest_digest": SPEC_DIGEST,
            "artifact_type": "prompt_bundle",
        },
        "mutable_artifact": {
            "artifact_type": "prompt_bundle",
            "paths": ["prompts/system.md"],
        },
        "strategy_plugin": {
            "plugin_id": "evo-prompt-strategist",
            "pinned_image": "ghcr.io/evoruntime/strategist@sha256:" + "b" * 64,
        },
        "arms": [
            {"id": "incumbent", "kind": "incumbent"},
            {"id": "retry", "kind": "retry-self-consistency", "max_attempts": 3},
            {"id": "one-shot", "kind": "one-shot-control"},
            {"id": "strategy", "kind": "strategy"},
        ],
        "datasets": {
            "dev_partition": "dev-primary",
            "selection_partition": "selection-primary",
            "holdout_handle": "holdout://ledger/alpha-1",
        },
        "evaluators": [
            {
                "name": "coding-verifier",
                "pinned_image": "ghcr.io/evoruntime/verifier@sha256:" + "c" * 64,
            }
        ],
        "budgets": {
            "task_budget_profile": "task-budget-v1",
            "max_proposals": 10,
            "max_model_tokens": 100_000,
            "max_wall_clock_minutes": 30.0,
        },
        "promotion_policy": {
            "policy_id": "tier-2-standard",
            "policy_digest": "sha256:" + "d" * 64,
        },
        "statistics": {
            "alpha": 0.05,
            "multiplicity": "bonferroni",
            "bootstrap_iterations": 200,
            "bootstrap_seed": 7,
        },
        "stopping_rules": {"max_rounds": 5, "max_no_improvement_rounds": 2},
        "metadata": {"owner": "evaluator"},
    }


def make_spec() -> CampaignSpec:
    """A validated CampaignSpec built from the fixture mapping."""
    return CampaignSpec.from_mapping(make_spec_mapping())


def make_pinned_spec() -> PinnedCampaignSpec:
    """The fixture spec, pinned and signed with a fresh evaluator key."""
    return pin_and_sign(make_spec(), Ed25519PrivateKey.generate())


class InMemoryCheckpointStore:
    """Content-addressed checkpoint store: digest-keyed, digest-verified.

    Mirrors what a real store (the payload store) guarantees: the address
    is derived from the bytes, so any tampering is detectable on load.
    """

    def __init__(self) -> None:
        self._blobs: dict[str, bytes] = {}

    def store(self, data: bytes, *, schema_id: str) -> str:
        """Store bytes under their sha256 digest (schema_id is metadata)."""
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        self._blobs[digest] = data
        return digest

    def load(self, digest: str) -> bytes:
        """Load bytes by digest.

        Raises:
            KeyError: no blob is stored under this digest.
        """
        return self._blobs[digest]

    def corrupt(self, digest: str, data: bytes) -> None:
        """Overwrite the blob at `digest` — fault injection for tamper tests."""
        self._blobs[digest] = data


@pytest.fixture
def checkpoint_store() -> InMemoryCheckpointStore:
    return InMemoryCheckpointStore()


@pytest.fixture
def pinned_spec() -> PinnedCampaignSpec:
    return make_pinned_spec()


@pytest.fixture
def orchestrator(
    pinned_spec: PinnedCampaignSpec, checkpoint_store: InMemoryCheckpointStore
) -> Iterator[CampaignOrchestrator]:
    yield CampaignOrchestrator(pinned_spec, checkpoints=checkpoint_store)
