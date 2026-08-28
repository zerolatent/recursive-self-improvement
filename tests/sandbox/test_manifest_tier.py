"""Manifest IsolationTier field: validator cross-checks against execution needs."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from evoruntime.core.isolation import IsolationTier
from evoruntime.plugins.manifest import NetworkMode, PermissionRequest
from tests.plugins.support import make_manifest


class TestTierCrossChecks:
    def test_explicit_tier_agreeing_with_network_validates(self) -> None:
        manifest = make_manifest(
            isolation_tier=IsolationTier.BROKERED,
            permissions=PermissionRequest(
                network=NetworkMode.BROKERED, model_access=True, model_hosts=("api.x.ai",)
            ),
        )
        assert manifest.isolation_tier is IsolationTier.BROKERED

    def test_explicit_executable_tier_with_brokered_network_rejected(self) -> None:
        with pytest.raises(ValidationError, match="no direct network path"):
            make_manifest(
                isolation_tier=IsolationTier.EXECUTABLE,
                permissions=PermissionRequest(
                    network=NetworkMode.BROKERED, model_access=True, model_hosts=("api.x.ai",)
                ),
            )

    def test_explicit_highest_tier_with_brokered_network_rejected(self) -> None:
        with pytest.raises(ValidationError, match="no direct network path"):
            make_manifest(
                isolation_tier=IsolationTier.HIGHEST,
                permissions=PermissionRequest(
                    network=NetworkMode.BROKERED, model_access=True, model_hosts=("api.x.ai",)
                ),
            )

    def test_brokered_tier_requires_brokered_network_and_hosts(self) -> None:
        with pytest.raises(ValidationError, match="brokered requires network=brokered"):
            make_manifest(
                isolation_tier=IsolationTier.BROKERED,
                permissions=PermissionRequest(network=NetworkMode.NONE),
            )

    def test_text_only_tier_cannot_request_brokered_network(self) -> None:
        # model_access + model_hosts satisfy the earlier brokered-network
        # validator so the tier cross-check is the check under test.
        with pytest.raises(ValidationError, match="never executes"):
            make_manifest(
                isolation_tier=IsolationTier.TEXT_ONLY,
                permissions=PermissionRequest(
                    network=NetworkMode.BROKERED,
                    model_access=True,
                    model_hosts=("api.x.ai",),
                ),
            )

    def test_text_only_tier_cannot_request_model_access(self) -> None:
        with pytest.raises(ValidationError, match="never executes"):
            make_manifest(
                isolation_tier=IsolationTier.TEXT_ONLY,
                permissions=PermissionRequest(network=NetworkMode.NONE, model_access=True),
            )

    def test_phase1_manifest_without_tier_still_validates(self) -> None:
        """Manifests predating the tier field keep validating unchanged."""
        manifest = make_manifest(
            permissions=PermissionRequest(
                network=NetworkMode.BROKERED, model_access=True, model_hosts=("api.x.ai",)
            ),
        )
        # The field defaults to executable; the strict cross-check applies
        # only when the tier is explicitly declared.
        assert manifest.isolation_tier is IsolationTier.EXECUTABLE

    def test_default_tier_is_executable(self) -> None:
        assert make_manifest().isolation_tier is IsolationTier.EXECUTABLE
