"""§10.4 manifest schema, effective grants, and compatibility checks."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from evoruntime.plugins.manifest import (
    CompatibilityRange,
    NetworkMode,
    PermissionRequest,
    check_compatibility,
    effective_grant,
    validate_manifest,
)
from tests.plugins.support import RUNTIME_VERSION, make_manifest


class TestManifestValidation:
    def test_brokered_network_requires_model_access_and_hosts(self) -> None:
        with pytest.raises(ValidationError, match="model_access"):
            make_manifest(
                permissions=PermissionRequest(
                    network=NetworkMode.BROKERED, model_hosts=("api.x.ai",)
                )
            )
        with pytest.raises(ValidationError, match="model_hosts"):
            make_manifest(
                permissions=PermissionRequest(network=NetworkMode.BROKERED, model_access=True)
            )

    def test_floating_pinned_image_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="digest-pinned"):
            make_manifest(
                reproducibility={
                    "pinned_image": "ghcr.io/acme/plugin:latest",
                    "seed": 7,
                }
            )

    def test_valid_manifest_admits_clean(self) -> None:
        assert validate_manifest(make_manifest(), RUNTIME_VERSION) == ()

    def test_deterministic_without_seed_is_flagged(self) -> None:
        manifest = make_manifest(
            reproducibility={
                "pinned_image": "ghcr.io/acme/plugin@sha256:" + "ab" * 32,
                "deterministic": True,
                "seed": None,
            }
        )
        problems = validate_manifest(manifest, RUNTIME_VERSION)
        assert len(problems) == 1
        assert "seed" in problems[0]

    def test_compatibility_mismatch_is_flagged(self) -> None:
        manifest = make_manifest(compatibility={"min_runtime": "2.0.0", "max_runtime": "3.0.0"})
        problems = validate_manifest(manifest, RUNTIME_VERSION)
        assert len(problems) == 1
        assert "outside the declared compatibility range" in problems[0]


class TestCompatibilityRange:
    def test_inclusive_bounds(self) -> None:
        compat = make_manifest().compatibility
        assert check_compatibility(compat, "1.0.0")
        assert check_compatibility(compat, "2.0.0")
        assert not check_compatibility(compat, "0.9.0")
        assert not check_compatibility(compat, "2.0.1")

    def test_unbounded_max(self) -> None:
        compat = CompatibilityRange(min_runtime="1.0.0")
        assert check_compatibility(compat, "99.0.0")

    def test_inverted_range_is_rejected_at_construction(self) -> None:
        with pytest.raises(ValidationError, match="must not be lower"):
            CompatibilityRange(min_runtime="2.0.0", max_runtime="1.0.0")


class TestEffectiveGrant:
    def test_grant_is_the_intersection_not_the_request(self) -> None:
        requested = PermissionRequest(
            network=NetworkMode.BROKERED,
            model_access=True,
            model_hosts=("api.x.ai", "api.openai.com", "evil.example.com"),
            filesystem_read=("datasets/", "holdout/"),
            tools=("search", "shell"),
        )
        tenant = PermissionRequest(
            network=NetworkMode.BROKERED,
            model_access=True,
            model_hosts=("api.x.ai",),
            filesystem_read=("datasets/",),
            tools=("search",),
        )
        grant = effective_grant(requested, tenant)
        assert grant.model_hosts == ("api.x.ai",)
        assert grant.filesystem_read == ("datasets/",)
        assert grant.tools == ("search",)

    def test_any_none_plane_kills_network_and_model(self) -> None:
        requested = PermissionRequest(network=NetworkMode.BROKERED, model_access=True)
        artifact_policy = PermissionRequest(network=NetworkMode.NONE, model_access=False)
        grant = effective_grant(requested, artifact_policy)
        assert grant.network is NetworkMode.NONE
        assert grant.model_access is False

    def test_disjoint_host_lists_grant_nothing(self) -> None:
        requested = PermissionRequest(model_hosts=("api.x.ai",))
        policy = PermissionRequest(model_hosts=("api.openai.com",))
        grant = effective_grant(requested, policy)
        assert grant.model_hosts == ()
