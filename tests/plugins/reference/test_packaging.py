"""Signed-OCI packaging tests for the E7 reference plugins.

Each plugin packages as a deterministic OCI archive (§10.5): SPDX SBOM,
Ed25519 detached signature, manifest.json + plugin source in the layer.
Tests prove end-to-end verification, byte-level determinism, and
tamper rejection — using the same inspection helpers as the E2 suite.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evoruntime.plugins.packaging import (
    ImageVerificationError,
    _read_archive,
    verify_plugin_image,
)
from evoruntime.plugins.reference import (
    REFERENCE_PLUGIN_MODULES,
    build_reference_image,
    load_reference_plugin,
)
from tests.plugins.reference.support import PLUGIN_MODULE_NAMES, load_plugin_module
from tests.plugins.support import rewrite_archive


def _signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def _layer_files(archive: bytes) -> dict[str, bytes]:
    """Read the plugin payload (manifest.json + plugin.py) out of the layer."""
    files = _read_archive(archive)
    index = json.loads(files["index.json"])
    # Two hops: index → image manifest blob → layer descriptor.
    image_manifest = json.loads(files[f"blobs/{index['manifests'][0]['digest']}"])
    layer_digest = image_manifest["layers"][0]["digest"]
    return _read_archive(files[f"blobs/{layer_digest}"])


class TestPackaging:
    @pytest.mark.parametrize("module_name", PLUGIN_MODULE_NAMES)
    def test_image_verifies_end_to_end(self, module_name: str) -> None:
        module = load_plugin_module(module_name)
        image = build_reference_image(module, _signing_key())
        report = verify_plugin_image(image.archive)
        assert report["verified"] is True
        assert report["plugin_id"] == module.build_manifest().plugin_id
        assert report["manifest_digest"].startswith("sha256:")
        assert report["sbom_digest"].startswith("sha256:")

    @pytest.mark.parametrize("module_name", PLUGIN_MODULE_NAMES)
    def test_image_is_deterministic(self, module_name: str) -> None:
        """Same manifest + source + key → byte-identical archive."""
        module = load_plugin_module(module_name)
        key = _signing_key()
        first = build_reference_image(module, key)
        second = build_reference_image(module, key)
        assert first.archive == second.archive
        assert first.manifest_digest == second.manifest_digest
        assert first.sbom_digest == second.sbom_digest

    @pytest.mark.parametrize("module_name", PLUGIN_MODULE_NAMES)
    def test_layer_carries_manifest_and_source(self, module_name: str) -> None:
        module = load_plugin_module(module_name)
        image = build_reference_image(module, _signing_key())
        layer = _layer_files(image.archive)
        manifest_payload = json.loads(layer["manifest.json"])
        assert manifest_payload["plugin_id"] == module.build_manifest().plugin_id
        assert manifest_payload["entrypoint"]["command"] == [
            "python",
            "-m",
            f"evoruntime.plugins.reference.{module_name}",
        ]
        assert b"def build_manifest" in layer["plugin.py"]

    @pytest.mark.parametrize("module_name", PLUGIN_MODULE_NAMES)
    def test_sbom_covers_every_payload_file(self, module_name: str) -> None:
        module = load_plugin_module(module_name)
        image = build_reference_image(module, _signing_key())
        files = _read_archive(image.archive)
        sbom = json.loads(files[f"blobs/{image.sbom_digest}"])
        names = {pkg["name"] for pkg in sbom["packages"]}
        assert {"manifest.json", "plugin.py"} <= names

    @pytest.mark.parametrize("module_name", PLUGIN_MODULE_NAMES)
    def test_tampered_layer_fails_verification(self, module_name: str) -> None:
        module = load_plugin_module(module_name)
        image = build_reference_image(module, _signing_key())
        files = _read_archive(image.archive)
        # Corrupt a byte inside a real blob (tar padding is ignored by the
        # reader, so the corruption must land in actual file content).
        blob_path = next(p for p in files if p.startswith("blobs/"))
        corrupted = bytearray(files[blob_path])
        corrupted[0] ^= 0xFF
        files[blob_path] = bytes(corrupted)
        with pytest.raises(ImageVerificationError):
            verify_plugin_image(rewrite_archive(files))

    @pytest.mark.parametrize("module_name", PLUGIN_MODULE_NAMES)
    def test_detached_signature_is_annotated_in_the_index(self, module_name: str) -> None:
        module = load_plugin_module(module_name)
        image = build_reference_image(module, _signing_key())
        files = _read_archive(image.archive)
        index = json.loads(files["index.json"])
        sig_digest = index["annotations"]["org.evoruntime.admission.signature-digest"]
        envelope = json.loads(files[f"blobs/{sig_digest}"])
        # The envelope carries a real (non-empty) signature over the image manifest.
        assert isinstance(envelope.get("signature"), str) and len(envelope["signature"]) > 0
        assert isinstance(envelope.get("publicKey"), str) and len(envelope["publicKey"]) > 0
        assert envelope.get("signedDigest", "").startswith("sha256:")

    def test_all_four_reference_modules_are_registered(self) -> None:
        assert len(REFERENCE_PLUGIN_MODULES) == 4
        for module_name in REFERENCE_PLUGIN_MODULES:
            module = load_reference_plugin(module_name)
            # Each module serves the §10.2 contract via its ``main`` entrypoint
            # (``python -m evoruntime.plugins.reference.<name>``).
            assert hasattr(module, "build_manifest")
            assert hasattr(module, "main")
