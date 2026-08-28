"""Signed OCI packaging with SBOM — determinism, verification, tamper evidence."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evoruntime.plugins.packaging import (
    ImageVerificationError,
    build_plugin_image,
    verify_plugin_image,
)
from tests.plugins.support import make_manifest

PAYLOAD = {
    "plugin/main.py": b"print('hello')\n",
    "plugin/manifest.json": b'{"name": "ref"}\n',
}


def build() -> bytes:
    image = build_plugin_image(make_manifest(), PAYLOAD, private_key=Ed25519PrivateKey.generate())
    return image.archive


class TestBuildAndVerify:
    def test_built_image_verifies(self) -> None:
        report = verify_plugin_image(build())
        assert report["verified"] is True
        assert report["plugin_id"] == "ref-strategy"
        assert report["manifest_digest"].startswith("sha256:")
        assert report["sbom_digest"].startswith("sha256:")

    def test_empty_payload_is_rejected(self) -> None:
        from evoruntime.plugins.packaging import PackagingError

        with pytest.raises(PackagingError):
            build_plugin_image(make_manifest(), {}, private_key=Ed25519PrivateKey.generate())


class TestDeterminism:
    def test_same_inputs_same_archive_bytes(self) -> None:
        manifest = make_manifest()
        key = Ed25519PrivateKey.generate()
        first = build_plugin_image(manifest, PAYLOAD, private_key=key)
        second = build_plugin_image(manifest, PAYLOAD, private_key=key)
        assert first.archive == second.archive
        assert first.manifest_digest == second.manifest_digest
        assert first.sbom_digest == second.sbom_digest


class TestTamperDetection:
    def test_flipped_payload_byte_fails_verification(self) -> None:
        from evoruntime.plugins.packaging import _read_archive
        from tests.plugins.support import rewrite_archive

        files = _read_archive(build())
        # Corrupt a byte inside an actual blob (tar padding is ignored by the
        # reader, so the corruption must land in real file content).
        blob_path = next(p for p in files if p.startswith("blobs/"))
        corrupted = bytearray(files[blob_path])
        corrupted[0] ^= 0xFF
        files[blob_path] = bytes(corrupted)
        with pytest.raises(ImageVerificationError):
            verify_plugin_image(rewrite_archive(files))

    def test_truncated_archive_fails_verification(self) -> None:
        archive = build()
        with pytest.raises(ImageVerificationError):
            verify_plugin_image(archive[: len(archive) // 2])

    def test_corrupted_signature_fails_verification(self) -> None:
        """A signature that does not verify against the attached key must fail."""
        import json

        from evoruntime.plugins.packaging import _read_archive, _sha256
        from tests.plugins.support import rewrite_archive

        files = _read_archive(build())
        index = json.loads(files["index.json"])
        sig_digest = index["annotations"]["org.evoruntime.admission.signature-digest"]
        envelope = json.loads(files[f"blobs/{sig_digest}"])
        envelope["signature"] = "00" * 64  # structurally valid, cryptographically wrong
        new_blob = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
        files[f"blobs/{_sha256(new_blob)}"] = new_blob
        del files[f"blobs/{sig_digest}"]
        index["annotations"]["org.evoruntime.admission.signature-digest"] = _sha256(new_blob)
        files["index.json"] = json.dumps(index, sort_keys=True, separators=(",", ":")).encode()
        with pytest.raises(ImageVerificationError, match="signature"):
            verify_plugin_image(rewrite_archive(files))
