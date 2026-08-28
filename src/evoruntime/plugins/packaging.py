"""Signed OCI packaging helper with SBOM (E2 supply-chain admission).

Plugins ship as OCI image-layout archives: a deterministic tar containing
``oci-layout``, ``index.json``, and content-addressed blobs under
``blobs/sha256/``. Three properties matter:

* **Deterministic.** Fixed mtimes, sorted entries, no compression
  randomness — rebuilding the same plugin from the same inputs yields the
  same archive bytes, which is what makes the manifest's
  ``reproducibility.pinned_image`` digest meaningful.
* **SBOM-carrying.** An SPDX 2.3 JSON document lists every payload file
  with its sha256, stored as its own blob and attached to the image
  manifest via the OCI 1.1 referrers ``subject`` field. A plugin without a
  verifiable SBOM is not admissible.
* **Signed.** The image manifest bytes carry a detached Ed25519 signature
  (Phase 0 signing service); the signature blob is referenced from
  ``index.json`` annotations so verifiers can find it without trusting
  the archive's file order.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from evoruntime.plugins.manifest import PluginManifest
from evoruntime.security.signing import DetachedSignature, sign, verify

MEDIA_TYPE_IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MEDIA_TYPE_IMAGE_CONFIG = "application/vnd.oci.image.config.v1+json"
MEDIA_TYPE_IMAGE_LAYER = "application/vnd.oci.image.layer.v1.tar"
MEDIA_TYPE_SBOM = "application/spdx+json"

_ANNOTATION_SIGNATURE_BLOB = "org.evoruntime.admission.signature-digest"
_ANNOTATION_PLUGIN_ID = "org.evoruntime.plugin.id"
_ANNOTATION_PLUGIN_VERSION = "org.evoruntime.plugin.version"
_FIXED_MTIME = 0


class PackagingError(ValueError):
    """Raised when an archive violates the packaging contract."""


class ImageVerificationError(ValueError):
    """Raised when a plugin image fails verification."""


@dataclass(frozen=True)
class BuiltPluginImage:
    """The archive bytes plus the digests a publisher records."""

    archive: bytes
    manifest_digest: str
    sbom_digest: str
    signature: DetachedSignature


def _sha256(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _descriptor(media_type: str, blob: bytes) -> dict[str, Any]:
    return {"mediaType": media_type, "digest": _sha256(blob), "size": len(blob)}


def build_sbom(manifest: PluginManifest, payload: Mapping[str, bytes]) -> bytes:
    """SPDX 2.3 JSON document covering every payload file by sha256."""
    packages = []
    for index, path in enumerate(sorted(payload), start=1):
        packages.append(
            {
                "name": path,
                "SPDXID": f"SPDXRef-File-{index}",
                "versionInfo": manifest.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "checksums": [{"algorithm": "SHA256", "checksumValue": _sha256(payload[path])[7:]}],
            }
        )
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{manifest.plugin_id}-{manifest.version}",
        "documentNamespace": (
            f"https://evoruntime.dev/plugins/{manifest.plugin_id}/{manifest.version}"
        ),
        "creationInfo": {"created": "1970-01-01T00:00:00Z", "creators": ["Tool: evoruntime-e2"]},
        "packages": packages,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def build_plugin_image(
    manifest: PluginManifest,
    payload: Mapping[str, bytes],
    *,
    private_key: Ed25519PrivateKey,
) -> BuiltPluginImage:
    """Package a plugin into a deterministic, signed OCI image-layout archive."""
    if not payload:
        raise PackagingError("plugin payload is empty")

    layer = _build_tar({path: payload[path] for path in sorted(payload)})
    config = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "Entrypoint": list(manifest.entrypoint.command),
                "Labels": {
                    _ANNOTATION_PLUGIN_ID: manifest.plugin_id,
                    _ANNOTATION_PLUGIN_VERSION: manifest.version,
                },
            },
            "rootfs": {"type": "layers", "diff_ids": [_sha256(layer)]},
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    image_manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": MEDIA_TYPE_IMAGE_MANIFEST,
            "config": _descriptor(MEDIA_TYPE_IMAGE_CONFIG, config),
            "layers": [_descriptor(MEDIA_TYPE_IMAGE_LAYER, layer)],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    image_manifest_digest = _sha256(image_manifest)

    sbom = build_sbom(manifest, payload)
    # OCI 1.1 referrers: the SBOM manifest points at the image manifest via
    # `subject`, so a verifier can discover the SBOM from the image alone.
    sbom_manifest = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": MEDIA_TYPE_IMAGE_MANIFEST,
            "artifactType": MEDIA_TYPE_SBOM,
            "blobs": [_descriptor(MEDIA_TYPE_SBOM, sbom)],
            "subject": _descriptor(MEDIA_TYPE_IMAGE_MANIFEST, image_manifest),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    signature = sign(private_key, image_manifest)
    signature_blob = json.dumps(
        {
            "signature": signature.signature.hex(),
            "publicKey": signature.public_key.hex(),
            "signedDigest": image_manifest_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    blobs = {
        _sha256(config): config,
        _sha256(layer): layer,
        _sha256(image_manifest): image_manifest,
        _sha256(sbom): sbom,
        _sha256(sbom_manifest): sbom_manifest,
        _sha256(signature_blob): signature_blob,
    }
    index = json.dumps(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                _descriptor(MEDIA_TYPE_IMAGE_MANIFEST, image_manifest),
                _descriptor(MEDIA_TYPE_IMAGE_MANIFEST, sbom_manifest),
            ],
            "annotations": {
                _ANNOTATION_SIGNATURE_BLOB: _sha256(signature_blob),
                _ANNOTATION_PLUGIN_ID: manifest.plugin_id,
                _ANNOTATION_PLUGIN_VERSION: manifest.version,
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    layout_files = {
        "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
        "index.json": index,
        **{f"blobs/{digest}": blob for digest, blob in blobs.items()},
    }
    return BuiltPluginImage(
        archive=_build_tar(layout_files),
        manifest_digest=image_manifest_digest,
        sbom_digest=_sha256(sbom),
        signature=signature,
    )


def _build_tar(files: Mapping[str, bytes]) -> bytes:
    """Deterministic tar: sorted paths, fixed mtime, uniform mode."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as tar:
        for path in sorted(files):
            content = files[path]
            info = tarfile.TarInfo(name=path)
            info.size = len(content)
            info.mtime = _FIXED_MTIME
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _read_archive(archive: bytes) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                files[member.name] = handle.read()
    except tarfile.TarError as exc:
        # A truncated or structurally corrupt archive is a verification
        # failure, not an unexpected crash — surface it as one.
        raise ImageVerificationError(f"archive is not a readable tar: {exc}") from exc
    return files


def verify_plugin_image(archive: bytes) -> dict[str, Any]:
    """Verify an OCI plugin archive end to end.

    Checks: OCI layout present, every blob matches its descriptor digest,
    the image-manifest signature verifies against the attached public key,
    and the SBOM exists, is attached to the image manifest, and covers the
    layer's files with matching checksums. Returns a report dict; raises
    :class:`ImageVerificationError` on any failure.
    """
    files = _read_archive(archive)
    if "oci-layout" not in files or "index.json" not in files:
        raise ImageVerificationError("archive is not an OCI image layout")

    # Every blob must match its own content digest — no unverified bytes ride
    # in the store, even blobs no descriptor references (e.g. the config).
    for path, content in files.items():
        if path.startswith("blobs/") and _sha256(content) != path.split("/", 1)[1]:
            raise ImageVerificationError(f"blob {path} content does not match its digest")

    index = json.loads(files["index.json"])
    if not index.get("manifests"):
        raise ImageVerificationError("index.json lists no image manifest")
    # The image manifest is the first entry; the SBOM manifest is discovered
    # by its `subject` pointing back at it (OCI 1.1 referrers).
    image_descriptor = index["manifests"][0]
    image_manifest = _blob(files, image_descriptor["digest"])

    _verify_signature(files, index, image_manifest)

    manifest_data = json.loads(image_manifest)
    for layer_descriptor in manifest_data["layers"]:
        _blob(files, layer_descriptor["digest"])  # _blob checks digest match

    sbom_manifest = _find_sbom_manifest(files, index, image_manifest)
    sbom = _blob(files, sbom_manifest["blobs"][0]["digest"])
    _verify_sbom_covers_layer(files, manifest_data, sbom)

    return {
        "verified": True,
        "manifest_digest": _sha256(image_manifest),
        "sbom_digest": _sha256(sbom),
        "plugin_id": index.get("annotations", {}).get(_ANNOTATION_PLUGIN_ID),
    }


def _find_sbom_manifest(
    files: dict[str, bytes], index: dict[str, Any], image_manifest: bytes
) -> dict[str, Any]:
    image_digest = _sha256(image_manifest)
    for descriptor in index["manifests"]:
        data: dict[str, Any] = json.loads(_blob(files, descriptor["digest"]))
        subject = data.get("subject") or {}
        if subject.get("digest") == image_digest and data.get("artifactType") == MEDIA_TYPE_SBOM:
            return data
    raise ImageVerificationError("no SBOM manifest is attached to the image manifest")


def _blob(files: dict[str, bytes], digest: str) -> bytes:
    path = f"blobs/{digest}"
    if path not in files:
        raise ImageVerificationError(f"missing blob {digest}")
    blob = files[path]
    if _sha256(blob) != digest:
        raise ImageVerificationError(f"blob {digest} content does not match its digest")
    return blob


def _verify_signature(
    files: dict[str, bytes], index: dict[str, Any], image_manifest: bytes
) -> None:
    signature_digest = index.get("annotations", {}).get(_ANNOTATION_SIGNATURE_BLOB)
    if not signature_digest:
        raise ImageVerificationError("index.json carries no admission signature annotation")
    envelope = json.loads(_blob(files, signature_digest))
    detached = DetachedSignature(
        signature=bytes.fromhex(envelope["signature"]),
        public_key=bytes.fromhex(envelope["publicKey"]),
    )
    if not verify(detached, image_manifest):
        raise ImageVerificationError("image manifest signature does not verify")


def _verify_sbom_covers_layer(
    files: dict[str, bytes], manifest_data: dict[str, Any], sbom: bytes
) -> None:
    layer_bytes = _blob(files, manifest_data["layers"][0]["digest"])
    layer_files = _read_archive(layer_bytes)
    document = json.loads(sbom)
    checksums = {
        package["name"]: package["checksums"][0]["checksumValue"]
        for package in document.get("packages", [])
    }
    for path, content in layer_files.items():
        expected = hashlib.sha256(content).hexdigest()
        if checksums.get(path) != expected:
            raise ImageVerificationError(f"SBOM does not cover layer file {path!r} correctly")
