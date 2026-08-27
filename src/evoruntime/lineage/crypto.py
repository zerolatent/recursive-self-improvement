"""Tenant-key payload encryption.

One master key (from env/secrets, never committed — see `LineageSettings`)
is never used directly. Each tenant gets its own derived key via HKDF, so a
key compromise or an accidental cross-tenant query can't decrypt another
tenant's payloads with the same key material, and rotating a single
tenant's key doesn't require re-provisioning every tenant.

Encryption is AES-256-GCM: authenticated, so a tampered ciphertext (or one
decrypted under the wrong tenant/key) fails loudly instead of returning
corrupted plaintext.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from evoruntime.lineage.settings import LineageSettings, get_lineage_settings

_NONCE_LENGTH_BYTES = 12
_KEY_LENGTH_BYTES = 32


class PayloadEncryptionNotConfiguredError(Exception):
    """Raised when no master key is configured. Encrypting payloads without
    one would silently store plaintext-adjacent data; refuse instead.
    """


class TenantKeyProvider:
    """Derives and caches per-tenant AES-256-GCM keys from a master key."""

    def __init__(self, settings: LineageSettings | None = None) -> None:
        self._settings = settings or get_lineage_settings()
        self._cache: dict[str, bytes] = {}

    @property
    def key_version(self) -> str:
        return self._settings.payload_key_version

    def _master_key_bytes(self) -> bytes:
        raw = self._settings.payload_master_key
        if not raw:
            raise PayloadEncryptionNotConfiguredError(
                "EVORUNTIME_PAYLOAD_MASTER_KEY is not set; refusing to encrypt payloads "
                "without a configured key (never commit this value — set it via the "
                "project secrets store or environment)."
            )
        return base64.b64decode(raw)

    def derive_tenant_key(self, tenant_id: str) -> bytes:
        """Return the AES-256-GCM key for `tenant_id`, deriving and caching it."""
        cached = self._cache.get(tenant_id)
        if cached is not None:
            return cached
        derived = HKDF(
            algorithm=SHA256(),
            length=_KEY_LENGTH_BYTES,
            salt=None,
            info=f"evoruntime-payload-key:{self._settings.payload_key_version}:{tenant_id}".encode(),
        ).derive(self._master_key_bytes())
        self._cache[tenant_id] = derived
        return derived

    def encrypt(self, tenant_id: str, plaintext: bytes) -> bytes:
        """Encrypt `plaintext` for `tenant_id`. Returns nonce || ciphertext."""
        key = self.derive_tenant_key(tenant_id)
        nonce = os.urandom(_NONCE_LENGTH_BYTES)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data=tenant_id.encode())
        return nonce + ciphertext

    def decrypt(self, tenant_id: str, nonce_and_ciphertext: bytes) -> bytes:
        """Decrypt a blob produced by `encrypt` for the same `tenant_id`.

        Raises `cryptography.exceptions.InvalidTag` if the ciphertext was
        tampered with, produced for a different tenant, or encrypted under a
        different key version.
        """
        key = self.derive_tenant_key(tenant_id)
        nonce, ciphertext = (
            nonce_and_ciphertext[:_NONCE_LENGTH_BYTES],
            nonce_and_ciphertext[_NONCE_LENGTH_BYTES:],
        )
        return AESGCM(key).decrypt(nonce, ciphertext, associated_data=tenant_id.encode())
