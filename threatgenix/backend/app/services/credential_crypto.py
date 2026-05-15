"""AES-256-GCM envelope encryption for scan credentials.

Secrets are never stored in plaintext. Each credential gets a fresh 12-byte nonce
(prepended to the ciphertext) and is stored as a single base64 blob.

Key source (in priority order):
  1. SCAN_CREDENTIAL_KEY env var — 32 bytes, base64-encoded
  2. Derived from settings.secret_key via PBKDF2-SHA256 (100 000 iterations)

Rotate credentials by re-encrypting if the key changes.
"""
from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_NONCE_BYTES = 12  # GCM standard
_KEY_SALT = b"threatgenix-scan-cred-v1"  # fixed; changing this invalidates all creds


def _derive_key(app_secret: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KEY_SALT,
        iterations=100_000,
    )
    return kdf.derive(app_secret.encode("utf-8"))


def _get_key() -> bytes:
    """Return the 32-byte AES key used for credential encryption."""
    raw = os.environ.get("SCAN_CREDENTIAL_KEY", "")
    if raw:
        key = base64.b64decode(raw)
        if len(key) != 32:
            raise ValueError("SCAN_CREDENTIAL_KEY must decode to exactly 32 bytes")
        return key
    from app.config import settings
    return _derive_key(settings.secret_key)


def encrypt_secret(plaintext: str) -> str:
    """Encrypt *plaintext* and return a base64-encoded nonce||ciphertext blob."""
    key = _get_key()
    nonce = os.urandom(_NONCE_BYTES)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_secret(encrypted: str) -> str:
    """Decrypt a blob produced by :func:`encrypt_secret` and return the plaintext."""
    key = _get_key()
    raw = base64.b64decode(encrypted)
    if len(raw) <= _NONCE_BYTES:
        raise ValueError("Encrypted credential blob is too short")
    nonce = raw[:_NONCE_BYTES]
    ciphertext = raw[_NONCE_BYTES:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None).decode("utf-8")
