"""AES-256-GCM encryption for BYOK user API keys.

Follows the same pattern as credential_crypto.py but with a distinct salt
so key rotation is independent.

Key source: derived from settings.secret_key via PBKDF2-SHA256 (100 000 iterations).
Each encrypted value gets a unique 12-byte nonce prepended to the ciphertext,
stored as a single base64 blob.

NEVER log or return decrypted key values.
"""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

_NONCE_BYTES = 12  # GCM standard
_KEY_SALT = b"threatgenix-byok-v1"


def _derive_key(app_secret: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KEY_SALT,
        iterations=100_000,
    )
    return kdf.derive(app_secret.encode("utf-8"))


def _get_key() -> bytes:
    from app.config import settings
    return _derive_key(settings.secret_key)


def encrypt_key(plaintext: str) -> str:
    """Encrypt an API key and return a base64-encoded nonce||ciphertext blob."""
    key = _get_key()
    nonce = os.urandom(_NONCE_BYTES)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def decrypt_key(ciphertext: str) -> str:
    """Decrypt a blob produced by encrypt_key and return the plaintext."""
    key = _get_key()
    raw = base64.b64decode(ciphertext)
    if len(raw) <= _NONCE_BYTES:
        raise ValueError("Encrypted key blob is too short")
    nonce = raw[:_NONCE_BYTES]
    ct = raw[_NONCE_BYTES:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode("utf-8")


def mask_key(plaintext: str) -> str:
    """Return a masked version showing only the last 4 characters."""
    if len(plaintext) <= 4:
        return "****"
    return f"{'*' * (len(plaintext) - 4)}{plaintext[-4:]}"
