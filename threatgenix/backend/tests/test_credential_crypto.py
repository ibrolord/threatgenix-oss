"""Tests for credential_crypto — AES-256-GCM encrypt/decrypt round-trips."""
from __future__ import annotations

import base64

import pytest

from app.services.credential_crypto import decrypt_secret, encrypt_secret


class TestEncryptDecryptRoundTrip:
    def test_short_secret(self):
        plaintext = "my-api-key"
        assert decrypt_secret(encrypt_secret(plaintext)) == plaintext

    def test_long_secret(self):
        plaintext = "Bearer " + "a" * 512
        assert decrypt_secret(encrypt_secret(plaintext)) == plaintext

    def test_unicode_secret(self):
        plaintext = "pässword-mit-ümlaut"
        assert decrypt_secret(encrypt_secret(plaintext)) == plaintext

    def test_each_encrypt_produces_different_ciphertext(self):
        """Nonce randomness: two encryptions of the same value must differ."""
        plaintext = "secret"
        c1 = encrypt_secret(plaintext)
        c2 = encrypt_secret(plaintext)
        assert c1 != c2

    def test_encrypted_is_valid_base64(self):
        blob = encrypt_secret("test")
        raw = base64.b64decode(blob)  # should not raise
        # nonce (12) + at least 1 ciphertext byte + 16 GCM tag
        assert len(raw) >= 29

    def test_tampered_ciphertext_raises(self):
        blob = encrypt_secret("secret")
        raw = bytearray(base64.b64decode(blob))
        raw[-1] ^= 0xFF  # flip last byte of GCM tag
        with pytest.raises(Exception):
            decrypt_secret(base64.b64encode(bytes(raw)).decode())

    def test_truncated_blob_raises(self):
        with pytest.raises(ValueError, match="too short"):
            decrypt_secret(base64.b64encode(b"short").decode())

    def test_env_key_override(self, monkeypatch):
        """SCAN_CREDENTIAL_KEY env var takes precedence over derived key."""
        custom_key = base64.b64encode(b"k" * 32).decode()
        monkeypatch.setenv("SCAN_CREDENTIAL_KEY", custom_key)
        plaintext = "env-key-test"
        blob = encrypt_secret(plaintext)
        assert decrypt_secret(blob) == plaintext

    def test_env_key_wrong_length_raises(self, monkeypatch):
        """16-byte key should raise ValueError."""
        bad_key = base64.b64encode(b"x" * 16).decode()
        monkeypatch.setenv("SCAN_CREDENTIAL_KEY", bad_key)
        with pytest.raises(ValueError, match="32 bytes"):
            encrypt_secret("anything")

    def test_cross_key_decrypt_fails(self, monkeypatch):
        """Decrypting with a different key must fail (authentication error)."""
        key_a = base64.b64encode(b"a" * 32).decode()
        key_b = base64.b64encode(b"b" * 32).decode()

        monkeypatch.setenv("SCAN_CREDENTIAL_KEY", key_a)
        blob = encrypt_secret("secret")

        monkeypatch.setenv("SCAN_CREDENTIAL_KEY", key_b)
        with pytest.raises(Exception):
            decrypt_secret(blob)
