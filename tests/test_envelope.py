"""
Unit Tests for AegisHMAC AES-256-GCM Master Key Envelope Encryption.
Validates key confidentiality, integrity tags, and tamper resistance.
"""

import sys
import os
import secrets
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.core.envelope import encrypt_secret, decrypt_secret
from app.core.errors import AegisSecurityError


@pytest.fixture
def master_key():
    """Generate a random 32-byte (256-bit) master encryption key as hex."""
    return secrets.token_hex(32)


def test_encryption_decryption_roundtrip(master_key):
    """Verify that encrypting and then decrypting returns the original secret."""
    original_secret = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
    encrypted = encrypt_secret(original_secret, master_key)

    assert encrypted != original_secret
    assert isinstance(encrypted, str)

    decrypted = decrypt_secret(encrypted, master_key)
    assert decrypted == original_secret


def test_iv_randomness(master_key):
    """Encrypting the same secret twice must produce distinct ciphertexts due to random 96-bit IVs."""
    secret = "my_super_secret_client_key_12345"
    encrypted1 = encrypt_secret(secret, master_key)
    encrypted2 = encrypt_secret(secret, master_key)

    assert encrypted1 != encrypted2
    # But both decrypt back to the same secret
    assert decrypt_secret(encrypted1, master_key) == secret
    assert decrypt_secret(encrypted2, master_key) == secret


def test_tampered_ciphertext_fails(master_key):
    """Modifying even a single character of the base64 ciphertext must fail GCM auth tag check."""
    secret = "production_client_symmetric_secret"
    encrypted = encrypt_secret(secret, master_key)

    # Flip one character in the middle
    tampered_list = list(encrypted)
    tampered_list[20] = "A" if tampered_list[20] != "A" else "B"
    tampered_encrypted = "".join(tampered_list)

    with pytest.raises(AegisSecurityError) as exc_info:
        decrypt_secret(tampered_encrypted, master_key)

    assert exc_info.value.error_code in ("DECRYPTION_AUTHENTICATION_FAILED", "DECRYPTION_FAILED")


def test_wrong_master_key_fails(master_key):
    """Attempting to decrypt with a different master key must fail authentication."""
    secret = "secure_token_payload"
    encrypted = encrypt_secret(secret, master_key)

    different_master_key = secrets.token_hex(32)
    with pytest.raises(AegisSecurityError) as exc_info:
        decrypt_secret(encrypted, different_master_key)

    assert exc_info.value.error_code == "DECRYPTION_AUTHENTICATION_FAILED"


def test_invalid_master_key_length():
    """Master keys that are not 32 bytes (256 bits) must be rejected."""
    short_key = "12345"
    with pytest.raises(AegisSecurityError) as exc_info:
        encrypt_secret("secret", short_key)

    assert exc_info.value.error_code == "INVALID_MASTER_KEY"
