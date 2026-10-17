"""
AegisHMAC Master Key Envelope Encryption.
Uses AES-256-GCM authenticated encryption to protect symmetric client keys at rest in MongoDB.
Simulates Hardware Security Module (HSM) / KMS key wrapping per FIPS 140 requirements.
"""

import base64
import os
from typing import Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.core.errors import AegisSecurityError


def _parse_master_key(master_key: Union[str, bytes]) -> bytes:
    """Validate and convert master key to 32 bytes (256 bits)."""
    if isinstance(master_key, str):
        try:
            if len(master_key) == 64 and all(c in "0123456789abcdefABCDEF" for c in master_key):
                key_bytes = bytes.fromhex(master_key)
            else:
                key_bytes = master_key.encode("utf-8")
        except ValueError:
            key_bytes = master_key.encode("utf-8")
    else:
        key_bytes = bytes(master_key)

    if len(key_bytes) != 32:
        raise AegisSecurityError(
            message=f"Master key must be exactly 32 bytes (256 bits), got {len(key_bytes)} bytes",
            status_code=500,
            error_code="INVALID_MASTER_KEY",
        )
    return key_bytes


def encrypt_secret(plaintext_secret: str, master_key: Union[str, bytes]) -> str:
    """
    Encrypt a client secret key using AES-256-GCM authenticated encryption.

    :param plaintext_secret: The raw 256-bit client secret key (e.g. hex string).
    :param master_key: The 32-byte master encryption key (hex or bytes).
    :return: Base64-encoded string containing [12-byte IV + Ciphertext + 16-byte Auth Tag].
    """
    key_bytes = _parse_master_key(master_key)
    aesgcm = AESGCM(key_bytes)

    # 12-byte (96-bit) cryptographically random IV per NIST SP 800-38D
    iv = os.urandom(12)
    plaintext_bytes = plaintext_secret.encode("utf-8")

    # AESGCM encrypt appends the 16-byte authentication tag to the ciphertext
    encrypted_bytes = aesgcm.encrypt(iv, plaintext_bytes, None)

    # Pack IV + Encrypted Data (Ciphertext + Tag)
    payload = iv + encrypted_bytes
    return base64.b64encode(payload).decode("utf-8")


def decrypt_secret(encrypted_b64: str, master_key: Union[str, bytes]) -> str:
    """
    Decrypt and verify an AES-256-GCM encrypted client secret key.

    :param encrypted_b64: Base64-encoded [IV + Ciphertext + Auth Tag].
    :param master_key: The 32-byte master encryption key.
    :return: The decrypted plaintext secret key.
    :raises AegisSecurityError: If data has been tampered with or key is incorrect.
    """
    key_bytes = _parse_master_key(master_key)
    aesgcm = AESGCM(key_bytes)

    try:
        raw_payload = base64.b64decode(encrypted_b64.encode("utf-8"))
    except Exception as exc:
        raise AegisSecurityError(
            message=f"Invalid base64 payload for encrypted secret: {exc}",
            status_code=500,
            error_code="DECRYPTION_FAILED",
        )

    if len(raw_payload) < 28:  # 12-byte IV + min 16-byte tag
        raise AegisSecurityError(
            message="Encrypted payload is too short to be valid AES-GCM data",
            status_code=500,
            error_code="DECRYPTION_FAILED",
        )

    iv = raw_payload[:12]
    ciphertext_and_tag = raw_payload[12:]

    try:
        decrypted_bytes = aesgcm.decrypt(iv, ciphertext_and_tag, None)
        return decrypted_bytes.decode("utf-8")
    except Exception as exc:
        raise AegisSecurityError(
            message="Failed to decrypt secret: Authentication tag mismatch or corrupted data",
            status_code=500,
            error_code="DECRYPTION_AUTHENTICATION_FAILED",
            details={"reason": str(exc)},
        )
