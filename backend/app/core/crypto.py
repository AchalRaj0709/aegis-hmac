"""
AegisHMAC Cryptographic Core Engine.
Implements RFC 2104 / NIST FIPS 198 compliant HMAC operations, SHA-256 body hashing,
constant-time signature comparison, and CSPRNG credential generation.
"""

import hashlib
import hmac
import secrets
from typing import Union, Tuple
from app.core.errors import UnsupportedAlgorithmError


SUPPORTED_ALGORITHMS = {
    "HMAC-SHA256": hashlib.sha256,
    "SHA256": hashlib.sha256,
    "HMAC-SHA512": hashlib.sha512,
    "SHA512": hashlib.sha512,
}


def generate_key_bytes(num_bytes: int = 32) -> bytes:
    """
    Generate cryptographically secure pseudo-random bytes.
    Default: 32 bytes (256 bits) of entropy per NIST SP 800-57 guidelines.
    """
    return secrets.token_bytes(num_bytes)


def generate_key_hex(num_bytes: int = 32) -> str:
    """
    Generate a 256-bit secret key as a 64-character hexadecimal string.
    """
    return secrets.token_hex(num_bytes)


def generate_client_id(prefix: str = "client_") -> str:
    """
    Generate a unique, cryptographically random Client ID.
    Example: 'client_7f8a9b2c3d4e5f60'
    """
    random_part = secrets.token_hex(8)
    return f"{prefix}{random_part}"


def generate_nonce(num_bytes: int = 16) -> str:
    """
    Generate a unique, single-use cryptographic nonce.
    Default: 16 bytes (32-character hex).
    """
    return secrets.token_hex(num_bytes)


def hash_payload(payload: Union[str, bytes, None]) -> str:
    """
    Compute the SHA-256 hex digest of the raw request payload.
    Empty body returns standard SHA-256 empty hash:
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    """
    if payload is None:
        raw_bytes = b""
    elif isinstance(payload, str):
        raw_bytes = payload.encode("utf-8")
    elif isinstance(payload, (bytes, bytearray)):
        raw_bytes = bytes(payload)
    else:
        raise ValueError(f"Payload must be str, bytes, or None, got: {type(payload)}")

    return hashlib.sha256(raw_bytes).hexdigest()


def compute_hmac(
    key: Union[str, bytes],
    message: Union[str, bytes],
    algorithm: str = "HMAC-SHA256",
) -> str:
    """
    Compute the HMAC hex digest for a given message using the specified shared secret key.

    :param key: Secret key as hex string, utf-8 string, or raw bytes.
    :param message: Message/Canonical string as string or bytes.
    :param algorithm: Algorithm name ('HMAC-SHA256' or 'HMAC-SHA512').
    :return: Lowercase hexadecimal signature string.
    """
    algo_key = algorithm.upper()
    if algo_key not in SUPPORTED_ALGORITHMS:
        raise UnsupportedAlgorithmError(algorithm)

    hash_func = SUPPORTED_ALGORITHMS[algo_key]

    # Convert key to bytes
    if isinstance(key, str):
        # If key is standard 64-char hex string, decode hex; otherwise encode as UTF-8
        try:
            if len(key) in (64, 128) and all(c in "0123456789abcdefABCDEF" for c in key):
                key_bytes = bytes.fromhex(key)
            else:
                key_bytes = key.encode("utf-8")
        except ValueError:
            key_bytes = key.encode("utf-8")
    else:
        key_bytes = bytes(key)

    # Convert message to bytes
    if isinstance(message, str):
        message_bytes = message.encode("utf-8")
    else:
        message_bytes = bytes(message)

    digest = hmac.new(key_bytes, message_bytes, hash_func).hexdigest()
    return digest.lower()


def constant_time_compare(val_a: Union[str, bytes], val_b: Union[str, bytes]) -> bool:
    """
    Perform a constant-time comparison of two values to prevent timing side-channel attacks.
    Executes in constant time regardless of where or whether the values differ.
    """
    bytes_a = val_a.encode("utf-8") if isinstance(val_a, str) else bytes(val_a)
    bytes_b = val_b.encode("utf-8") if isinstance(val_b, str) else bytes(val_b)
    return hmac.compare_digest(bytes_a, bytes_b)
