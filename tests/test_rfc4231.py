"""
RFC 4231 Test Vectors for HMAC-SHA256 & Core Cryptographic Verification.
Validates implementation against IETF standards to guarantee mathematical correctness.
"""

import sys
import os
import pytest

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.core.crypto import (
    compute_hmac,
    constant_time_compare,
    hash_payload,
    generate_key_hex,
    generate_client_id,
    generate_nonce,
)
from app.core.errors import UnsupportedAlgorithmError


def test_rfc4231_case_1():
    """RFC 4231 - Test Case 1: Standard key and data."""
    key = bytes([0x0B] * 20)
    data = b"Hi There"
    expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    assert compute_hmac(key, data, "HMAC-SHA256") == expected


def test_rfc4231_case_2():
    """RFC 4231 - Test Case 2: Short key test."""
    key = b"Jefe"
    data = b"what do ya want for nothing?"
    expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    assert compute_hmac(key, data, "HMAC-SHA256") == expected


def test_rfc4231_case_3():
    """RFC 4231 - Test Case 3: 20-byte key with 50-byte repeated data."""
    key = bytes([0xAA] * 20)
    data = bytes([0xDD] * 50)
    expected = "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
    assert compute_hmac(key, data, "HMAC-SHA256") == expected


def test_rfc4231_case_4():
    """RFC 4231 - Test Case 4: 25-byte sequential key."""
    key = bytes(range(1, 26))
    data = bytes([0xCD] * 50)
    expected = "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"
    assert compute_hmac(key, data, "HMAC-SHA256") == expected


def test_rfc4231_case_5():
    """RFC 4231 - Test Case 5: Standard truncation vector test (128-bit prefix)."""
    key = bytes([0x0C] * 20)
    data = b"Test With Truncation"
    # RFC 4231 specifies 128-bit truncated output
    expected_truncated = "a3b6167473100ee06e0c796c2955552b"
    result = compute_hmac(key, data, "HMAC-SHA256")
    assert result.startswith(expected_truncated)


def test_rfc4231_case_6():
    """RFC 4231 - Test Case 6: Key larger than block size (131 bytes > 64 bytes)."""
    key = bytes([0xAA] * 131)
    data = b"Test Using Larger Than Block-Size Key - Hash Key First"
    expected = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
    assert compute_hmac(key, data, "HMAC-SHA256") == expected


def test_rfc4231_case_7():
    """RFC 4231 - Test Case 7: Key and data both larger than block size."""
    key = bytes([0xAA] * 131)
    data = (
        b"This is a test using a larger than block-size key and a larger than "
        b"block-size data. The key needs to be hashed before being used by the "
        b"HMAC algorithm."
    )
    expected = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
    assert compute_hmac(key, data, "HMAC-SHA256") == expected


def test_constant_time_compare():
    """Verify timing-safe comparison logic."""
    sig1 = "5bdcc146bf60754e6a0424260895750491f323bce743528041430c4f6d49c866"
    sig2 = "5bdcc146bf60754e6a0424260895750491f323bce743528041430c4f6d49c866"
    tampered = "5bdcc146bf60754e6a0424260895750491f323bce743528041430c4f6d49c867"

    assert constant_time_compare(sig1, sig2) is True
    assert constant_time_compare(sig1, tampered) is False
    assert constant_time_compare(sig1, "") is False


def test_empty_payload_hashing():
    """Verify SHA-256 hash for empty body matches the standard empty hash."""
    expected_empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert hash_payload("") == expected_empty_hash
    assert hash_payload(b"") == expected_empty_hash
    assert hash_payload(None) == expected_empty_hash


def test_unsupported_algorithm():
    """Verify invalid algorithm raises UnsupportedAlgorithmError."""
    with pytest.raises(UnsupportedAlgorithmError):
        compute_hmac("key", "message", "MD5")


def test_csprng_entropy():
    """Verify CSPRNG generators produce unique, correct-length keys and nonces."""
    key1 = generate_key_hex(32)
    key2 = generate_key_hex(32)
    assert len(key1) == 64
    assert len(key2) == 64
    assert key1 != key2

    client_id = generate_client_id()
    assert client_id.startswith("client_")
    assert len(client_id) == 23

    nonce1 = generate_nonce()
    nonce2 = generate_nonce()
    assert len(nonce1) == 32
    assert nonce1 != nonce2
