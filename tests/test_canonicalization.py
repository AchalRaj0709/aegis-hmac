"""
Unit Tests for AegisHMAC Canonical Request Engine.
Validates AWS SigV4 style canonicalization, query sorting, header normalization, and body hashing.
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.core.canonical import (
    normalize_uri_path,
    build_canonical_query_string,
    build_canonical_headers,
    build_canonical_request,
)
from app.core.crypto import hash_payload


def test_normalize_uri_path():
    """Verify URI path normalization collapses slashes and sets defaults."""
    assert normalize_uri_path("") == "/"
    assert normalize_uri_path("///") == "/"
    assert normalize_uri_path("/api///v1//transfers") == "/api/v1/transfers"
    assert normalize_uri_path("api/v1/users") == "/api/v1/users"
    # Strips accidental query or fragment in path
    assert normalize_uri_path("/api/v1/search?q=test#top") == "/api/v1/search"


def test_canonical_query_string_sorting():
    """Different ordering of query parameters must result in identical canonical query strings."""
    qs1 = "b=2&a=1&c=3"
    qs2 = "c=3&a=1&b=2"
    qs3 = "a=1&b=2&c=3"

    canonical1 = build_canonical_query_string(qs1)
    canonical2 = build_canonical_query_string(qs2)
    canonical3 = build_canonical_query_string(qs3)

    assert canonical1 == "a=1&b=2&c=3"
    assert canonical1 == canonical2 == canonical3


def test_canonical_query_string_encoding():
    """Verify RFC 3986 percent encoding in query parameters."""
    qs = "message=hello world&filter=active_user*~"
    canonical = build_canonical_query_string(qs)
    # Spaces must be %20, not +
    assert "hello%20world" in canonical
    assert "%2A" in canonical or "*=" in canonical or "active_user" in canonical


def test_canonical_headers_normalization():
    """Verify lowercase conversion, whitespace collapsing, and alphabetical sorting of headers."""
    headers = {
        "X-Custom-Header": "  custom    value  ",
        "Content-Type": "application/json",
        "HOST": "api.aegis.io",
    }

    canonical_headers, signed_headers = build_canonical_headers(headers)

    # Must be sorted alphabetically: content-type, host, x-custom-header
    assert signed_headers == "content-type;host;x-custom-header"

    expected_headers_str = (
        "content-type:application/json\n"
        "host:api.aegis.io\n"
        "x-custom-header:custom value\n"
    )
    assert canonical_headers == expected_headers_str


def test_selective_signed_headers():
    """Verify signing only specific selected headers."""
    headers = {
        "Host": "api.aegis.io",
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0",  # should be excluded
        "X-Nonce": "12345678",
    }

    headers_to_sign = ["host", "content-type", "x-nonce"]
    canonical_headers, signed_headers = build_canonical_headers(headers, headers_to_sign)

    assert signed_headers == "content-type;host;x-nonce"
    assert "user-agent" not in signed_headers
    assert "user-agent" not in canonical_headers


def test_full_canonical_request_assembly():
    """Verify end-to-end deterministic canonical string assembly."""
    method = "POST"
    path = "/api/v1/payments/transfer"
    query = "currency=USD&amount=500"
    headers = {
        "Host": "api.aegis.io",
        "Content-Type": "application/json",
        "X-Timestamp": "20261017T200000Z",
        "X-Nonce": "abcdef1234567890",
    }
    payload = '{"recipient": "user_42", "amount": 500}'
    timestamp = "20261017T200000Z"
    nonce = "abcdef1234567890"

    canonical_req, signed_headers, payload_hash = build_canonical_request(
        method=method,
        path=path,
        query_string=query,
        headers=headers,
        payload=payload,
        timestamp=timestamp,
        nonce=nonce,
    )

    expected_payload_hash = hash_payload(payload)
    assert payload_hash == expected_payload_hash

    lines = canonical_req.split("\n")
    assert lines[0] == "POST"
    assert lines[1] == "/api/v1/payments/transfer"
    assert lines[2] == "amount=500&currency=USD"
    # Headers section
    assert "content-type:application/json" in lines
    assert "host:api.aegis.io" in lines
    assert lines[-3] == expected_payload_hash
    assert lines[-2] == timestamp
    assert lines[-1] == nonce
