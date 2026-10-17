"""
AegisHMAC Canonical Request Engine.
Normalizes HTTP requests into a deterministic, reproducible representation per AWS SigV4 specification.
Guarantees that both client and server construct the identical byte sequence for cryptographic signing.
"""

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union
from app.core.crypto import hash_payload


def normalize_uri_path(path: str) -> str:
    """
    Normalize the URI path:
    1. If empty, default to '/'.
    2. Collapse duplicate slashes (e.g. '//api///v1' -> '/api/v1').
    3. Ensure leading slash.
    4. Remove query strings or fragments if accidentally passed in path.
    """
    if not path:
        return "/"

    # Strip query/fragment if present
    path = path.split("?")[0].split("#")[0]

    # Normalize slashes
    path = re.sub(r"/+", "/", path)

    if not path.startswith("/"):
        path = "/" + path

    return path


def build_canonical_query_string(query_string: Union[str, Dict[str, Union[str, List[str]]]]) -> str:
    """
    Build canonical query string:
    1. Parse query string or dictionary into (key, value) pairs.
    2. Sort pairs alphabetically by key, then by value.
    3. URL-encode keys and values per RFC 3986 (spaces become '%20', not '+').
    4. Join with '&'.
    """
    if not query_string:
        return ""

    pairs: List[Tuple[str, str]] = []

    if isinstance(query_string, str):
        # Strip leading '?' if present
        cleaned_qs = query_string.lstrip("?")
        if not cleaned_qs:
            return ""
        parsed = urllib.parse.parse_qsl(cleaned_qs, keep_blank_values=True)
        pairs = [(k, v) for k, v in parsed]
    elif isinstance(query_string, dict):
        for k, v in query_string.items():
            if isinstance(v, list):
                for sub_v in v:
                    pairs.append((str(k), str(sub_v)))
            else:
                pairs.append((str(k), str(v)))

    # Sort alphabetically by key, then by value
    sorted_pairs = sorted(pairs, key=lambda x: (x[0], x[1]))

    # RFC 3986 percent-encoding (quote with safe='-_.~')
    encoded_pairs = [
        f"{urllib.parse.quote(k, safe='-_.~')}={urllib.parse.quote(v, safe='-_.~')}"
        for k, v in sorted_pairs
    ]

    return "&".join(encoded_pairs)


def build_canonical_headers(
    headers: Dict[str, str],
    headers_to_sign: Optional[List[str]] = None,
) -> Tuple[str, str]:
    """
    Build canonical headers and signed headers list:
    1. Lowercase header names.
    2. Filter to 'headers_to_sign' if specified (otherwise standard headers).
    3. Strip leading/trailing whitespace and collapse internal consecutive spaces.
    4. Sort alphabetically by lowercase name.
    5. Format canonical headers as: "name:value\n" for each header.
    6. Return (canonical_headers_str, signed_headers_semicolon_list).
    """
    # Lowercase and clean all headers
    cleaned_headers: Dict[str, str] = {}
    for k, v in headers.items():
        k_lower = k.strip().lower()
        # Collapse multiple spaces in value to single space
        v_clean = " ".join(str(v).strip().split())
        cleaned_headers[k_lower] = v_clean

    # Determine headers to sign
    if headers_to_sign:
        target_keys = [h.strip().lower() for h in headers_to_sign]
    else:
        # Default security headers to sign if not explicitly specified
        target_keys = sorted(cleaned_headers.keys())

    # Filter and sort
    sorted_signed_keys = sorted(set(k for k in target_keys if k in cleaned_headers))

    canonical_headers_list = [
        f"{k}:{cleaned_headers[k]}\n" for k in sorted_signed_keys
    ]
    canonical_headers_str = "".join(canonical_headers_list)
    signed_headers_str = ";".join(sorted_signed_keys)

    return canonical_headers_str, signed_headers_str


def build_canonical_request(
    method: str,
    path: str,
    query_string: Union[str, Dict[str, Any]] = "",
    headers: Optional[Dict[str, str]] = None,
    headers_to_sign: Optional[List[str]] = None,
    payload: Union[str, bytes, None] = None,
    timestamp: str = "",
    nonce: str = "",
) -> Tuple[str, str, str]:
    """
    Construct the full Canonical Request String:
    Format:
        <HTTP_METHOD>\n
        <CANONICAL_URI>\n
        <CANONICAL_QUERY_STRING>\n
        <CANONICAL_HEADERS>\n
        <SIGNED_HEADERS>\n
        <HASHED_PAYLOAD>\n
        <TIMESTAMP>\n
        <NONCE>

    :return: Tuple of (canonical_request_string, signed_headers_list, payload_hash)
    """
    canonical_method = method.strip().upper()
    canonical_uri = normalize_uri_path(path)
    canonical_qs = build_canonical_query_string(query_string)

    headers = headers or {}
    canonical_headers, signed_headers = build_canonical_headers(headers, headers_to_sign)

    payload_hash = hash_payload(payload)

    parts = [
        canonical_method,
        canonical_uri,
        canonical_qs,
        canonical_headers.rstrip("\n"),  # remove trailing newline before joining
        signed_headers,
        payload_hash,
        timestamp.strip(),
        nonce.strip(),
    ]

    canonical_request_string = "\n".join(parts)
    return canonical_request_string, signed_headers, payload_hash
