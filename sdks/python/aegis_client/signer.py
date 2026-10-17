"""
AegisHMAC Client-Side Request Signer.
Constructs canonical requests and computes cryptographic signatures for outbound API calls.
"""

import hashlib
import hmac
import re
import secrets
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Union


class HMACSigner:
    """Computes AWS SigV4-compliant HMAC signatures for outbound HTTP requests."""

    def __init__(
        self,
        client_id: str,
        secret_key: str,
        algorithm: str = "HMAC-SHA256",
    ) -> None:
        self.client_id = client_id.strip()
        self.secret_key = secret_key.strip()
        self.algorithm = algorithm.upper()

        if self.algorithm not in ("HMAC-SHA256", "HMAC-SHA512"):
            raise ValueError(f"Unsupported algorithm: {algorithm}. Must be HMAC-SHA256 or HMAC-SHA512")

    def _get_key_bytes(self) -> bytes:
        """Decode hex key or encode as UTF-8."""
        key = self.secret_key
        try:
            if len(key) in (64, 128) and all(c in "0123456789abcdefABCDEF" for c in key):
                return bytes.fromhex(key)
        except ValueError:
            pass
        return key.encode("utf-8")

    @staticmethod
    def hash_payload(payload: Union[str, bytes, None]) -> str:
        """Compute SHA-256 of the payload."""
        if payload is None:
            raw = b""
        elif isinstance(payload, str):
            raw = payload.encode("utf-8")
        elif isinstance(payload, (bytes, bytearray)):
            raw = bytes(payload)
        else:
            raise TypeError(f"Payload must be str or bytes, got: {type(payload)}")
        return hashlib.sha256(raw).hexdigest()

    def sign(
        self,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        query_string: Union[str, Dict[str, str]] = "",
        payload: Union[str, bytes, None] = None,
        timestamp_override: Optional[str] = None,
        nonce_override: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Produce a new headers dictionary with Authorization, X-Timestamp, and X-Nonce injected.
        """
        out_headers = {str(k).lower(): str(v).strip() for k, v in (headers or {}).items()}

        # 1. Temporal & Nonce parameters
        now = datetime.now(timezone.utc)
        timestamp = timestamp_override or now.strftime("%Y%m%dT%H%M%SZ")
        nonce = nonce_override or secrets.token_hex(16)

        out_headers["x-timestamp"] = timestamp
        out_headers["x-nonce"] = nonce

        # Ensure default Content-Type if payload provided and not set
        if payload and "content-type" not in out_headers:
            out_headers["content-type"] = "application/json"

        # 2. Canonical URI
        canonical_uri = re.sub(r"/+", "/", path.split("?")[0].split("#")[0])
        if not canonical_uri.startswith("/"):
            canonical_uri = "/" + canonical_uri

        # 3. Canonical Query String
        if isinstance(query_string, str):
            cleaned_qs = query_string.lstrip("?")
            parsed = urllib.parse.parse_qsl(cleaned_qs, keep_blank_values=True)
        elif isinstance(query_string, dict):
            parsed = list(query_string.items())
        else:
            parsed = []

        sorted_qs = sorted(parsed, key=lambda x: (x[0], x[1]))
        canonical_qs = "&".join(
            f"{urllib.parse.quote(str(k), safe='-_.~')}={urllib.parse.quote(str(v), safe='-_.~')}"
            for k, v in sorted_qs
        )

        # 4. Canonical Headers
        sorted_keys = sorted(out_headers.keys())
        canonical_headers_list = [f"{k}:{' '.join(out_headers[k].split())}\n" for k in sorted_keys]
        canonical_headers = "".join(canonical_headers_list).rstrip("\n")
        signed_headers = ";".join(sorted_keys)

        # 5. Payload Hash
        payload_hash = self.hash_payload(payload)

        # 6. Canonical Request Assembly
        canonical_parts = [
            method.strip().upper(),
            canonical_uri,
            canonical_qs,
            canonical_headers,
            signed_headers,
            payload_hash,
            timestamp,
            nonce,
        ]
        canonical_request_string = "\n".join(canonical_parts)

        # 7. Compute HMAC Signature
        hash_func = hashlib.sha256 if self.algorithm == "HMAC-SHA256" else hashlib.sha512
        sig = hmac.new(
            self._get_key_bytes(),
            canonical_request_string.encode("utf-8"),
            hash_func,
        ).hexdigest().lower()

        # 8. Set Authorization Header
        out_headers["authorization"] = (
            f"{self.algorithm} Credential={self.client_id}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={sig}"
        )

        return out_headers
