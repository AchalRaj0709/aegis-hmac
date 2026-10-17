"""
AegisHMAC Authentication Middleware Pipeline.
Intercepts incoming HTTP requests, enforces temporal validity (clock skew),
blocks replay attacks, reconstructs canonical requests, and verifies HMAC signatures using constant-time comparison.
"""

import asyncio
import re
import time
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Set
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.config import settings
from app.core.canonical import build_canonical_request
from app.core.crypto import compute_hmac, constant_time_compare
from app.core.errors import (
    AegisSecurityError,
    MissingHeaderError,
    MalformedAuthorizationError,
    ClockSkewError,
    ClientNotFoundError,
    SignatureMismatchError,
    UnsupportedAlgorithmError,
)
from app.database.connection import DatabaseManager
from app.database.models import AuditLogDocument, AuditVerdict
from app.database.repositories.audit_repo import AuditRepository
from app.database.repositories.client_repo import ClientRepository
from app.database.repositories.key_repo import KeyRepository
from app.database.repositories.nonce_repo import NonceRepository


# Regex for Authorization header:
# Format: HMAC-SHA256 Credential=<client_id>, SignedHeaders=<headers>, Signature=<signature>
AUTH_HEADER_PATTERN = re.compile(
    r"^(?P<algorithm>HMAC-SHA256|HMAC-SHA512)\s+"
    r"Credential=(?P<client_id>[^,\s]+),\s*"
    r"SignedHeaders=(?P<signed_headers>[^,\s]+),\s*"
    r"Signature=(?P<signature>[a-fA-F0-9]+)$"
)


def parse_timestamp(timestamp_str: str) -> datetime:
    """
    Parse timestamp in either compact AWS format (YYYYMMDDTHHMMSSZ)
    or standard ISO 8601 format.
    """
    timestamp_str = timestamp_str.strip()
    # Try compact format: 20261017T200000Z
    try:
        dt = datetime.strptime(timestamp_str, "%Y%m%dT%H%M%SZ")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    # Try ISO format
    try:
        clean_str = timestamp_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        raise MalformedAuthorizationError(f"Invalid timestamp format: '{timestamp_str}'. Use ISO 8601 or YYYYMMDDTHHMMSSZ.")


class HMACAuthenticationMiddleware(BaseHTTPMiddleware):
    """
    Core security middleware verifying HMAC-SHA256/512 signatures on all protected routes.
    """

    def __init__(self, app, exempt_paths: Optional[Set[str]] = None):
        super().__init__(app)
        # Default public endpoints exempt from HMAC verification
        self.exempt_paths: Set[str] = exempt_paths or {
            "/health",
            "/docs",
            "/redoc",
            "/openapi.json",
            "/favicon.ico",
            "/api/v1/admin/clients",  # Allow initial registration
            "/api/v1/admin/clients/register",
        }

    def _is_path_exempt(self, path: str) -> bool:
        """Check if request path is exempt from authentication."""
        if path in self.exempt_paths:
            return True
        for exempt in self.exempt_paths:
            if exempt.endswith("/*") and path.startswith(exempt[:-2]):
                return True
        return False

    async def dispatch(self, request: Request, call_next) -> Response:
        """Execute the HMAC verification pipeline."""
        path = request.url.path
        if self._is_path_exempt(path):
            return await call_next(request)

        start_time = time.perf_counter()
        request_id = f"req_{int(time.time() * 1000)}"
        client_id: Optional[str] = None
        method = request.method
        ip_address = request.client.host if request.client else "unknown"

        try:
            # 1. Extract required authentication headers
            auth_header = request.headers.get("authorization")
            if not auth_header:
                raise MissingHeaderError("Authorization")

            timestamp_header = request.headers.get("x-timestamp")
            if not timestamp_header:
                raise MissingHeaderError("X-Timestamp")

            nonce_header = request.headers.get("x-nonce")
            if not nonce_header:
                raise MissingHeaderError("X-Nonce")

            # 2. Parse Authorization header components
            match = AUTH_HEADER_PATTERN.match(auth_header.strip())
            if not match:
                raise MalformedAuthorizationError(
                    "Authorization header must follow format: "
                    "HMAC-SHA256 Credential=<client_id>, SignedHeaders=<h1;h2>, Signature=<hex_signature>"
                )

            algorithm = match.group("algorithm")
            client_id = match.group("client_id")
            signed_headers_str = match.group("signed_headers")
            provided_signature = match.group("signature").lower()

            if algorithm not in settings.ALLOWED_ALGORITHMS:
                raise UnsupportedAlgorithmError(algorithm)

            signed_headers_list = [h.strip().lower() for h in signed_headers_str.split(";")]

            # 3. Clock Skew Verification (|T_client - T_server| <= tolerance)
            request_dt = parse_timestamp(timestamp_header)
            now_dt = datetime.now(timezone.utc)
            skew_seconds = (now_dt - request_dt).total_seconds()

            if abs(skew_seconds) > settings.CLOCK_SKEW_TOLERANCE_SECONDS:
                raise ClockSkewError(
                    delta_seconds=skew_seconds,
                    tolerance_seconds=settings.CLOCK_SKEW_TOLERANCE_SECONDS,
                )

            # 4. Access Database
            db = DatabaseManager.get_database()

            # 5. Verify Client Status & Retrieve Valid Symmetric Keys
            client_record = await ClientRepository.get_client(db, client_id)
            if not client_record or client_record.status != "ACTIVE":
                raise ClientNotFoundError(client_id)

            valid_keys = await KeyRepository.get_valid_keys(db, client_id)
            if not valid_keys:
                raise ClientNotFoundError(client_id)

            # 6. Replay Attack Defense (Atomic Nonce Verification)
            await NonceRepository.record_and_verify_nonce(db, client_id, nonce_header)

            # 7. Read & Preserve Raw Request Body
            raw_body = await request.body()

            # 8. Reconstruct Server Canonical Request String
            # Extract headers dictionary from incoming request
            incoming_headers = {k: v for k, v in request.headers.items()}

            canonical_string, _, _ = build_canonical_request(
                method=method,
                path=path,
                query_string=str(request.url.query),
                headers=incoming_headers,
                headers_to_sign=signed_headers_list,
                payload=raw_body,
                timestamp=timestamp_header,
                nonce=nonce_header,
            )

            # 9. Constant-Time Signature Verification across valid keys
            # (supports both current ACTIVE and ROTATING keys during graceful rollover)
            matched_key = None
            for key_doc, plaintext_secret in valid_keys:
                expected_signature = compute_hmac(
                    key=plaintext_secret,
                    message=canonical_string,
                    algorithm=algorithm,
                )

                if constant_time_compare(provided_signature, expected_signature):
                    matched_key = key_doc
                    break

            if not matched_key:
                raise SignatureMismatchError()

            # 10. Inject Authentication State into Request Scope
            request.state.client_id = client_id
            request.state.key_version = matched_key.key_version
            request.state.request_id = request_id

            # 11. Proceed to downstream handler
            response = await call_next(request)

            # Record successful audit log
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            asyncio.create_task(
                AuditRepository.record_log(
                    db,
                    AuditLogDocument(
                        request_id=request_id,
                        client_id=client_id,
                        method=method,
                        path=path,
                        ip_address=ip_address,
                        status_code=response.status_code,
                        verdict=AuditVerdict.SUCCESS,
                        latency_ms=duration_ms,
                    ),
                )
            )

            return response

        except AegisSecurityError as err:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            # Log failure asynchronously (without secrets)
            try:
                db = DatabaseManager.get_database()
                asyncio.create_task(
                    AuditRepository.record_log(
                        db,
                        AuditLogDocument(
                            request_id=request_id,
                            client_id=client_id,
                            method=method,
                            path=path,
                            ip_address=ip_address,
                            status_code=err.status_code,
                            verdict=AuditVerdict.FAILED,
                            failure_reason=err.message,
                            latency_ms=duration_ms,
                            details=err.details,
                        ),
                    )
                )
            except Exception:
                pass

            return JSONResponse(
                status_code=err.status_code,
                content=err.to_dict(),
            )
        except Exception as exc:
            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return JSONResponse(
                status_code=500,
                content={
                    "error": "INTERNAL_SERVER_ERROR",
                    "message": f"An unexpected security error occurred: {str(exc)}",
                    "status_code": 500,
                },
            )
