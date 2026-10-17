"""
AegisHMAC Security Exception Hierarchy.
Provides standardized, structured error classes for all authentication and cryptographic failures.
"""

from typing import Optional, Dict, Any


class AegisSecurityError(Exception):
    """Base exception for all AegisHMAC security and authentication failures."""

    def __init__(
        self,
        message: str,
        status_code: int = 401,
        error_code: str = "SECURITY_ERROR",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to a safe JSON-serializable dictionary."""
        response: Dict[str, Any] = {
            "error": self.error_code,
            "message": self.message,
            "status_code": self.status_code,
        }
        if self.details:
            response["details"] = self.details
        return response


class MissingHeaderError(AegisSecurityError):
    """Raised when one or more required HMAC authentication headers are missing."""

    def __init__(self, missing_header: str) -> None:
        super().__init__(
            message=f"Missing required authentication header: '{missing_header}'",
            status_code=400,
            error_code="MISSING_AUTH_HEADER",
            details={"missing_header": missing_header},
        )


class MalformedAuthorizationError(AegisSecurityError):
    """Raised when the Authorization header does not conform to the expected HMAC schema."""

    def __init__(self, message: str = "Malformed Authorization header format") -> None:
        super().__init__(
            message=message,
            status_code=400,
            error_code="MALFORMED_AUTHORIZATION_HEADER",
        )


class ClockSkewError(AegisSecurityError):
    """Raised when the request timestamp falls outside the acceptable tolerance window."""

    def __init__(self, delta_seconds: float, tolerance_seconds: float) -> None:
        super().__init__(
            message=(
                f"Request timestamp is outside the allowed tolerance window. "
                f"Clock skew: {abs(delta_seconds):.1f}s, Max allowed: {tolerance_seconds:.1f}s"
            ),
            status_code=408,  # Request Timeout / Stale Request
            error_code="CLOCK_SKEW_EXCEEDED",
            details={
                "skew_seconds": round(delta_seconds, 2),
                "tolerance_seconds": tolerance_seconds,
            },
        )


class ReplayAttackError(AegisSecurityError):
    """Raised when a nonce has already been utilized within the active validity window."""

    def __init__(self, nonce: str) -> None:
        super().__init__(
            message="Replay attack detected: This request nonce has already been processed.",
            status_code=401,
            error_code="REPLAY_ATTACK_DETECTED",
            details={"nonce": nonce},
        )


class ClientNotFoundError(AegisSecurityError):
    """Raised when the claimed Client ID does not exist or has been disabled."""

    def __init__(self, client_id: str) -> None:
        super().__init__(
            message="Invalid credentials: Client ID not recognized or deactivated.",
            status_code=401,
            error_code="CLIENT_NOT_FOUND",
            details={"client_id": client_id},
        )


class KeyRevokedError(AegisSecurityError):
    """Raised when the key associated with the client has been revoked."""

    def __init__(self, client_id: str) -> None:
        super().__init__(
            message="Credentials revoked: The secret key for this client has been permanently revoked.",
            status_code=401,
            error_code="KEY_REVOKED",
            details={"client_id": client_id},
        )


class SignatureMismatchError(AegisSecurityError):
    """Raised when the calculated HMAC does not match the provided signature."""

    def __init__(self) -> None:
        super().__init__(
            message="Signature mismatch: Request data was tampered with or secret key is invalid.",
            status_code=401,
            error_code="SIGNATURE_MISMATCH",
        )


class UnsupportedAlgorithmError(AegisSecurityError):
    """Raised when an unsupported cryptographic algorithm is requested."""

    def __init__(self, algorithm: str) -> None:
        super().__init__(
            message=f"Unsupported cryptographic algorithm: '{algorithm}'. Supported: HMAC-SHA256, HMAC-SHA512.",
            status_code=400,
            error_code="UNSUPPORTED_ALGORITHM",
            details={"algorithm": algorithm},
        )
