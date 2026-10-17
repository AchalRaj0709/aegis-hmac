"""
AegisHMAC Data Models & Schemas.
Defines database document models, status enumerations, and API schemas.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field


def utc_now() -> datetime:
    """Return timezone-aware current UTC datetime."""
    return datetime.now(timezone.utc)


class ClientStatus(str, Enum):
    """Operational status of a client identity."""
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    REVOKED = "REVOKED"


class KeyStatus(str, Enum):
    """Lifecycle status of a symmetric HMAC key."""
    ACTIVE = "ACTIVE"         # Primary key in use
    ROTATING = "ROTATING"     # Secondary key during grace-period migration
    REVOKED = "REVOKED"       # Inactive / compromised key


class AuditVerdict(str, Enum):
    """Authentication outcome for audit logging."""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


# -----------------------------------------------------------------------------
# Database Document Models
# -----------------------------------------------------------------------------

class ClientDocument(BaseModel):
    """MongoDB model for registered API consumers/services."""
    client_id: str = Field(..., description="Unique client identifier (e.g. client_abc123)")
    client_name: str = Field(..., description="Human-readable application or service name")
    status: ClientStatus = Field(default=ClientStatus.ACTIVE)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class ApiKeyDocument(BaseModel):
    """MongoDB model for client symmetric keys (stored AES-GCM encrypted)."""
    key_id: str = Field(..., description="Unique identifier for this key record")
    client_id: str = Field(..., description="Associated client ID")
    encrypted_secret: str = Field(..., description="Base64 AES-256-GCM encrypted secret key")
    key_version: int = Field(default=1, description="Version counter (v1, v2, etc.)")
    status: KeyStatus = Field(default=KeyStatus.ACTIVE)
    algorithm: str = Field(default="HMAC-SHA256")
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: Optional[datetime] = Field(
        default=None,
        description="Expiration time for rotating keys during grace periods"
    )


class NonceDocument(BaseModel):
    """MongoDB model for replay prevention nonces. Expired by TTL index."""
    nonce: str = Field(..., description="Unique one-time cryptographic nonce")
    client_id: str = Field(..., description="Associated client ID")
    created_at: datetime = Field(default_factory=utc_now)


class AuditLogDocument(BaseModel):
    """MongoDB model for security telemetry and audit trails."""
    request_id: str
    client_id: Optional[str] = None
    timestamp: datetime = Field(default_factory=utc_now)
    method: str
    path: str
    ip_address: Optional[str] = None
    status_code: int
    verdict: AuditVerdict
    failure_reason: Optional[str] = None
    latency_ms: float = 0.0
    details: Optional[Dict[str, Any]] = None


# -----------------------------------------------------------------------------
# API Request & Response Schemas
# -----------------------------------------------------------------------------

class ClientCreateRequest(BaseModel):
    """Payload for provisioning a new client."""
    client_name: str = Field(..., min_length=2, max_length=100)
    algorithm: Optional[str] = Field(default="HMAC-SHA256")


class ClientCreateResponse(BaseModel):
    """Returned once upon client creation. Contains the raw secret key."""
    client_id: str
    client_name: str
    secret_key: str = Field(..., description="Raw 256-bit secret key (reveal ONCE to the user)")
    key_version: int
    algorithm: str
    created_at: datetime


class KeyRotateResponse(BaseModel):
    """Returned when a client rotates their secret key."""
    client_id: str
    new_secret_key: str
    new_key_version: int
    grace_period_expires_at: datetime
    message: str


class ClientSummaryResponse(BaseModel):
    """Safe client representation excluding secrets."""
    client_id: str
    client_name: str
    status: ClientStatus
    active_key_version: int
    created_at: datetime
