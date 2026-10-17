"""
AegisHMAC Protected REST Business Endpoints.
Simulates real-world enterprise operations (payments, secure profiles, and webhook ingress)
requiring tamper-proof HMAC verification.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1", tags=["Protected REST Endpoints"])


# -----------------------------------------------------------------------------
# Request & Response Schemas
# -----------------------------------------------------------------------------

class TransferRequest(BaseModel):
    """Payment transfer payload requiring cryptographic non-tampering guarantees."""
    recipient_id: str = Field(..., min_length=3, description="Target recipient account or client ID")
    amount: float = Field(..., gt=0, description="Transfer amount (must be positive)")
    currency: str = Field(default="USD", min_length=3, max_length=3)
    idempotency_key: str = Field(default_factory=lambda: str(uuid.uuid4()))


class TransferResponse(BaseModel):
    transaction_id: str
    sender_client_id: str
    recipient_id: str
    amount: float
    currency: str
    status: str
    settled_at: datetime


class WebhookEventPayload(BaseModel):
    """Webhook event structure requiring origin authentication."""
    event_type: str = Field(..., json_schema_extra={"example": "invoice.payment_succeeded"})
    data: Dict[str, Any]


class WebhookReceiptResponse(BaseModel):
    event_id: str
    event_type: str
    authenticated_origin: str
    received_at: datetime
    status: str


# -----------------------------------------------------------------------------
# Protected Route Handlers
# -----------------------------------------------------------------------------

@router.post("/payments/transfer", response_model=TransferResponse)
async def execute_payment_transfer(payload: TransferRequest, request: Request):
    """
    Simulated financial transfer endpoint.
    If an attacker alters the recipient_id or amount in transit,
    the HMAC signature breaks and the request is rejected before reaching this handler.
    """
    client_id = getattr(request.state, "client_id", "unknown")
    tx_id = f"tx_{uuid.uuid4().hex[:12]}"

    return TransferResponse(
        transaction_id=tx_id,
        sender_client_id=client_id,
        recipient_id=payload.recipient_id,
        amount=payload.amount,
        currency=payload.currency.upper(),
        status="SETTLED",
        settled_at=datetime.now(timezone.utc),
    )


@router.get("/user/profile")
async def get_secure_profile(request: Request):
    """
    Retrieve caller's profile and credentials state based on verified request signature.
    """
    client_id = getattr(request.state, "client_id", "unknown")
    key_version = getattr(request.state, "key_version", 1)
    req_id = getattr(request.state, "request_id", "unknown")

    return {
        "client_id": client_id,
        "active_key_version": key_version,
        "request_id": req_id,
        "permissions": ["transfers:execute", "reports:read", "webhooks:push"],
        "authenticated_at": datetime.now(timezone.utc).isoformat(),
    }


@router.post("/webhooks/deliver", response_model=WebhookReceiptResponse)
async def ingest_webhook_event(event: WebhookEventPayload, request: Request):
    """
    Ingest critical webhook notifications.
    Origin is strictly authenticated via the shared symmetric HMAC secret.
    """
    client_id = getattr(request.state, "client_id", "unknown")
    event_id = f"evt_{uuid.uuid4().hex[:16]}"

    return WebhookReceiptResponse(
        event_id=event_id,
        event_type=event.event_type,
        authenticated_origin=client_id,
        received_at=datetime.now(timezone.utc),
        status="PROCESSED",
    )
