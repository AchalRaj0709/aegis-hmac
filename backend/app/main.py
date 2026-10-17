"""
AegisHMAC FastAPI Application Entrypoint.
Initializes lifespan events, CORS, database connection, middleware pipeline, and administrative routes.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.config import settings
from app.core.crypto import generate_key_hex
from app.database.connection import DatabaseManager, get_db
from app.database.models import (
    ClientCreateRequest,
    ClientCreateResponse,
    KeyRotateResponse,
    ClientSummaryResponse,
    ClientStatus,
    AuditLogDocument,
)
from app.database.repositories.client_repo import ClientRepository
from app.database.repositories.key_repo import KeyRepository
from app.database.repositories.audit_repo import AuditRepository
from app.middleware.hmac_auth import HMACAuthenticationMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan context manager for startup and shutdown events."""
    # Startup: Connect to MongoDB and create security indexes (including TTL index)
    await DatabaseManager.connect()
    yield
    # Shutdown: Close database connection pools
    await DatabaseManager.disconnect()


app = FastAPI(
    title="AegisHMAC API Security Gateway",
    description="Production-grade HMAC-SHA256 authentication system with replay defense and timing attack immunity.",
    version="1.0.0",
    lifespan=lifespan,
)

# 1. CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 2. Attach HMAC Authentication Middleware
app.add_middleware(HMACAuthenticationMiddleware)


# -----------------------------------------------------------------------------
# Public & Administrative Endpoints
# -----------------------------------------------------------------------------

@app.get("/health", tags=["System"])
async def health_check():
    """Service health check endpoint (Public)."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "environment": settings.ENVIRONMENT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post(
    "/api/v1/admin/clients",
    response_model=ClientCreateResponse,
    status_code=201,
    tags=["Key Management"],
)
async def register_client(
    payload: ClientCreateRequest,
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """
    Provision a new client identity and generate a 256-bit symmetric secret key.
    The secret key is encrypted at rest using AES-256-GCM envelope encryption.
    NOTE: The raw secret key is displayed in this response ONCE and cannot be recovered.
    """
    # 1. Create client identity
    client = await ClientRepository.create_client(db, payload.client_name)

    # 2. Generate 256-bit CSPRNG secret key
    raw_secret_key = generate_key_hex(32)
    algo = payload.algorithm or settings.DEFAULT_ALGORITHM

    # 3. Encrypt and persist key in vault
    key_doc = await KeyRepository.provision_key(
        db=db,
        client_id=client.client_id,
        raw_secret=raw_secret_key,
        algorithm=algo,
        version=1,
    )

    return ClientCreateResponse(
        client_id=client.client_id,
        client_name=client.client_name,
        secret_key=raw_secret_key,
        key_version=key_doc.key_version,
        algorithm=key_doc.algorithm,
        created_at=client.created_at,
    )


@app.get(
    "/api/v1/admin/clients",
    response_model=List[ClientSummaryResponse],
    tags=["Key Management"],
)
async def list_registered_clients(db: AsyncIOMotorDatabase = Depends(get_db)):
    """List all registered client identities and their operational statuses."""
    clients = await ClientRepository.list_clients(db)
    results: List[ClientSummaryResponse] = []

    for c in clients:
        valid_keys = await KeyRepository.get_valid_keys(db, c.client_id)
        active_version = valid_keys[0][0].key_version if valid_keys else 0
        results.append(
            ClientSummaryResponse(
                client_id=c.client_id,
                client_name=c.client_name,
                status=c.status,
                active_key_version=active_version,
                created_at=c.created_at,
            )
        )
    return results


@app.post(
    "/api/v1/admin/clients/{client_id}/rotate",
    response_model=KeyRotateResponse,
    tags=["Key Management"],
)
async def rotate_client_key(
    client_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """
    Rotate a client's secret key with zero downtime.
    The old key remains valid in a 'ROTATING' state for a 24-hour grace window.
    """
    client = await ClientRepository.get_client(db, client_id)
    if not client or client.status != ClientStatus.ACTIVE:
        raise HTTPException(status_code=404, detail="Active client not found")

    new_raw_secret = generate_key_hex(32)
    new_key, old_key = await KeyRepository.rotate_key(
        db=db,
        client_id=client_id,
        new_raw_secret=new_raw_secret,
        grace_hours=settings.KEY_ROTATION_GRACE_HOURS,
    )

    expires_at = old_key.expires_at if old_key and old_key.expires_at else datetime.now(timezone.utc)

    return KeyRotateResponse(
        client_id=client_id,
        new_secret_key=new_raw_secret,
        new_key_version=new_key.key_version,
        grace_period_expires_at=expires_at,
        message="Key rotated successfully. Old key will remain valid during grace period.",
    )


@app.post(
    "/api/v1/admin/clients/{client_id}/revoke",
    tags=["Key Management"],
)
async def revoke_client_credentials(
    client_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Permanently revoke all keys for a client, blocking subsequent requests immediately."""
    client = await ClientRepository.get_client(db, client_id)
    if not client:
        raise HTTPException(status_code=404, detail="Client not found")

    await KeyRepository.revoke_all_keys(db, client_id)
    await ClientRepository.update_status(db, client_id, ClientStatus.REVOKED)

    return {"message": f"All credentials for client {client_id} have been permanently revoked."}


@app.get(
    "/api/v1/admin/audit-logs",
    response_model=List[AuditLogDocument],
    tags=["Telemetry"],
)
async def get_audit_logs(
    limit: int = 50,
    client_id: Optional[str] = None,
    db: AsyncIOMotorDatabase = Depends(get_db),
):
    """Retrieve recent security audit logs and failure forensics."""
    return await AuditRepository.get_recent_logs(db, limit=limit, client_id=client_id)


# -----------------------------------------------------------------------------
# Protected Application Endpoints (Require HMAC Verification)
# -----------------------------------------------------------------------------

@app.get("/api/v1/test/ping", tags=["Protected Endpoints"])
async def protected_ping(request: Request):
    """Protected GET endpoint verifying HMAC authentication."""
    return {
        "message": "pong",
        "authenticated_client_id": request.state.client_id,
        "key_version": request.state.key_version,
        "request_id": request.state.request_id,
    }


@app.post("/api/v1/test/echo", tags=["Protected Endpoints"])
async def protected_echo(request: Request):
    """Protected POST endpoint verifying body integrity and HMAC signature."""
    payload = await request.json()
    return {
        "message": "Request authenticated successfully",
        "authenticated_client_id": request.state.client_id,
        "received_payload": payload,
    }
