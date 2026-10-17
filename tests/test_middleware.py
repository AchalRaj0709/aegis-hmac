"""
Integration Tests for AegisHMAC Authentication Middleware Pipeline.
Verifies end-to-end HTTP request signing, replay defense, clock skew enforcement,
tamper detection, and key rotation handling via httpx AsyncClient.
"""

import sys
import os
import json
import secrets
from datetime import datetime, timedelta, timezone
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.main import app
from app.config import settings
from app.core.canonical import build_canonical_request
from app.core.crypto import compute_hmac
from app.database.connection import DatabaseManager
from app.database.repositories.client_repo import ClientRepository
from app.database.repositories.key_repo import KeyRepository


TEST_DB_NAME = "aegis_middleware_test_db"


def generate_signed_headers(
    method: str,
    path: str,
    client_id: str,
    secret_key: str,
    query_string: str = "",
    payload: str = "",
    timestamp_override: str = None,
    nonce_override: str = None,
    headers_to_sign_list: list = None,
) -> dict:
    """Helper constructing client-side signed headers."""
    now = datetime.now(timezone.utc)
    timestamp = timestamp_override or now.strftime("%Y%m%dT%H%M%SZ")
    nonce = nonce_override or secrets.token_hex(16)

    # Base headers
    headers = {
        "host": "testserver",
        "content-type": "application/json",
        "x-timestamp": timestamp,
        "x-nonce": nonce,
    }

    signed_headers_keys = headers_to_sign_list or ["content-type", "host", "x-nonce", "x-timestamp"]

    canonical_req, signed_headers_str, _ = build_canonical_request(
        method=method,
        path=path,
        query_string=query_string,
        headers=headers,
        headers_to_sign=signed_headers_keys,
        payload=payload,
        timestamp=timestamp,
        nonce=nonce,
    )

    signature = compute_hmac(secret_key, canonical_req, "HMAC-SHA256")
    auth_header = (
        f"HMAC-SHA256 Credential={client_id}, "
        f"SignedHeaders={signed_headers_str}, "
        f"Signature={signature}"
    )

    headers["authorization"] = auth_header
    return headers


@pytest_asyncio.fixture(scope="function")
async def client_fixture():
    """AsyncClient fixture with isolated test database setup and teardown."""
    await DatabaseManager.connect(db_name=TEST_DB_NAME)
    db = DatabaseManager.get_database()

    # Provision test client & key
    client = await ClientRepository.create_client(db, "Middleware Test Service")
    secret_key = secrets.token_hex(32)
    key_doc = await KeyRepository.provision_key(db, client.client_id, secret_key)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac, client.client_id, secret_key, db

    # Teardown
    if DatabaseManager.client:
        await DatabaseManager.client.drop_database(TEST_DB_NAME)
    await DatabaseManager.disconnect()


@pytest.mark.asyncio
async def test_public_health_check(client_fixture):
    """Exempt endpoints must succeed without HMAC headers."""
    client, _, _, _ = client_fixture
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_valid_signed_get_request(client_fixture):
    """Valid HMAC signed GET request succeeds with 200 OK."""
    client, client_id, secret_key, _ = client_fixture
    path = "/api/v1/test/ping"

    headers = generate_signed_headers("GET", path, client_id, secret_key)
    response = await client.get(path, headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["message"] == "pong"
    assert data["authenticated_client_id"] == client_id


@pytest.mark.asyncio
async def test_valid_signed_post_request(client_fixture):
    """Valid HMAC signed POST request verifies body integrity."""
    client, client_id, secret_key, _ = client_fixture
    path = "/api/v1/test/echo"
    body = json.dumps({"transaction_id": "tx_12345", "amount": 250.75})

    headers = generate_signed_headers("POST", path, client_id, secret_key, payload=body)
    response = await client.post(path, content=body, headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["authenticated_client_id"] == client_id
    assert data["received_payload"]["transaction_id"] == "tx_12345"


@pytest.mark.asyncio
async def test_missing_auth_headers(client_fixture):
    """Missing Authorization header returns 400 Bad Request."""
    client, _, _, _ = client_fixture
    response = await client.get("/api/v1/test/ping")

    assert response.status_code == 400
    assert response.json()["error"] == "MISSING_AUTH_HEADER"


@pytest.mark.asyncio
async def test_clock_skew_expired_timestamp(client_fixture):
    """Timestamp older than 5 minutes must be rejected with 408 Request Timeout."""
    client, client_id, secret_key, _ = client_fixture
    path = "/api/v1/test/ping"

    stale_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y%m%dT%H%M%SZ")
    headers = generate_signed_headers("GET", path, client_id, secret_key, timestamp_override=stale_time)

    response = await client.get(path, headers=headers)
    assert response.status_code == 408
    assert response.json()["error"] == "CLOCK_SKEW_EXCEEDED"


@pytest.mark.asyncio
async def test_clock_skew_future_timestamp(client_fixture):
    """Timestamp more than 5 minutes in the future must be rejected with 408."""
    client, client_id, secret_key, _ = client_fixture
    path = "/api/v1/test/ping"

    future_time = (datetime.now(timezone.utc) + timedelta(minutes=10)).strftime("%Y%m%dT%H%M%SZ")
    headers = generate_signed_headers("GET", path, client_id, secret_key, timestamp_override=future_time)

    response = await client.get(path, headers=headers)
    assert response.status_code == 408
    assert response.json()["error"] == "CLOCK_SKEW_EXCEEDED"


@pytest.mark.asyncio
async def test_tampered_payload_detected(client_fixture):
    """Altering 1 byte in the request payload invalidates the signature (401 Unauthorized)."""
    client, client_id, secret_key, _ = client_fixture
    path = "/api/v1/test/echo"

    original_body = json.dumps({"recipient": "alice", "amount": 100})
    tampered_body = json.dumps({"recipient": "alice", "amount": 1000})

    # Sign with original_body, but send tampered_body over the wire
    headers = generate_signed_headers("POST", path, client_id, secret_key, payload=original_body)
    response = await client.post(path, content=tampered_body, headers=headers)

    assert response.status_code == 401
    assert response.json()["error"] == "SIGNATURE_MISMATCH"


@pytest.mark.asyncio
async def test_replay_attack_prevention(client_fixture):
    """Sending the exact same request twice with the same nonce fails on second attempt."""
    client, client_id, secret_key, _ = client_fixture
    path = "/api/v1/test/ping"

    headers = generate_signed_headers("GET", path, client_id, secret_key)

    # 1. First attempt: succeeds
    resp1 = await client.get(path, headers=headers)
    assert resp1.status_code == 200

    # 2. Replay attempt: same headers and nonce -> REJECTED
    resp2 = await client.get(path, headers=headers)
    assert resp2.status_code == 401
    assert resp2.json()["error"] == "REPLAY_ATTACK_DETECTED"


@pytest.mark.asyncio
async def test_key_rotation_dual_validity(client_fixture):
    """During rotation grace period, requests signed with BOTH old and new keys must succeed."""
    client, client_id, old_secret, db = client_fixture
    path = "/api/v1/test/ping"

    new_secret = secrets.token_hex(32)
    await KeyRepository.rotate_key(db, client_id, new_secret, grace_hours=24)

    # Request signed with Old Key: MUST SUCCEED
    headers_old = generate_signed_headers("GET", path, client_id, old_secret)
    resp_old = await client.get(path, headers=headers_old)
    assert resp_old.status_code == 200

    # Request signed with New Key: MUST SUCCEED
    headers_new = generate_signed_headers("GET", path, client_id, new_secret)
    resp_new = await client.get(path, headers=headers_new)
    assert resp_new.status_code == 200


@pytest.mark.asyncio
async def test_revoked_client_blocked(client_fixture):
    """Revoked client keys are rejected immediately."""
    client, client_id, secret_key, db = client_fixture
    path = "/api/v1/test/ping"

    # Revoke credentials
    await KeyRepository.revoke_all_keys(db, client_id)

    headers = generate_signed_headers("GET", path, client_id, secret_key)
    response = await client.get(path, headers=headers)

    assert response.status_code == 401
    assert response.json()["error"] == "CLIENT_NOT_FOUND"
