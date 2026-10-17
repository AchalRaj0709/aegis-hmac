"""
Integration Tests for AegisHMAC Python Client SDK.
Verifies that AegisClient and AegisHttpxAuth correctly sign requests and authenticate
against the live FastAPI server endpoints.
"""

import sys
import os
import secrets
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sdks", "python")))

from app.main import app
from app.database.connection import DatabaseManager
from app.database.repositories.client_repo import ClientRepository
from app.database.repositories.key_repo import KeyRepository

from aegis_client.signer import HMACSigner
from aegis_client.auth import AegisHttpxAuth

TEST_DB_NAME = "aegis_sdk_test_db"


@pytest_asyncio.fixture(scope="function")
async def sdk_fixture():
    """Setup test client and key in MongoDB, yield credentials and httpx AsyncClient."""
    await DatabaseManager.connect(db_name=TEST_DB_NAME)
    db = DatabaseManager.get_database()

    client = await ClientRepository.create_client(db, "SDK Test Client")
    secret_key = secrets.token_hex(32)
    await KeyRepository.provision_key(db, client.client_id, secret_key)

    yield client.client_id, secret_key, db

    if DatabaseManager.client:
        await DatabaseManager.client.drop_database(TEST_DB_NAME)
    await DatabaseManager.disconnect()


def test_signer_deterministic():
    """Verify HMACSigner produces valid canonical headers and signature."""
    signer = HMACSigner(client_id="client_123", secret_key="deadbeef" * 8)
    headers = signer.sign(
        method="GET",
        path="/api/v1/user/profile",
        headers={"host": "api.aegis.io"},
        timestamp_override="20261017T200000Z",
        nonce_override="nonce12345",
    )

    assert "authorization" in headers
    assert "x-timestamp" in headers
    assert "x-nonce" in headers
    assert headers["x-timestamp"] == "20261017T200000Z"
    assert headers["x-nonce"] == "nonce12345"
    assert headers["authorization"].startswith("HMAC-SHA256 Credential=client_123, ")


@pytest.mark.asyncio
async def test_sdk_auth_with_fastapi_server(sdk_fixture):
    """Test AegisHttpxAuth authenticating requests to FastAPI endpoints."""
    client_id, secret_key, _ = sdk_fixture

    auth = AegisHttpxAuth(client_id=client_id, secret_key=secret_key)
    transport = ASGITransport(app=app)

    async with AsyncClient(auth=auth, transport=transport, base_url="http://testserver") as client:
        # 1. GET Request
        res_get = await client.get("/api/v1/user/profile")
        assert res_get.status_code == 200
        assert res_get.json()["client_id"] == client_id

        # 2. POST Request with JSON body
        transfer_payload = {"recipient_id": "vendor_7", "amount": 99.50, "currency": "USD"}
        res_post = await client.post("/api/v1/payments/transfer", json=transfer_payload)
        assert res_post.status_code == 200
        data = res_post.json()
        assert data["sender_client_id"] == client_id
        assert data["amount"] == 99.50
        assert data["status"] == "SETTLED"

        # 3. GraphQL Query
        gql_body = {"query": "{ getAccount(accountId: \"acc_sdk\") { balance currency } }"}
        res_gql = await client.post("/graphql", json=gql_body)
        assert res_gql.status_code == 200
        assert res_gql.json()["data"]["getAccount"]["balance"] == 15420.50
