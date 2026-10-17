"""
Integration Tests for Protected Business Endpoints (REST & GraphQL).
Verifies requirement FR7: Authenticating REST payloads and Strawberry GraphQL queries/mutations
with HMAC-SHA256 signature and body integrity verification.
"""

import sys
import os
import json
import secrets
from datetime import datetime, timezone
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.main import app
from app.core.canonical import build_canonical_request
from app.core.crypto import compute_hmac
from app.database.connection import DatabaseManager
from app.database.repositories.client_repo import ClientRepository
from app.database.repositories.key_repo import KeyRepository


TEST_DB_NAME = "aegis_business_test_db"


def generate_signed_headers(
    method: str,
    path: str,
    client_id: str,
    secret_key: str,
    query_string: str = "",
    payload: str = "",
) -> dict:
    """Helper constructing client-side signed headers."""
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    nonce = secrets.token_hex(16)

    headers = {
        "host": "testserver",
        "content-type": "application/json",
        "x-timestamp": timestamp,
        "x-nonce": nonce,
    }

    signed_headers_keys = ["content-type", "host", "x-nonce", "x-timestamp"]

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

    client = await ClientRepository.create_client(db, "Fintech Payment Consumer")
    secret_key = secrets.token_hex(32)
    await KeyRepository.provision_key(db, client.client_id, secret_key)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac, client.client_id, secret_key, db

    if DatabaseManager.client:
        await DatabaseManager.client.drop_database(TEST_DB_NAME)
    await DatabaseManager.disconnect()


# -----------------------------------------------------------------------------
# REST Endpoint Tests
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_rest_payment_transfer(client_fixture):
    """Test authenticated financial transfer via signed REST POST."""
    client, client_id, secret_key, _ = client_fixture
    path = "/api/v1/payments/transfer"

    transfer_data = {
        "recipient_id": "client_vendor_99",
        "amount": 750.50,
        "currency": "USD",
        "idempotency_key": "tx_idem_12345",
    }
    body = json.dumps(transfer_data)

    headers = generate_signed_headers("POST", path, client_id, secret_key, payload=body)
    response = await client.post(path, content=body, headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["sender_client_id"] == client_id
    assert data["recipient_id"] == "client_vendor_99"
    assert data["amount"] == 750.50
    assert data["status"] == "SETTLED"


@pytest.mark.asyncio
async def test_rest_transfer_tamper_defense(client_fixture):
    """Tampering with payment amount ($750 -> $7500) fails signature check."""
    client, client_id, secret_key, _ = client_fixture
    path = "/api/v1/payments/transfer"

    legit_body = json.dumps({"recipient_id": "vendor", "amount": 750.0, "currency": "USD"})
    tampered_body = json.dumps({"recipient_id": "vendor", "amount": 7500.0, "currency": "USD"})

    headers = generate_signed_headers("POST", path, client_id, secret_key, payload=legit_body)
    response = await client.post(path, content=tampered_body, headers=headers)

    assert response.status_code == 401
    assert response.json()["error"] == "SIGNATURE_MISMATCH"


@pytest.mark.asyncio
async def test_rest_secure_profile(client_fixture):
    """Test retrieving user profile via authenticated REST GET."""
    client, client_id, secret_key, _ = client_fixture
    path = "/api/v1/user/profile"

    headers = generate_signed_headers("GET", path, client_id, secret_key)
    response = await client.get(path, headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["client_id"] == client_id
    assert "transfers:execute" in data["permissions"]


@pytest.mark.asyncio
async def test_rest_webhook_delivery(client_fixture):
    """Test authenticated webhook push via signed REST POST."""
    client, client_id, secret_key, _ = client_fixture
    path = "/api/v1/webhooks/deliver"

    webhook_data = {
        "event_type": "invoice.paid",
        "data": {"invoice_id": "inv_001", "total": 1200.00},
    }
    body = json.dumps(webhook_data)

    headers = generate_signed_headers("POST", path, client_id, secret_key, payload=body)
    response = await client.post(path, content=body, headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["authenticated_origin"] == client_id
    assert data["event_type"] == "invoice.paid"
    assert data["status"] == "PROCESSED"


# -----------------------------------------------------------------------------
# GraphQL Endpoint Tests (Requirement FR7)
# -----------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_graphql_query_get_account(client_fixture):
    """Test authenticated GraphQL Query with HMAC signed body."""
    client, client_id, secret_key, _ = client_fixture
    path = "/graphql"

    gql_query = {
        "query": """
            query {
                getAccount(accountId: "acc_prod_001") {
                    id
                    clientId
                    balance
                    currency
                    status
                }
            }
        """
    }
    body = json.dumps(gql_query)

    headers = generate_signed_headers("POST", path, client_id, secret_key, payload=body)
    response = await client.post(path, content=body, headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    account = data["data"]["getAccount"]
    assert account["id"] == "acc_prod_001"
    assert account["clientId"] == client_id
    assert account["balance"] == 15420.50


@pytest.mark.asyncio
async def test_graphql_mutation_transfer(client_fixture):
    """Test authenticated GraphQL Mutation with HMAC signed body."""
    client, client_id, secret_key, _ = client_fixture
    path = "/graphql"

    gql_mutation = {
        "query": """
            mutation {
                executeTransfer(fromAccount: "acc_main", toAccount: "acc_dest", amount: 350.0, currency: "USD") {
                    success
                    transactionId
                    message
                    remainingBalance
                }
            }
        """
    }
    body = json.dumps(gql_mutation)

    headers = generate_signed_headers("POST", path, client_id, secret_key, payload=body)
    response = await client.post(path, content=body, headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert "data" in data
    result = data["data"]["executeTransfer"]
    assert result["success"] is True
    assert result["remainingBalance"] == 15070.50
    assert client_id in result["message"]


@pytest.mark.asyncio
async def test_graphql_tampered_query_rejected(client_fixture):
    """Tampering with GraphQL query string payload causes signature mismatch."""
    client, client_id, secret_key, _ = client_fixture
    path = "/graphql"

    original_query = json.dumps({"query": '{ getAccount(accountId: "acc_001") { id } }'})
    tampered_query = json.dumps({"query": '{ getAccount(accountId: "acc_HACKED") { id } }'})

    headers = generate_signed_headers("POST", path, client_id, secret_key, payload=original_query)
    response = await client.post(path, content=tampered_query, headers=headers)

    assert response.status_code == 401
    assert response.json()["error"] == "SIGNATURE_MISMATCH"
