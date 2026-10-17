"""
Integration Tests for AegisHMAC MongoDB Database Layer & Repositories.
Tests client CRUD, key envelope encryption, zero-downtime rotation, replay nonce TTL defense, and audit logs.
"""

import sys
import os
import secrets
import pytest
import pytest_asyncio
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.database.connection import DatabaseManager
from app.database.models import ClientStatus, KeyStatus, AuditLogDocument, AuditVerdict
from app.database.repositories.client_repo import ClientRepository
from app.database.repositories.key_repo import KeyRepository
from app.database.repositories.nonce_repo import NonceRepository
from app.database.repositories.audit_repo import AuditRepository
from app.core.errors import ReplayAttackError

TEST_DB_NAME = "aegis_hmac_test_db"


@pytest_asyncio.fixture(scope="function")
async def db_instance():
    """Connect to test database and teardown upon completion."""
    db = await DatabaseManager.connect(db_name=TEST_DB_NAME)
    yield db
    # Teardown: Drop test database
    if DatabaseManager.client:
        await DatabaseManager.client.drop_database(TEST_DB_NAME)
    await DatabaseManager.disconnect()


@pytest.mark.asyncio
async def test_client_lifecycle(db_instance):
    """Test client creation, retrieval, and status transitions."""
    client = await ClientRepository.create_client(db_instance, client_name="Payments Microservice")

    assert client.client_id.startswith("client_")
    assert client.client_name == "Payments Microservice"
    assert client.status == ClientStatus.ACTIVE

    fetched = await ClientRepository.get_client(db_instance, client.client_id)
    assert fetched is not None
    assert fetched.client_id == client.client_id

    # Update status to suspended
    updated = await ClientRepository.update_status(db_instance, client.client_id, ClientStatus.SUSPENDED)
    assert updated is True

    fetched_updated = await ClientRepository.get_client(db_instance, client.client_id)
    assert fetched_updated.status == ClientStatus.SUSPENDED


@pytest.mark.asyncio
async def test_key_provisioning_and_decryption(db_instance):
    """Test provisioning encrypted key and retrieving decrypted plaintext."""
    client = await ClientRepository.create_client(db_instance, client_name="Vault Test Service")
    raw_secret = secrets.token_hex(32)

    key_doc = await KeyRepository.provision_key(
        db=db_instance,
        client_id=client.client_id,
        raw_secret=raw_secret,
        algorithm="HMAC-SHA256",
    )

    assert key_doc.client_id == client.client_id
    assert key_doc.status == KeyStatus.ACTIVE
    assert key_doc.key_version == 1
    # Secret stored in database MUST NOT be plaintext
    assert key_doc.encrypted_secret != raw_secret

    # Retrieve valid keys and verify decryption
    valid_keys = await KeyRepository.get_valid_keys(db_instance, client.client_id)
    assert len(valid_keys) == 1
    retrieved_doc, decrypted_secret = valid_keys[0]

    assert retrieved_doc.key_id == key_doc.key_id
    assert decrypted_secret == raw_secret


@pytest.mark.asyncio
async def test_key_rotation_grace_period(db_instance):
    """Verify key rotation enables dual-key validity (old rotating + new active)."""
    client = await ClientRepository.create_client(db_instance, client_name="Rotation Test Client")
    secret_v1 = secrets.token_hex(32)
    secret_v2 = secrets.token_hex(32)

    # 1. Provision v1 key
    await KeyRepository.provision_key(db_instance, client.client_id, secret_v1, version=1)

    # 2. Trigger rotation to v2
    new_key, old_key = await KeyRepository.rotate_key(
        db=db_instance,
        client_id=client.client_id,
        new_raw_secret=secret_v2,
        grace_hours=24,
    )

    assert new_key.key_version == 2
    assert new_key.status == KeyStatus.ACTIVE
    assert old_key.key_version == 1
    assert old_key.status == KeyStatus.ROTATING
    assert old_key.expires_at is not None

    # 3. Both keys MUST be valid during the grace period
    valid_keys = await KeyRepository.get_valid_keys(db_instance, client.client_id)
    assert len(valid_keys) == 2

    secrets_in_store = [s for _, s in valid_keys]
    assert secret_v1 in secrets_in_store
    assert secret_v2 in secrets_in_store


@pytest.mark.asyncio
async def test_key_revocation(db_instance):
    """Revoking keys immediately invalidates all keys for that client."""
    client = await ClientRepository.create_client(db_instance, client_name="Compromised Client")
    secret = secrets.token_hex(32)
    await KeyRepository.provision_key(db_instance, client.client_id, secret)

    # Verify key is active
    assert len(await KeyRepository.get_valid_keys(db_instance, client.client_id)) == 1

    # Revoke keys
    revoked = await KeyRepository.revoke_all_keys(db_instance, client.client_id)
    assert revoked is True

    # No valid keys should be returned
    assert len(await KeyRepository.get_valid_keys(db_instance, client.client_id)) == 0


@pytest.mark.asyncio
async def test_nonce_replay_attack_prevention(db_instance):
    """Test that duplicate nonces raise ReplayAttackError."""
    client_id = "client_replay_test"
    nonce = secrets.token_hex(16)

    # First attempt: succeeds
    await NonceRepository.record_and_verify_nonce(db_instance, client_id, nonce)

    # Second attempt with same nonce and client_id: MUST raise ReplayAttackError
    with pytest.raises(ReplayAttackError) as exc_info:
        await NonceRepository.record_and_verify_nonce(db_instance, client_id, nonce)

    assert exc_info.value.error_code == "REPLAY_ATTACK_DETECTED"
    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_audit_logging(db_instance):
    """Verify security audit events are persisted and queried accurately."""
    log_entry = AuditLogDocument(
        request_id="req_998877",
        client_id="client_audit_test",
        timestamp=datetime.now(timezone.utc),
        method="POST",
        path="/api/v1/payments/transfer",
        ip_address="192.168.1.100",
        status_code=200,
        verdict=AuditVerdict.SUCCESS,
        latency_ms=1.42,
    )

    await AuditRepository.record_log(db_instance, log_entry)

    logs = await AuditRepository.get_recent_logs(db_instance, limit=10, client_id="client_audit_test")
    assert len(logs) >= 1
    assert logs[0].request_id == "req_998877"
    assert logs[0].verdict == AuditVerdict.SUCCESS
    assert logs[0].latency_ms == 1.42
