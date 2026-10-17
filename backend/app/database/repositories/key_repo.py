"""
AegisHMAC Key Lifecycle & Storage Repository.
Manages AES-256-GCM envelope encrypted keys, dual-key rotation grace windows, and revocation.
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.config import settings
from app.core.envelope import encrypt_secret, decrypt_secret
from app.core.errors import AegisSecurityError, KeyRevokedError
from app.database.models import ApiKeyDocument, KeyStatus


class KeyRepository:
    """Repository handling cryptographic key persistence and lifecycle in MongoDB."""

    @staticmethod
    async def provision_key(
        db: AsyncIOMotorDatabase,
        client_id: str,
        raw_secret: str,
        algorithm: str = "HMAC-SHA256",
        version: int = 1,
    ) -> ApiKeyDocument:
        """
        Encrypt a 256-bit symmetric secret using Master Key envelope encryption
        and store it in MongoDB.
        """
        encrypted_secret = encrypt_secret(raw_secret, settings.MASTER_ENCRYPTION_KEY)
        key_id = f"key_{secrets.token_hex(8)}"
        now = datetime.now(timezone.utc)

        doc = {
            "key_id": key_id,
            "client_id": client_id,
            "encrypted_secret": encrypted_secret,
            "key_version": version,
            "status": KeyStatus.ACTIVE.value,
            "algorithm": algorithm,
            "created_at": now,
            "expires_at": None,
        }

        await db.api_keys.insert_one(doc)
        return ApiKeyDocument(**doc)

    @staticmethod
    async def get_valid_keys(
        db: AsyncIOMotorDatabase,
        client_id: str,
    ) -> List[Tuple[ApiKeyDocument, str]]:
        """
        Retrieve all currently valid keys for a client and decrypt them into plaintext.
        Accepts:
        1. Status == ACTIVE
        2. Status == ROTATING (if current UTC time <= expires_at)
        Returns a list of (ApiKeyDocument, plaintext_secret_key) tuples.
        """
        cursor = db.api_keys.find({
            "client_id": client_id,
            "status": {"$in": [KeyStatus.ACTIVE.value, KeyStatus.ROTATING.value]},
        }).sort("key_version", -1)

        now = datetime.now(timezone.utc)
        valid_keys: List[Tuple[ApiKeyDocument, str]] = []

        async for raw_doc in cursor:
            doc = ApiKeyDocument(**raw_doc)

            # Check if rotating key has passed its expiration window
            if doc.status == KeyStatus.ROTATING and doc.expires_at:
                # Ensure timezone-aware comparison
                expires = doc.expires_at if doc.expires_at.tzinfo else doc.expires_at.replace(tzinfo=timezone.utc)
                if now > expires:
                    continue  # Expired rotating key, skip

            # Decrypt secret with Master Key
            decrypted_secret = decrypt_secret(doc.encrypted_secret, settings.MASTER_ENCRYPTION_KEY)
            valid_keys.append((doc, decrypted_secret))

        return valid_keys

    @staticmethod
    async def rotate_key(
        db: AsyncIOMotorDatabase,
        client_id: str,
        new_raw_secret: str,
        grace_hours: Optional[int] = None,
    ) -> Tuple[ApiKeyDocument, Optional[ApiKeyDocument]]:
        """
        Rotate the symmetric key for a client without downtime:
        1. Find current ACTIVE key.
        2. Mark current key as ROTATING with grace expiration window.
        3. Provision new key with version = previous_version + 1 as ACTIVE.
        """
        window_hours = grace_hours if grace_hours is not None else settings.KEY_ROTATION_GRACE_HOURS
        now = datetime.now(timezone.utc)
        grace_expiration = now + timedelta(hours=window_hours)

        # 1. Fetch current active key
        current_active = await db.api_keys.find_one({
            "client_id": client_id,
            "status": KeyStatus.ACTIVE.value,
        })

        old_key_doc: Optional[ApiKeyDocument] = None
        next_version = 1

        if current_active:
            # Transition active key to ROTATING with expiration
            await db.api_keys.update_one(
                {"key_id": current_active["key_id"]},
                {"$set": {
                    "status": KeyStatus.ROTATING.value,
                    "expires_at": grace_expiration,
                }},
            )
            current_active["status"] = KeyStatus.ROTATING.value
            current_active["expires_at"] = grace_expiration
            old_key_doc = ApiKeyDocument(**current_active)
            next_version = current_active.get("key_version", 1) + 1

        # 2. Provision new key as ACTIVE
        new_key_doc = await KeyRepository.provision_key(
            db=db,
            client_id=client_id,
            raw_secret=new_raw_secret,
            version=next_version,
        )

        return new_key_doc, old_key_doc

    @staticmethod
    async def revoke_all_keys(db: AsyncIOMotorDatabase, client_id: str) -> bool:
        """Permanently revoke all active and rotating keys for a client."""
        result = await db.api_keys.update_many(
            {"client_id": client_id, "status": {"$ne": KeyStatus.REVOKED.value}},
            {"$set": {"status": KeyStatus.REVOKED.value, "expires_at": datetime.now(timezone.utc)}},
        )
        return result.modified_count > 0
