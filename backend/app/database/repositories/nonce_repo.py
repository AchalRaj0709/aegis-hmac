"""
AegisHMAC Nonce Repository (Replay Attack Defense).
Enforces atomic single-use nonce validation backed by MongoDB Unique Index and TTL Auto-Purge.
"""

from datetime import datetime, timezone
from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo.errors import DuplicateKeyError
from app.core.errors import ReplayAttackError


class NonceRepository:
    """Repository preventing replay attacks via atomic nonce registration."""

    @staticmethod
    async def record_and_verify_nonce(
        db: AsyncIOMotorDatabase,
        client_id: str,
        nonce: str,
    ) -> None:
        """
        Record a nonce for a client.
        If the nonce was already used by this client within the TTL window,
        the unique compound index throws DuplicateKeyError, triggering a ReplayAttackError.

        :param db: Active Motor database instance.
        :param client_id: The authenticated client ID.
        :param nonce: The client-provided single-use nonce string.
        :raises ReplayAttackError: If nonce was already observed.
        """
        doc = {
            "nonce": nonce.strip(),
            "client_id": client_id,
            "created_at": datetime.now(timezone.utc),
        }

        try:
            await db.nonces.insert_one(doc)
        except DuplicateKeyError:
            raise ReplayAttackError(nonce=nonce)
