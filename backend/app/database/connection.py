"""
AegisHMAC MongoDB Database Connection & Index Lifecycle Manager.
Configures Motor async driver, handles connection pooling, and initializes security indexes (including TTL index).
"""

from typing import Optional
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from app.config import settings


class DatabaseManager:
    """Singleton managing Motor AsyncIOMotorClient connection lifecycle."""

    client: Optional[AsyncIOMotorClient] = None
    db: Optional[AsyncIOMotorDatabase] = None

    @classmethod
    async def connect(cls, uri: Optional[str] = None, db_name: Optional[str] = None) -> AsyncIOMotorDatabase:
        """Establish asynchronous connection to MongoDB and ensure indexes exist."""
        connection_uri = uri or settings.MONGODB_URI
        target_db = db_name or settings.DATABASE_NAME

        cls.client = AsyncIOMotorClient(connection_uri)
        cls.db = cls.client[target_db]

        await cls.init_indexes()
        return cls.db

    @classmethod
    async def disconnect(cls) -> None:
        """Close MongoDB connection gracefully."""
        if cls.client:
            cls.client.close()
            cls.client = None
            cls.db = None

    @classmethod
    async def init_indexes(cls) -> None:
        """
        Create essential performance and security indexes.
        Includes the crucial TTL (Time-To-Live) index for automatic replay attack nonce expiration.
        """
        if cls.db is None:
            return

        # 1. Clients collection indexes
        await cls.db.clients.create_index("client_id", unique=True)
        await cls.db.clients.create_index("status")

        # 2. API Keys collection indexes
        await cls.db.api_keys.create_index("key_id", unique=True)
        await cls.db.api_keys.create_index([("client_id", 1), ("status", 1)])

        # 3. Nonces collection: Unique compound index + 300s TTL Index
        # Prevents re-use of identical (client_id, nonce) pairs
        await cls.db.nonces.create_index([("nonce", 1), ("client_id", 1)], unique=True)
        # TTL Index: MongoDB automatically purges documents when 'created_at' exceeds NONCE_TTL_SECONDS
        await cls.db.nonces.create_index("created_at", expireAfterSeconds=settings.NONCE_TTL_SECONDS)

        # 4. Audit Logs collection indexes
        await cls.db.audit_logs.create_index([("timestamp", -1)])
        await cls.db.audit_logs.create_index([("client_id", 1)])
        await cls.db.audit_logs.create_index([("verdict", 1)])

    @classmethod
    def get_database(cls) -> AsyncIOMotorDatabase:
        """Return the active database instance."""
        if cls.db is None:
            raise RuntimeError("Database is not connected. Call DatabaseManager.connect() first.")
        return cls.db


def get_db() -> AsyncIOMotorDatabase:
    """Dependency injection helper for FastAPI endpoints."""
    return DatabaseManager.get_database()
