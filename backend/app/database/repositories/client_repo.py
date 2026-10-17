"""
AegisHMAC Client Identity Repository.
Manages client lifecycle, registration, and status transitions.
"""

from datetime import datetime, timezone
from typing import List, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.core.crypto import generate_client_id
from app.database.models import ClientDocument, ClientStatus


class ClientRepository:
    """Repository handling CRUD operations on the 'clients' collection."""

    @staticmethod
    async def create_client(
        db: AsyncIOMotorDatabase,
        client_name: str,
        client_id: Optional[str] = None,
    ) -> ClientDocument:
        """Register a new client identity."""
        cid = client_id or generate_client_id()
        now = datetime.now(timezone.utc)

        doc = {
            "client_id": cid,
            "client_name": client_name.strip(),
            "status": ClientStatus.ACTIVE.value,
            "created_at": now,
            "updated_at": now,
        }

        await db.clients.insert_one(doc)
        return ClientDocument(**doc)

    @staticmethod
    async def get_client(db: AsyncIOMotorDatabase, client_id: str) -> Optional[ClientDocument]:
        """Fetch client record by unique client_id."""
        doc = await db.clients.find_one({"client_id": client_id})
        if not doc:
            return None
        return ClientDocument(**doc)

    @staticmethod
    async def list_clients(db: AsyncIOMotorDatabase) -> List[ClientDocument]:
        """List all registered clients ordered by creation date."""
        cursor = db.clients.find().sort("created_at", -1)
        clients: List[ClientDocument] = []
        async for doc in cursor:
            clients.append(ClientDocument(**doc))
        return clients

    @staticmethod
    async def update_status(
        db: AsyncIOMotorDatabase,
        client_id: str,
        status: ClientStatus,
    ) -> bool:
        """Update client operational status (ACTIVE, SUSPENDED, REVOKED)."""
        now = datetime.now(timezone.utc)
        result = await db.clients.update_one(
            {"client_id": client_id},
            {"$set": {"status": status.value, "updated_at": now}},
        )
        return result.modified_count > 0
