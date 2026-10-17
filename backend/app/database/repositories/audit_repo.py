"""
AegisHMAC Security Audit Logging Repository.
Records and queries tamper-evident authentication telemetry and failure forensics.
"""

from typing import List, Optional
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.database.models import AuditLogDocument


class AuditRepository:
    """Repository handling asynchronous security audit logging in MongoDB."""

    @staticmethod
    async def record_log(db: AsyncIOMotorDatabase, log_entry: AuditLogDocument) -> None:
        """
        Persist an authentication attempt event.
        Ensures strict compliance with FR8: Secrets and raw signatures are NEVER logged.
        """
        doc = log_entry.model_dump()
        await db.audit_logs.insert_one(doc)

    @staticmethod
    async def get_recent_logs(
        db: AsyncIOMotorDatabase,
        limit: int = 50,
        client_id: Optional[str] = None,
    ) -> List[AuditLogDocument]:
        """Query recent authentication attempts ordered by timestamp descending."""
        query = {}
        if client_id:
            query["client_id"] = client_id

        cursor = db.audit_logs.find(query).sort("timestamp", -1).limit(limit)
        logs: List[AuditLogDocument] = []
        async for doc in cursor:
            logs.append(AuditLogDocument(**doc))
        return logs
