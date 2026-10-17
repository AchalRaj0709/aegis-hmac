"""
AegisHMAC Database Seeder Script.
Pre-populates MongoDB with demo clients, encrypted symmetric keys, and historical audit logs.
"""

import asyncio
import os
import secrets
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from app.database.connection import DatabaseManager
from app.database.models import ClientStatus, KeyStatus, AuditLogDocument, AuditVerdict
from app.database.repositories.client_repo import ClientRepository
from app.database.repositories.key_repo import KeyRepository
from app.database.repositories.audit_repo import AuditRepository


if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

DEMO_CLIENTS = [
    {
        "client_name": "Fintech Payments Service",
        "client_id": "client_fintech_prod",
        "secret_key": "4a6566650123456789abcdef0123456789abcdef0123456789abcdef01234567",
    },
    {
        "client_name": "Mobile Client (iOS/Android)",
        "client_id": "client_mobile_app",
        "secret_key": "89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567",
    },
    {
        "client_name": "Analytics & Webhooks Ingress",
        "client_id": "client_analytics_node",
        "secret_key": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
    },
]


async def seed():
    print("[*] Connecting to MongoDB...")
    db = await DatabaseManager.connect()

    print("[*] Seeding Demo Client Identities & Key Vault...")
    created_credentials = []

    for item in DEMO_CLIENTS:
        # Check if already exists
        existing = await ClientRepository.get_client(db, item["client_id"])
        if existing:
            print(f"  • Client '{item['client_id']}' already exists, skipping.")
            continue

        client = await ClientRepository.create_client(
            db,
            client_name=item["client_name"],
            client_id=item["client_id"],
        )

        key_doc = await KeyRepository.provision_key(
            db=db,
            client_id=client.client_id,
            raw_secret=item["secret_key"],
            algorithm="HMAC-SHA256",
            version=1,
        )

        created_credentials.append((client.client_name, client.client_id, item["secret_key"]))
        print(f"  ✓ Provisioned: {client.client_name} ({client.client_id})")

    # Seed Sample Historical Audit Logs
    print("📊 Seeding Security Audit Logs & Telemetry...")
    now = datetime.now(timezone.utc)

    sample_logs = [
        AuditLogDocument(
            request_id=f"req_seed_{i+100}",
            client_id="client_fintech_prod",
            timestamp=now - timedelta(minutes=15 - i),
            method="POST",
            path="/api/v1/payments/transfer",
            ip_address="192.168.1.42",
            status_code=200,
            verdict=AuditVerdict.SUCCESS,
            latency_ms=round(1.15 + (i * 0.08), 2),
        )
        for i in range(8)
    ]

    # Add sample rejected logs (tamper, replay, stale)
    sample_logs.extend([
        AuditLogDocument(
            request_id="req_seed_blocked_tamper",
            client_id="client_mobile_app",
            timestamp=now - timedelta(minutes=5),
            method="POST",
            path="/api/v1/payments/transfer",
            ip_address="198.51.100.12",
            status_code=401,
            verdict=AuditVerdict.FAILED,
            failure_reason="Signature mismatch: Request data was tampered with or secret key is invalid.",
            latency_ms=0.85,
        ),
        AuditLogDocument(
            request_id="req_seed_blocked_replay",
            client_id="client_analytics_node",
            timestamp=now - timedelta(minutes=3),
            method="POST",
            path="/api/v1/webhooks/deliver",
            ip_address="203.0.113.88",
            status_code=401,
            verdict=AuditVerdict.FAILED,
            failure_reason="Replay attack detected: This request nonce has already been processed.",
            latency_ms=1.42,
        ),
        AuditLogDocument(
            request_id="req_seed_blocked_stale",
            client_id="client_fintech_prod",
            timestamp=now - timedelta(minutes=1),
            method="GET",
            path="/api/v1/user/profile",
            ip_address="192.168.1.42",
            status_code=408,
            verdict=AuditVerdict.FAILED,
            failure_reason="Request timestamp is outside the allowed tolerance window. Clock skew: 620.0s",
            latency_ms=0.35,
        ),
    ])

    for log in sample_logs:
        await AuditRepository.record_log(db, log)

    print(f"  [+] Seeded {len(sample_logs)} security audit telemetry records.")
    await DatabaseManager.disconnect()

    print("\n" + "=" * 70)
    print(">>> DATABASE SEEDING COMPLETE! <<<")
    print("=" * 70)
    print(f"{'Client Name':<30} | {'Client ID':<22} | {'Secret Key (HMAC)'}")
    print("-" * 70)
    for name, cid, sec in DEMO_CLIENTS:
        print(f"{name:<30} | {cid:<22} | {sec[:16]}...")
    print("=" * 70)
    print("You can now open http://localhost:5173 to view these seeded records in your dashboard!\n")


if __name__ == "__main__":
    asyncio.run(seed())
