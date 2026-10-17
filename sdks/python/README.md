# 🐍 AegisHMAC Python Client SDK

The official Python client library for communicating with **AegisHMAC** protected gateways and microservices.

---

## 📦 Installation

```bash
pip install aegis-hmac-client
```

---

## 🚀 Quickstart

### 1. Using the High-Level `AegisClient`
```python
import asyncio
from aegis_client import AegisClient

async def main():
    client = AegisClient(
        base_url="https://api.example.com",
        client_id="client_abc123",
        secret_key="your_256_bit_secret_key_here",
    )

    # 1. Authenticated REST GET
    profile = await client.get("/api/v1/user/profile")
    print("Profile:", profile.json())

    # 2. Authenticated REST POST (Tamper-Proof)
    transfer = await client.post(
        "/api/v1/payments/transfer",
        json={"recipient_id": "vendor_42", "amount": 150.00, "currency": "USD"}
    )
    print("Transfer status:", transfer.json())

    # 3. Authenticated GraphQL Query
    gql_res = await client.graphql(
        query="query { getAccount(accountId: \"acc_1\") { balance currency } }"
    )
    print("Account:", gql_res.json())

asyncio.run(main())
```

---

### 2. Using with `HTTPX` Directly via `AegisHttpxAuth`
```python
import httpx
from aegis_client import AegisHttpxAuth

auth = AegisHttpxAuth(client_id="client_abc123", secret_key="your_secret")

with httpx.Client(auth=auth) as client:
    response = client.get("https://api.example.com/api/v1/user/profile")
    print(response.json())
```
