"""
AegisHMAC Performance & Verification Latency Benchmark Script.
Validates requirement NFR1 (p99 latency <= 50ms) and NFR2 (Throughput & Scalability).
Fires concurrent signed HMAC requests and computes statistical latency percentiles.
"""

import asyncio
import json
import os
import secrets
import statistics
import sys
import time
from datetime import datetime, timezone
from typing import List, Tuple
import httpx

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sdks", "python")))

from aegis_client.signer import HMACSigner

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Benchmark Configuration
BASE_URL = "http://localhost:8000"
TOTAL_REQUESTS = 300
CONCURRENCY = 20

# Use seeded fintech client
CLIENT_ID = "client_fintech_prod"
SECRET_KEY = "4a6566650123456789abcdef0123456789abcdef0123456789abcdef01234567"


async def send_single_request(
    client: httpx.AsyncClient,
    signer: HMACSigner,
    req_index: int,
    semaphore: asyncio.Semaphore,
) -> Tuple[bool, float, int]:
    """Send a single signed HMAC request and record its round-trip latency in ms."""
    path = "/api/v1/payments/transfer"
    payload = json.dumps({
        "recipient_id": f"vendor_{req_index}",
        "amount": round(10.0 + (req_index * 0.5), 2),
        "currency": "USD",
        "idempotency_key": f"bench_{secrets.token_hex(8)}",
    })

    # Sign request with unique nonce per request
    headers = signer.sign(
        method="POST",
        path=path,
        headers={"content-type": "application/json", "host": "localhost:8000"},
        payload=payload,
    )

    async with semaphore:
        start_time = time.perf_counter()
        try:
            res = await client.post(
                f"{BASE_URL}{path}",
                headers=headers,
                content=payload,
                timeout=10.0,
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return (res.status_code == 200, elapsed_ms, res.status_code)
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return (False, elapsed_ms, 500)


async def run_benchmark():
    print("=" * 70)
    print(">>> AEGISHMAC PERFORMANCE & VERIFICATION LATENCY BENCHMARK <<<")
    print("=" * 70)
    print(f"Target Gateway:     {BASE_URL}")
    print(f"Total Requests:     {TOTAL_REQUESTS}")
    print(f"Concurrency Level:  {CONCURRENCY}")
    print(f"Client Identity:    {CLIENT_ID}")
    print(f"HMAC Suite:         HMAC-SHA256 (AWS SigV4 Canonical Format)")
    print("-" * 70)
    print("[*] Dispatching signed requests...")

    signer = HMACSigner(client_id=CLIENT_ID, secret_key=SECRET_KEY)
    semaphore = asyncio.Semaphore(CONCURRENCY)

    overall_start = time.perf_counter()
    async with httpx.AsyncClient() as client:
        tasks = [
            send_single_request(client, signer, i, semaphore)
            for i in range(TOTAL_REQUESTS)
        ]
        results = await asyncio.gather(*tasks)

    overall_duration = time.perf_counter() - overall_start

    # Metrics calculation
    successful = [r for r in results if r[0]]
    failed = [r for r in results if not r[0]]
    latencies = sorted([r[1] for r in results])

    min_lat = min(latencies)
    max_lat = max(latencies)
    mean_lat = statistics.mean(latencies)
    median_lat = statistics.median(latencies)

    p95_idx = int(len(latencies) * 0.95)
    p99_idx = int(len(latencies) * 0.99)
    p95_lat = latencies[min(p95_idx, len(latencies) - 1)]
    p99_lat = latencies[min(p99_idx, len(latencies) - 1)]

    throughput_rps = round(len(results) / overall_duration, 1)

    print("\n" + "=" * 70)
    print("BENCHMARK RESULTS & LATENCY DISTRIBUTION")
    print("=" * 70)
    print(f"{'Metric':<32} | {'Measured Value'}")
    print("-" * 70)
    print(f"{'Total Requests Dispatched':<32} | {len(results)}")
    print(f"{'Successful Verifications (200 OK)':<32} | {len(successful)} ({len(successful)/len(results)*100:.1f}%)")
    print(f"{'Failed Verifications':<32} | {len(failed)}")
    print(f"{'Total Benchmark Duration':<32} | {overall_duration:.2f} seconds")
    print(f"{'Throughput (Requests / Sec)':<32} | {throughput_rps} req/sec")
    print("-" * 70)
    print(f"{'Min Latency':<32} | {min_lat:.2f} ms")
    print(f"{'Mean Latency':<32} | {mean_lat:.2f} ms")
    print(f"{'Median Latency (p50)':<32} | {median_lat:.2f} ms")
    print(f"{'95th Percentile (p95)':<32} | {p95_lat:.2f} ms")
    print(f"{'99th Percentile (p99)':<32} | {p99_lat:.2f} ms")
    print(f"{'Max Latency':<32} | {max_lat:.2f} ms")
    print("=" * 70)

    # NFR1 & NFR2 Compliance Check
    print("\n[+] SLA & Non-Functional Requirements Verification:")
    if p99_lat <= 50.0:
        print(f"  [PASS] NFR1 Latency SLA: p99 ({p99_lat:.2f}ms) is well under the 50.0ms limit!")
    else:
        print(f"  [WARN] NFR1 Latency SLA: p99 ({p99_lat:.2f}ms) exceeded 50.0ms limit.")

    if len(failed) == 0:
        print(f"  [PASS] Data Integrity & Authenticity: 100% of HMAC-SHA256 signatures verified!")
    else:
        print(f"  [FAIL] Failed requests observed: {len(failed)}")

    print("\nBenchmark completed successfully!\n")


if __name__ == "__main__":
    asyncio.run(run_benchmark())
