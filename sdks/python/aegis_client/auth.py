"""
AegisHMAC Authentication Plugins for HTTPX and Requests.
Allows zero-configuration request signing for Python HTTP clients.
"""

from typing import Generator
import httpx
from .signer import HMACSigner


class AegisHttpxAuth(httpx.Auth):
    """
    HTTPX authentication plugin for AegisHMAC.
    Usage:
        client = httpx.AsyncClient(auth=AegisHttpxAuth(client_id, secret_key))
        response = await client.post("https://api.example.com/transfer", json={...})
    """

    def __init__(
        self,
        client_id: str,
        secret_key: str,
        algorithm: str = "HMAC-SHA256",
    ) -> None:
        self.signer = HMACSigner(client_id=client_id, secret_key=secret_key, algorithm=algorithm)

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response, None]:
        # Read payload bytes
        body_bytes = request.read()

        # Convert headers
        headers_dict = {k: v for k, v in request.headers.items()}
        # Ensure host header is set if missing
        if "host" not in headers_dict and request.url.host:
            port_suffix = f":{request.url.port}" if request.url.port and request.url.port not in (80, 443) else ""
            headers_dict["host"] = f"{request.url.host}{port_suffix}"

        # Sign request
        signed_headers = self.signer.sign(
            method=request.method,
            path=request.url.path,
            headers=headers_dict,
            query_string=request.url.query.decode("ascii") if request.url.query else "",
            payload=body_bytes,
        )

        # Apply signed headers
        for k, v in signed_headers.items():
            request.headers[k] = v

        yield request
