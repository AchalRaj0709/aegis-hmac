"""
AegisHMAC High-Level API Client.
Provides a ready-to-use client interface for REST and GraphQL calls with built-in HMAC signing.
"""

from typing import Any, Dict, Optional
import httpx
from .auth import AegisHttpxAuth


class AegisClient:
    """
    High-level client for communicating with an AegisHMAC protected gateway.
    Automatically signs all outgoing requests.
    """

    def __init__(
        self,
        base_url: str,
        client_id: str,
        secret_key: str,
        algorithm: str = "HMAC-SHA256",
        timeout: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth = AegisHttpxAuth(client_id, secret_key, algorithm=algorithm)
        self.timeout = timeout

    async def get(
        self,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        """Execute an authenticated GET request."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        async with httpx.AsyncClient(auth=self.auth, timeout=self.timeout) as client:
            return await client.get(url, params=params, headers=headers)

    async def post(
        self,
        path: str,
        json: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> httpx.Response:
        """Execute an authenticated POST request."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        async with httpx.AsyncClient(auth=self.auth, timeout=self.timeout) as client:
            return await client.post(url, json=json, params=params, headers=headers)

    async def graphql(
        self,
        query: str,
        variables: Optional[Dict[str, Any]] = None,
        path: str = "graphql",
    ) -> httpx.Response:
        """Execute an authenticated GraphQL Query or Mutation."""
        url = f"{self.base_url}/{path.lstrip('/')}"
        payload: Dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables

        async with httpx.AsyncClient(auth=self.auth, timeout=self.timeout) as client:
            return await client.post(url, json=payload)
