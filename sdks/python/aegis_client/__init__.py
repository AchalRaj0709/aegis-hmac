"""
AegisHMAC Python Client SDK.
Provides automatic request signing, canonicalization, and seamless integration
with httpx and requests.
"""

from .signer import HMACSigner
from .auth import AegisHttpxAuth
from .client import AegisClient

__all__ = ["HMACSigner", "AegisHttpxAuth", "AegisClient"]
__version__ = "1.0.0"
