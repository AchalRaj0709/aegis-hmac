"""
AegisHMAC Global Configuration.
Loads settings from environment variables or .env file with type validation.
"""

from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application configuration and cryptographic parameter settings."""

    # Application
    APP_NAME: str = "AegisHMAC"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # MongoDB
    MONGODB_URI: str = "mongodb://localhost:27017"
    DATABASE_NAME: str = "aegis_hmac_db"

    # Master Key for Envelope Encryption of secret keys at rest (32 bytes / 64 hex chars)
    # Default is a development key. In production, provide via secure environment variable.
    MASTER_ENCRYPTION_KEY: str = (
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    )

    # Temporal & Security Tolerances
    CLOCK_SKEW_TOLERANCE_SECONDS: float = 300.0  # ±5 minutes
    NONCE_TTL_SECONDS: int = 300  # Nonces automatically expire and vanish after 5 min
    ALLOWED_ALGORITHMS: List[str] = ["HMAC-SHA256", "HMAC-SHA512"]
    DEFAULT_ALGORITHM: str = "HMAC-SHA256"

    # Key Rotation Grace Window (hours during which an old rotating key remains valid)
    KEY_ROTATION_GRACE_HOURS: int = 24

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
