from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    environment: Literal["development", "test", "staging", "production"] = "development"
    database_url: str = "sqlite:///./agentguard.db"
    database_host: str | None = None
    database_name: str = "agentguard"
    database_user: str | None = None
    database_auth: Literal["password", "entra"] = "password"
    database_secret_name: str = "database-password"  # noqa: S105
    public_url: str = "http://localhost:8000"
    web_url: str = "http://localhost:3000"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    session_secure: bool = False
    payload_encryption_key: str | None = None
    api_key_pepper: str | None = None
    key_vault_url: str | None = None
    azure_client_id: str | None = None
    applicationinsights_connection_string: str | None = None
    redis_host: str | None = None
    redis_port: int = 10000
    redis_ssl: bool = True
    redis_auth: Literal["none", "entra"] = "none"
    otel_service_name: str = "agentguard-api"
    authorization_ttl_seconds: int = 900
    approval_ttl_seconds: int = 900
    execution_claim_ttl_seconds: int = 60
    access_token_ttl_seconds: int = 900
    refresh_token_ttl_seconds: int = 2_592_000
    request_body_limit_bytes: int = 262_144
    connector_timeout_seconds: float = 15.0
    dlp_default_action: Literal["allow", "warn", "redact", "approval", "block"] = "redact"
    worker_batch_size: int = 100
    archive_container: str = "audit-archive"
    audit_storage_account_url: str | None = None
    magic_link_webhook_url: str | None = None
    magic_link_secret_ref: str = "magic-link-webhook-secret"  # noqa: S105 - this is a Key Vault name, not a value
    microsoft_client_id: str | None = None
    google_client_id: str | None = None
    github_client_id: str | None = None
    log_level: str = "INFO"

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_origins(cls, value: object) -> object:
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @model_validator(mode="after")
    def secure_production(self) -> "Settings":
        if self.environment in {"staging", "production"}:
            if not self.session_secure:
                raise ValueError("SESSION_SECURE must be true outside development/test")
            if not (self.payload_encryption_key or self.key_vault_url):
                raise ValueError("PAYLOAD_ENCRYPTION_KEY or KEY_VAULT_URL is required outside development/test")
            if not (self.database_url.startswith("postgresql") or self.database_host):
                raise ValueError("PostgreSQL is required outside development/test")
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()


def configure_logging(settings: Settings) -> None:
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    for name in ("httpx", "httpcore", "azure.core.pipeline.policies.http_logging_policy"):
        logging.getLogger(name).setLevel(logging.WARNING)
    os.environ.setdefault("OTEL_SERVICE_NAME", settings.otel_service_name)
