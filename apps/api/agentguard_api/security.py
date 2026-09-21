from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import threading
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.fernet import Fernet, InvalidToken

from .config import Settings, get_settings

logger = logging.getLogger(__name__)
password_hasher = PasswordHasher(time_cost=3, memory_cost=65_536, parallelism=4)


def digest_secret(value: str, pepper: str = "") -> str:
    return hmac.new(pepper.encode(), value.encode(), hashlib.sha256).hexdigest()


def verify_digest(value: str, expected: str, pepper: str = "") -> bool:
    return hmac.compare_digest(digest_secret(value, pepper), expected)


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, encoded: str | None) -> bool:
    if not encoded:
        return False
    try:
        return password_hasher.verify(encoded, password)
    except (VerificationError, InvalidHashError):
        return False


def random_token(size: int = 32) -> str:
    return secrets.token_urlsafe(size)


def is_expired(value: datetime | None) -> bool:
    if value is None:
        return False
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value <= datetime.now(timezone.utc)


class SecretStore:
    """Reads secret values from process env in dev or Managed Identity + Key Vault in Azure."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self._cache: dict[str, str] = {}
        self._lock = threading.Lock()
        self._client: Any = None

    def get(self, name: str, *, required: bool = True) -> str | None:
        import os

        with self._lock:
            if name in self._cache:
                return self._cache[name]
            env_name = name.upper().replace("-", "_")
            value = os.getenv(env_name)
            if not value and name == "payload-encryption-key":
                value = self.settings.payload_encryption_key
            if not value and name == "api-key-pepper":
                value = self.settings.api_key_pepper
            if not value and self.settings.key_vault_url:
                if self._client is None:
                    from azure.identity import DefaultAzureCredential
                    from azure.keyvault.secrets import SecretClient

                    credential = DefaultAzureCredential(managed_identity_client_id=self.settings.azure_client_id)
                    self._client = SecretClient(vault_url=self.settings.key_vault_url, credential=credential)
                value = self._client.get_secret(name).value
            if value:
                self._cache[name] = value
                return value
            if required:
                raise RuntimeError(f"Required secret {name!r} is not configured")
            return None


@lru_cache
def get_secret_store() -> SecretStore:
    return SecretStore(get_settings())


class PayloadCipher:
    def __init__(self, store: SecretStore, settings: Settings):
        key = store.get("payload-encryption-key", required=False)
        if not key and settings.environment in {"development", "test"}:
            key = Fernet.generate_key().decode()
            logger.warning("Using an ephemeral payload key; pending approvals do not survive process restart")
        if not key:
            raise RuntimeError("A Key Vault payload-encryption-key is required")
        self._fernet = Fernet(key.encode())

    def encrypt(self, payload: dict[str, Any]) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        return self._fernet.encrypt(raw).decode()

    def decrypt(self, token: str) -> dict[str, Any]:
        try:
            result = json.loads(self._fernet.decrypt(token.encode()).decode())
        except (InvalidToken, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Stored request payload failed authenticated decryption") from exc
        if not isinstance(result, dict):
            raise ValueError("Stored request payload is invalid")
        return result


@lru_cache
def get_payload_cipher() -> PayloadCipher:
    settings = get_settings()
    return PayloadCipher(get_secret_store(), settings)


def api_key_pepper() -> str:
    return get_secret_store().get("api-key-pepper", required=False) or ""


def make_machine_key(environment: str, organization_id: str, credential_id: str) -> tuple[str, str, str]:
    secret = random_token(32)
    raw = f"agk_{environment}_{organization_id}_{credential_id}_{secret}"
    return raw, digest_secret(raw, api_key_pepper()), secret[:8]


def parse_machine_key(raw: str) -> tuple[str, str, str] | None:
    parts = raw.split("_", 4)
    if len(parts) != 5 or parts[0] != "agk":
        return None
    _, environment, organization_id, credential_id, _ = parts
    if environment not in {"development", "staging", "production"}:
        return None
    return organization_id, credential_id, environment


def make_admin_key(environment: str, organization_id: str, key_id: str) -> tuple[str, str, str]:
    secret = random_token(32)
    raw = f"agu_{environment}_{organization_id}_{key_id}_{secret}"
    return raw, digest_secret(raw, api_key_pepper()), secret[:8]


def parse_admin_key(raw: str) -> tuple[str, str] | None:
    parts = raw.split("_", 4)
    if len(parts) != 5 or parts[0] != "agu":
        return None
    return parts[2], parts[3]


def verify_slack_signature(secret: str, timestamp: str, body: bytes, signature: str, tolerance: int = 300) -> bool:
    try:
        sent_at = int(timestamp)
    except ValueError:
        return False
    now = int(datetime.now(timezone.utc).timestamp())
    if abs(now - sent_at) > tolerance:
        return False
    base = b"v0:" + timestamp.encode() + b":" + body
    expected = "v0=" + hmac.new(secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
