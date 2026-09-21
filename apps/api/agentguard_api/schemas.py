from __future__ import annotations

from datetime import datetime
import json
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, HttpUrl, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class RegisterInput(StrictModel):
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)
    name: str = Field(min_length=1, max_length=200)
    organization_name: str = Field(min_length=2, max_length=200)


class LoginInput(StrictModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class MagicLinkInput(StrictModel):
    email: EmailStr


class MagicLinkConsumeInput(StrictModel):
    token: str = Field(min_length=32, max_length=500)


class WorkspaceInput(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    environment: Literal["development", "staging", "production"] = "development"


class TeamInput(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    workspace_id: str


class InvitationInput(StrictModel):
    email: EmailStr
    role: Literal["admin", "member", "approver", "auditor"] = "member"


class InvitationAcceptInput(StrictModel):
    token: str = Field(min_length=32, max_length=500)


class AgentInput(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=4000)
    framework: str = Field(default="custom", max_length=60)
    model_provider: str = Field(default="unknown", max_length=60)
    environment: Literal["development", "staging", "production"] = "development"
    workspace_id: str
    team_id: str | None = None


class AgentPatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    framework: str | None = Field(default=None, max_length=60)
    model_provider: str | None = Field(default=None, max_length=60)
    team_id: str | None = None
    risk_level: Literal["low", "medium", "high", "critical", "unknown"] | None = None


class AgentStatusInput(StrictModel):
    status: Literal["active", "suspended", "revoked", "killed"]


class CredentialInput(StrictModel):
    environment: Literal["development", "staging", "production"]
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)
    tools: list[str] = Field(default_factory=list, max_length=500)


class ToolInput(StrictModel):
    name: str = Field(min_length=3, max_length=255, pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]+$")
    provider: str = Field(min_length=1, max_length=60, pattern=r"^[a-zA-Z0-9_-]+$")
    description: str = Field(default="", max_length=4000)
    risk_category: Literal["low", "medium", "high", "critical"] = "medium"
    read_write_classification: Literal["read", "write", "admin"] = "write"
    destructive: bool = False
    financial: bool = False
    sensitive_data: bool = False
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    environment: Literal["development", "staging", "production"] = "development"
    tags: list[str] = Field(default_factory=list, max_length=100)
    adapter: Literal["sdk", "http", "stripe", "github", "postgres", "mcp"] = "sdk"
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("config")
    @classmethod
    def no_inline_secrets(cls, value: dict[str, Any]) -> dict[str, Any]:
        banned = {"secret", "password", "token", "api_key", "authorization", "private_key", "connection_string"}
        def has_banned(obj: Any) -> bool:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if str(k).lower() in banned or has_banned(v):
                        return True
            elif isinstance(obj, list):
                for item in obj:
                    if has_banned(item):
                        return True
            return False

        if has_banned(value):
            raise ValueError("connector secrets must be referenced through secret_ref, never stored inline")
        return value


class PolicyInput(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    priority: int = Field(default=0, ge=-10_000, le=10_000)
    document: dict[str, Any] | str
    workspace_id: str | None = None


class PolicySimulationInput(StrictModel):
    document: dict[str, Any] | str
    facts: dict[str, Any]


class AuthorizationInput(StrictModel):
    agent_id: str | None = None
    tool: str = Field(min_length=3, max_length=255)
    arguments: dict[str, Any] = Field(default_factory=dict)
    context: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, min_length=8, max_length=200)

    @field_validator("arguments", "context")
    @classmethod
    def finite_json(cls, value: dict[str, Any]) -> dict[str, Any]:
        json.dumps(value, allow_nan=False)
        def check_depth(item: Any, depth: int = 0) -> None:
            if depth > 32:
                raise ValueError("JSON nesting exceeds 32 levels")
            if isinstance(item, dict):
                for child in item.values():
                    check_depth(child, depth + 1)
            elif isinstance(item, list):
                for child in item:
                    check_depth(child, depth + 1)
        check_depth(value)
        return value


class ResultInput(StrictModel):
    status: Literal["succeeded", "failed"]
    result: Any = None
    error: str | None = Field(default=None, max_length=2000)

    @field_validator("result")
    @classmethod
    def finite_json(cls, value: Any) -> Any:
        json.dumps(value, allow_nan=False)
        return value


class ApprovalDecisionInput(StrictModel):
    decision: Literal["approve", "reject"]
    comment: str = Field(default="", max_length=2000)


class BudgetInput(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    scope: Literal["organization", "workspace", "team", "agent", "tool", "provider"]
    scope_id: str | None = None
    period: Literal["action", "daily", "weekly", "monthly"]
    limit_minor: int = Field(gt=0, le=9_000_000_000_000)
    currency: str = Field(default="USD", min_length=3, max_length=3, pattern=r"^[A-Za-z]{3}$")

    @field_validator("currency")
    @classmethod
    def uppercase_currency(cls, value: str) -> str:
        return value.upper()


class RateLimitInput(StrictModel):
    scope: Literal["organization", "workspace", "agent", "tool"]
    scope_id: str | None = None
    window_seconds: int = Field(ge=1, le=86_400)
    max_requests: int = Field(ge=1, le=10_000_000)


class KillSwitchInput(StrictModel):
    scope: Literal["organization", "workspace", "team", "agent", "tool", "environment"]
    scope_id: str | None = Field(default=None, max_length=255)
    active: bool
    reason: str = Field(min_length=3, max_length=2000)


class IntegrationInput(StrictModel):
    provider: Literal["stripe", "github", "slack", "postgres", "http", "mcp", "email", "webhook"]
    name: str = Field(min_length=1, max_length=200)
    config: dict[str, Any] = Field(default_factory=dict)
    secret_ref: str | None = Field(default=None, max_length=200, pattern=r"^[a-zA-Z0-9-]+$")

    @field_validator("config")
    @classmethod
    def no_inline_secrets(cls, value: dict[str, Any]) -> dict[str, Any]:
        banned = {"secret", "password", "token", "api_key", "authorization", "private_key", "connection_string"}
        def has_banned(obj: Any) -> bool:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if str(k).lower() in banned or has_banned(v):
                        return True
            elif isinstance(obj, list):
                for item in obj:
                    if has_banned(item):
                        return True
            return False

        if has_banned(value):
            raise ValueError("connector secrets must be referenced through secret_ref, never stored inline")
        return value


class WebhookInput(StrictModel):
    url: HttpUrl
    events: list[str] = Field(min_length=1, max_length=100)
    secret_ref: str = Field(max_length=200, pattern=r"^[a-zA-Z0-9-]+$")


class ApiKeyInput(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    scopes: list[str] = Field(default_factory=lambda: ["read"], max_length=100)
    expires_in_days: int | None = Field(default=None, ge=1, le=3650)


class CheckoutInput(StrictModel):
    plan: Literal["pro", "team"]


class SettingsInput(StrictModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    dlp_action: Literal["allow", "warn", "redact", "approval", "block"] | None = None
    custom_dlp_patterns: list[dict[str, str]] | None = Field(default=None, max_length=50)


class AuthorizationOutput(BaseModel):
    decision: str
    request_id: str
    approval_id: str | None = None
    risk_score: int
    approval_required: bool
    reason: str
    status: str
    result: Any = None


class HealthOutput(BaseModel):
    status: Literal["ok", "degraded"]
    time: datetime
