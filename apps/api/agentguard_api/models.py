from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    JSON, Boolean, DateTime, ForeignKey, Index, Integer, Numeric, String, Text, UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


def new_id() -> str:
    return str(uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Timestamped:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class User(Base, Timestamped):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    password_hash: Mapped[str | None] = mapped_column(Text)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Organization(Base, Timestamped):
    __tablename__ = "organizations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(100), unique=True)
    plan: Mapped[str] = mapped_column(String(30), default="free")
    dlp_action: Mapped[str] = mapped_column(String(20), default="redact")
    custom_dlp_patterns: Mapped[list] = mapped_column(JSON, default=list)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class OrganizationMember(Base):
    __tablename__ = "organization_members"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role: Mapped[str] = mapped_column(String(30), default="member")
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Workspace(Base, Timestamped):
    __tablename__ = "workspaces"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    environment: Mapped[str] = mapped_column(String(30), default="development")
    __table_args__ = (UniqueConstraint("organization_id", "name"),)


class Team(Base, Timestamped):
    __tablename__ = "teams"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (UniqueConstraint("workspace_id", "name"),)


class TeamMember(Base):
    __tablename__ = "team_members"
    team_id: Mapped[str] = mapped_column(ForeignKey("teams.id", ondelete="CASCADE"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    role: Mapped[str] = mapped_column(String(30), default="member")


class Invitation(Base, Timestamped):
    __tablename__ = "invitations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    email: Mapped[str] = mapped_column(String(320))
    role: Mapped[str] = mapped_column(String(30), default="member")
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class UserSession(Base):
    __tablename__ = "user_sessions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    access_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    refresh_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    access_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    refresh_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class MagicLink(Base):
    __tablename__ = "magic_links"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OAuthIdentity(Base):
    __tablename__ = "oauth_identities"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(30))
    provider_subject: Mapped[str] = mapped_column(String(500))
    __table_args__ = (UniqueConstraint("provider", "provider_subject"),)


class OAuthFlow(Base):
    __tablename__ = "oauth_flows"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    provider: Mapped[str] = mapped_column(String(30))
    state_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    encrypted_verifier: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Agent(Base, Timestamped):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id", ondelete="RESTRICT"), index=True)
    team_id: Mapped[str | None] = mapped_column(ForeignKey("teams.id", ondelete="SET NULL"), index=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    framework: Mapped[str] = mapped_column(String(60), default="custom")
    model_provider: Mapped[str] = mapped_column(String(60), default="unknown")
    environment: Mapped[str] = mapped_column(String(30), default="development")
    status: Mapped[str] = mapped_column(String(30), default="active", index=True)
    risk_level: Mapped[str] = mapped_column(String(20), default="unknown")
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("workspace_id", "name"),)


class AgentCredential(Base):
    __tablename__ = "agent_credentials"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), index=True)
    key_hash: Mapped[str] = mapped_column(String(64))
    key_prefix: Mapped[str] = mapped_column(String(16))
    environment: Mapped[str] = mapped_column(String(30))
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Tool(Base, Timestamped):
    __tablename__ = "tools"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    provider: Mapped[str] = mapped_column(String(60))
    description: Mapped[str] = mapped_column(Text, default="")
    risk_category: Mapped[str] = mapped_column(String(30), default="medium")
    read_write_classification: Mapped[str] = mapped_column(String(20), default="write")
    destructive: Mapped[bool] = mapped_column(Boolean, default=False)
    financial: Mapped[bool] = mapped_column(Boolean, default=False)
    sensitive_data: Mapped[bool] = mapped_column(Boolean, default=False)
    input_schema: Mapped[dict] = mapped_column(JSON, default=dict)
    output_schema: Mapped[dict] = mapped_column(JSON, default=dict)
    environment: Mapped[str] = mapped_column(String(30), default="development")
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    tags: Mapped[list] = mapped_column(JSON, default=list)
    adapter: Mapped[str] = mapped_column(String(30), default="sdk")
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (UniqueConstraint("organization_id", "name", "environment"),)


class AgentToolPermission(Base):
    __tablename__ = "agent_tool_permissions"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id", ondelete="CASCADE"), primary_key=True)
    tool_id: Mapped[str] = mapped_column(ForeignKey("tools.id", ondelete="CASCADE"), primary_key=True)
    allowed: Mapped[bool] = mapped_column(Boolean, default=True)


class Policy(Base, Timestamped):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    workspace_id: Mapped[str | None] = mapped_column(ForeignKey("workspaces.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    priority: Mapped[int] = mapped_column(Integer, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    current_version: Mapped[int] = mapped_column(Integer, default=1)
    __table_args__ = (UniqueConstraint("organization_id", "name"),)


class PolicyVersion(Base):
    __tablename__ = "policy_versions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id", ondelete="CASCADE"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    document: Mapped[dict] = mapped_column(JSON)
    checksum: Mapped[str] = mapped_column(String(64))
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (UniqueConstraint("policy_id", "version"),)


class AuthorizationRequest(Base):
    __tablename__ = "authorization_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    workspace_id: Mapped[str] = mapped_column(ForeignKey("workspaces.id", ondelete="RESTRICT"), index=True)
    agent_id: Mapped[str] = mapped_column(ForeignKey("agents.id", ondelete="RESTRICT"), index=True)
    tool_id: Mapped[str] = mapped_column(ForeignKey("tools.id", ondelete="RESTRICT"), index=True)
    credential_id: Mapped[str] = mapped_column(ForeignKey("agent_credentials.id", ondelete="RESTRICT"))
    correlation_id: Mapped[str] = mapped_column(String(100), index=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(200))
    arguments_hash: Mapped[str] = mapped_column(String(64))
    sanitized_arguments: Mapped[dict] = mapped_column(JSON)
    encrypted_payload: Mapped[str | None] = mapped_column(Text)
    policy_id: Mapped[str | None] = mapped_column(ForeignKey("policies.id", ondelete="SET NULL"))
    policy_version: Mapped[int | None] = mapped_column(Integer)
    risk_score: Mapped[int] = mapped_column(Integer)
    decision: Mapped[str] = mapped_column(String(30), index=True)
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), index=True)
    approval_id: Mapped[str | None] = mapped_column(String(36), index=True)
    execution_claim_hash: Mapped[str | None] = mapped_column(String(64))
    claim_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict | None] = mapped_column(JSON)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    __table_args__ = (UniqueConstraint("organization_id", "agent_id", "idempotency_key"),)


class ApprovalRequest(Base):
    __tablename__ = "approval_requests"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    authorization_request_id: Mapped[str] = mapped_column(ForeignKey("authorization_requests.id", ondelete="CASCADE"), unique=True)
    mode: Mapped[str] = mapped_column(String(20), default="any")
    threshold: Mapped[int] = mapped_column(Integer, default=1)
    eligible_roles: Mapped[list] = mapped_column(JSON, default=lambda: ["owner", "admin", "approver"])
    state: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class ApprovalDecision(Base):
    __tablename__ = "approval_decisions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    approval_request_id: Mapped[str] = mapped_column(ForeignKey("approval_requests.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    decision: Mapped[str] = mapped_column(String(10))
    comment: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (UniqueConstraint("approval_request_id", "user_id"),)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    workspace_id: Mapped[str | None] = mapped_column(String(36), index=True)
    agent_id: Mapped[str | None] = mapped_column(String(36), index=True)
    user_id: Mapped[str | None] = mapped_column(String(36), index=True)
    tool_id: Mapped[str | None] = mapped_column(String(36), index=True)
    request_id: Mapped[str | None] = mapped_column(String(36), index=True)
    correlation_id: Mapped[str] = mapped_column(String(100), index=True)
    event_type: Mapped[str] = mapped_column(String(80), index=True)
    decision: Mapped[str | None] = mapped_column(String(30), index=True)
    risk_score: Mapped[int | None] = mapped_column(Integer)
    arguments_hash: Mapped[str | None] = mapped_column(String(64))
    sanitized_data: Mapped[dict] = mapped_column(JSON, default=dict)
    result: Mapped[dict | None] = mapped_column(JSON)
    latency_ms: Mapped[float | None] = mapped_column(Numeric(12, 3))
    previous_hash: Mapped[str | None] = mapped_column(String(64))
    event_hash: Mapped[str] = mapped_column(String(64), unique=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class AuditCheckpoint(Base):
    __tablename__ = "audit_checkpoints"
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), primary_key=True)
    archived_through_hash: Mapped[str] = mapped_column(String(64))
    archived_through_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    archive_blob: Mapped[str] = mapped_column(Text)


class Budget(Base, Timestamped):
    __tablename__ = "budgets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    scope: Mapped[str] = mapped_column(String(30))
    scope_id: Mapped[str | None] = mapped_column(String(255), index=True)
    period: Mapped[str] = mapped_column(String(20))
    limit_minor: Mapped[int] = mapped_column(Integer)
    currency: Mapped[str] = mapped_column(String(3), default="USD")
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class BudgetUsage(Base):
    __tablename__ = "budget_usage"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    budget_id: Mapped[str] = mapped_column(ForeignKey("budgets.id", ondelete="CASCADE"), index=True)
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_minor: Mapped[int] = mapped_column(Integer, default=0)
    reserved_minor: Mapped[int] = mapped_column(Integer, default=0)
    __table_args__ = (UniqueConstraint("budget_id", "period_start"),)


class BudgetReservation(Base):
    __tablename__ = "budget_reservations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    budget_usage_id: Mapped[str] = mapped_column(ForeignKey("budget_usage.id", ondelete="CASCADE"), index=True)
    request_id: Mapped[str] = mapped_column(ForeignKey("authorization_requests.id", ondelete="CASCADE"), index=True)
    amount_minor: Mapped[int] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(20), default="reserved", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (UniqueConstraint("budget_usage_id", "request_id"),)


class RateLimit(Base, Timestamped):
    __tablename__ = "rate_limits"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    scope: Mapped[str] = mapped_column(String(30))
    scope_id: Mapped[str | None] = mapped_column(String(255), index=True)
    window_seconds: Mapped[int] = mapped_column(Integer)
    max_requests: Mapped[int] = mapped_column(Integer)
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class RateLimitBucket(Base):
    __tablename__ = "rate_limit_buckets"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    rate_limit_id: Mapped[str] = mapped_column(ForeignKey("rate_limits.id", ondelete="CASCADE"), index=True)
    bucket_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    count: Mapped[int] = mapped_column(Integer, default=0)
    __table_args__ = (UniqueConstraint("rate_limit_id", "bucket_start"),)


class KillSwitch(Base, Timestamped):
    __tablename__ = "kill_switches"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    scope: Mapped[str] = mapped_column(String(30))
    scope_id: Mapped[str | None] = mapped_column(String(255), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    reason: Mapped[str] = mapped_column(Text)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))


class ApiKey(Base):
    __tablename__ = "api_keys"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"))
    name: Mapped[str] = mapped_column(String(200))
    key_hash: Mapped[str] = mapped_column(String(64))
    key_prefix: Mapped[str] = mapped_column(String(16))
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Webhook(Base, Timestamped):
    __tablename__ = "webhooks"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    url: Mapped[str] = mapped_column(Text)
    events: Mapped[list] = mapped_column(JSON, default=list)
    secret_ref: Mapped[str] = mapped_column(String(200))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class WebhookDelivery(Base):
    __tablename__ = "webhook_deliveries"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    webhook_id: Mapped[str] = mapped_column(ForeignKey("webhooks.id", ondelete="CASCADE"), index=True)
    event_id: Mapped[str | None] = mapped_column(String(36))
    payload: Mapped[dict] = mapped_column(JSON)
    state: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    response_status: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class InboundWebhookEvent(Base):
    __tablename__ = "inbound_webhook_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    provider: Mapped[str] = mapped_column(String(30))
    provider_event_id: Mapped[str] = mapped_column(String(255))
    organization_id: Mapped[str | None] = mapped_column(String(36), index=True)
    payload_hash: Mapped[str] = mapped_column(String(64))
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    __table_args__ = (UniqueConstraint("provider", "provider_event_id"),)


class Integration(Base, Timestamped):
    __tablename__ = "integrations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(40))
    name: Mapped[str] = mapped_column(String(200))
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    secret_ref: Mapped[str | None] = mapped_column(String(200))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    channel: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(String(200))
    body: Mapped[str] = mapped_column(Text)
    state: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class UsageEvent(Base):
    __tablename__ = "usage_events"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(50), index=True)
    quantity: Mapped[int] = mapped_column(Integer, default=1)
    request_id: Mapped[str | None] = mapped_column(String(36))
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class BillingSubscription(Base, Timestamped):
    __tablename__ = "billing_subscriptions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), unique=True)
    provider_customer_id: Mapped[str | None] = mapped_column(String(255))
    provider_subscription_id: Mapped[str | None] = mapped_column(String(255), unique=True)
    plan: Mapped[str] = mapped_column(String(30), default="free")
    status: Mapped[str] = mapped_column(String(30), default="active")
    period_end: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


Index("ix_audit_org_time", AuditEvent.organization_id, AuditEvent.occurred_at)
Index("ix_request_org_time", AuthorizationRequest.organization_id, AuthorizationRequest.created_at)
