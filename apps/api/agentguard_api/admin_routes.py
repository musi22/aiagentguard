from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from agentguard_policy import evaluate, parse_policy
from agentguard_shared import validate_custom_patterns

from .audit import append_audit, hash_payload, verify_audit_chain
from .config import get_settings
from .connectors import _safe_url
from .database import get_db
from .dependencies import Principal, current_principal, require_roles
from .limits import PLAN_LIMITS, settle_budget_reservations
from .models import (
    Agent, AgentCredential, ApiKey, ApprovalDecision, ApprovalRequest, AuditCheckpoint, AuditEvent, AuthorizationRequest, BillingSubscription,
    Budget, BudgetUsage, Integration, Invitation, KillSwitch, Organization, OrganizationMember, Policy, PolicyVersion,
    RateLimit, Team, Tool, UsageEvent, User, Webhook, Workspace, new_id, utcnow,
)
from .schemas import (
    AgentInput, AgentPatch, AgentStatusInput, ApiKeyInput, ApprovalDecisionInput, BudgetInput, CheckoutInput,
    CredentialInput, IntegrationInput, InvitationInput, KillSwitchInput, PolicyInput, PolicySimulationInput,
    RateLimitInput, SettingsInput, TeamInput, ToolInput, WebhookInput, WorkspaceInput,
)
from .security import digest_secret, get_secret_store, is_expired, make_admin_key, make_machine_key, random_token

router = APIRouter(prefix="/api/v1", tags=["management"])
admin = require_roles("owner", "admin")


def _owner_id(db: Session, principal: Principal) -> str:
    if principal.user_id:
        return principal.user_id
    owner = db.scalar(select(OrganizationMember.user_id).where(
        OrganizationMember.organization_id == principal.organization_id, OrganizationMember.role == "owner"
    ))
    if not owner:
        raise HTTPException(status_code=403, detail="Organization has no owner")
    return owner


def _commit(db: Session, conflict: str = "Resource already exists") -> None:
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=conflict) from exc


def _workspace(db: Session, principal: Principal, workspace_id: str) -> Workspace:
    item = db.scalar(select(Workspace).where(
        Workspace.id == workspace_id, Workspace.organization_id == principal.organization_id
    ))
    if not item:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return item


def _team(db: Session, principal: Principal, team_id: str) -> Team:
    item = db.scalar(select(Team).where(Team.id == team_id, Team.organization_id == principal.organization_id))
    if not item:
        raise HTTPException(status_code=404, detail="Team not found")
    return item


def _agent(db: Session, principal: Principal, agent_id: str) -> Agent:
    item = db.scalar(select(Agent).where(
        Agent.id == agent_id, Agent.organization_id == principal.organization_id, Agent.deleted_at.is_(None)
    ))
    if not item:
        raise HTTPException(status_code=404, detail="Agent not found")
    return item


def _tool(db: Session, principal: Principal, tool_id: str) -> Tool:
    item = db.scalar(select(Tool).where(Tool.id == tool_id, Tool.organization_id == principal.organization_id))
    if not item:
        raise HTTPException(status_code=404, detail="Tool not found")
    return item


def _agent_json(item: Agent) -> dict[str, Any]:
    return {field: getattr(item, field) for field in (
        "id", "organization_id", "workspace_id", "team_id", "name", "description", "framework",
        "model_provider", "environment", "status", "risk_level", "created_at", "updated_at", "last_seen_at",
    )}


def _tool_json(item: Tool) -> dict[str, Any]:
    return {field: getattr(item, field) for field in (
        "id", "name", "provider", "description", "risk_category", "read_write_classification", "destructive",
        "financial", "sensitive_data", "input_schema", "output_schema", "environment", "tags", "adapter", "config",
        "disabled", "created_at", "updated_at",
    )}


@router.get("/workspaces")
def list_workspaces(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> list[dict]:
    return [{"id": item.id, "name": item.name, "environment": item.environment} for item in db.scalars(
        select(Workspace).where(Workspace.organization_id == principal.organization_id).order_by(Workspace.name)
    ).all()]


@router.post("/workspaces", status_code=201)
def create_workspace(payload: WorkspaceInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    item = Workspace(organization_id=principal.organization_id, **payload.model_dump())
    db.add(item)
    _commit(db)
    return {"id": item.id, "name": item.name, "environment": item.environment}


@router.get("/teams")
def list_teams(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> list[dict]:
    return [{"id": item.id, "name": item.name, "workspace_id": item.workspace_id, "disabled": item.disabled} for item in db.scalars(
        select(Team).where(Team.organization_id == principal.organization_id).order_by(Team.name)
    ).all()]


@router.post("/teams", status_code=201)
def create_team(payload: TeamInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    _workspace(db, principal, payload.workspace_id)
    item = Team(organization_id=principal.organization_id, **payload.model_dump())
    db.add(item)
    _commit(db)
    return {"id": item.id, "name": item.name, "workspace_id": item.workspace_id, "disabled": item.disabled}


@router.get("/members")
def list_members(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> list[dict]:
    rows = db.execute(
        select(User, OrganizationMember).join(OrganizationMember, OrganizationMember.user_id == User.id).where(
            OrganizationMember.organization_id == principal.organization_id
        ).order_by(User.email)
    ).all()
    return [{"id": user.id, "email": user.email, "name": user.name, "role": member.role, "status": member.status} for user, member in rows]


def _deliver_invitation(email: str, token: str) -> str | None:
    settings = get_settings()
    link = f"{settings.web_url.rstrip('/')}/invitations/accept?token={token}"
    if settings.magic_link_webhook_url:
        _safe_url(settings.magic_link_webhook_url)
        secret = get_secret_store().get(settings.magic_link_secret_ref)
        httpx.post(
            settings.magic_link_webhook_url,
            json={"to": email, "template": "agentguard_invitation", "variables": {"link": link}},
            headers={"Authorization": f"Bearer {secret}"}, timeout=10, follow_redirects=False,
        ).raise_for_status()
        return None
    return token if settings.environment in {"development", "test"} else None


@router.post("/invitations", status_code=201)
def invite_member(payload: InvitationInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    if not get_settings().magic_link_webhook_url and get_settings().environment not in {"development", "test"}:
        raise HTTPException(status_code=503, detail="Email delivery is not configured")
    token = random_token(40)
    invitation = Invitation(
        organization_id=principal.organization_id, email=str(payload.email).lower(), role=payload.role,
        token_hash=digest_secret(token), expires_at=datetime.now(timezone.utc) + timedelta(days=7),
    )
    db.add(invitation)
    db.commit()
    dev_token = _deliver_invitation(invitation.email, token)
    result = {"id": invitation.id, "email": invitation.email, "role": invitation.role, "expires_at": invitation.expires_at}
    if dev_token:
        result["development_token"] = dev_token
    return result


@router.post("/invitations/accept")
def accept_invitation(token: str, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> dict:
    invitation = db.scalar(select(Invitation).where(Invitation.token_hash == digest_secret(token)).with_for_update())
    user = db.get(User, principal.user_id) if principal.user_id else None
    if not invitation or invitation.accepted_at or is_expired(invitation.expires_at) or not user or invitation.email != user.email:
        raise HTTPException(status_code=400, detail="Invitation is invalid or expired")
    existing = db.scalar(select(OrganizationMember).where(
        OrganizationMember.organization_id == invitation.organization_id, OrganizationMember.user_id == user.id
    ))
    if not existing:
        db.add(OrganizationMember(
            organization_id=invitation.organization_id, user_id=user.id, role=invitation.role, status="active"
        ))
    invitation.accepted_at = utcnow()
    db.commit()
    return {"accepted": True, "organization_id": invitation.organization_id}


@router.get("/agents")
def list_agents(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> list[dict]:
    return [_agent_json(item) for item in db.scalars(select(Agent).where(
        Agent.organization_id == principal.organization_id, Agent.deleted_at.is_(None)
    ).order_by(Agent.created_at.desc())).all()]


@router.post("/agents", status_code=201)
def create_agent(payload: AgentInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    organization = db.get(Organization, principal.organization_id)
    limit = PLAN_LIMITS.get(organization.plan, PLAN_LIMITS["free"])["agents"]
    count = db.scalar(select(func.count(Agent.id)).where(
        Agent.organization_id == principal.organization_id, Agent.deleted_at.is_(None)
    )) or 0
    if count >= limit:
        raise HTTPException(status_code=402, detail="Agent plan limit reached")
    workspace = _workspace(db, principal, payload.workspace_id)
    if workspace.environment != payload.environment:
        raise HTTPException(status_code=422, detail="Agent environment must match its workspace")
    if payload.team_id and _team(db, principal, payload.team_id).workspace_id != workspace.id:
        raise HTTPException(status_code=422, detail="Team belongs to a different workspace")
    item = Agent(organization_id=principal.organization_id, owner_id=_owner_id(db, principal), **payload.model_dump())
    db.add(item)
    _commit(db)
    return _agent_json(item)


@router.patch("/agents/{agent_id}")
def update_agent(agent_id: str, payload: AgentPatch, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    item = _agent(db, principal, agent_id)
    values = payload.model_dump(exclude_unset=True)
    if values.get("team_id") and _team(db, principal, values["team_id"]).workspace_id != item.workspace_id:
        raise HTTPException(status_code=422, detail="Team belongs to a different workspace")
    for key, value in values.items():
        setattr(item, key, value)
    _commit(db)
    return _agent_json(item)


@router.post("/agents/{agent_id}/status")
def agent_status(agent_id: str, payload: AgentStatusInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    item = _agent(db, principal, agent_id)
    item.status = payload.status
    if payload.status == "revoked":
        for credential in db.scalars(select(AgentCredential).where(
            AgentCredential.organization_id == principal.organization_id, AgentCredential.agent_id == item.id,
            AgentCredential.revoked_at.is_(None),
        )).all():
            credential.revoked_at = utcnow()
    append_audit(db, organization_id=principal.organization_id, user_id=_owner_id(db, principal), agent_id=item.id,
                 correlation_id=new_id(), event_type="agent.status_changed", data={"status": payload.status})
    db.commit()
    return _agent_json(item)


@router.delete("/agents/{agent_id}", status_code=204)
def delete_agent(agent_id: str, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> Response:
    item = _agent(db, principal, agent_id)
    item.deleted_at, item.status = utcnow(), "revoked"
    for credential in db.scalars(select(AgentCredential).where(
        AgentCredential.organization_id == principal.organization_id, AgentCredential.agent_id == item.id,
        AgentCredential.revoked_at.is_(None),
    )).all():
        credential.revoked_at = utcnow()
    db.commit()
    return Response(status_code=204)


@router.post("/agents/{agent_id}/credentials", status_code=201)
def create_credential(agent_id: str, payload: CredentialInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    item = _agent(db, principal, agent_id)
    if payload.environment != item.environment:
        raise HTTPException(status_code=422, detail="Credential environment must match agent")
    credential = AgentCredential(
        organization_id=principal.organization_id, agent_id=item.id, key_hash="pending", key_prefix="pending",
        environment=payload.environment, scopes=payload.tools,
        expires_at=utcnow() + timedelta(days=payload.expires_in_days) if payload.expires_in_days else None,
    )
    db.add(credential)
    db.flush()
    raw, key_hash, prefix = make_machine_key(payload.environment, principal.organization_id, credential.id)
    credential.key_hash, credential.key_prefix = key_hash, prefix
    db.commit()
    return {"api_key": raw, "credential": {"id": credential.id, "key_prefix": prefix,
            "environment": credential.environment, "scopes": credential.scopes, "expires_at": credential.expires_at}}


@router.post("/agents/{agent_id}/credentials/rotate", status_code=201)
def rotate_credential(agent_id: str, payload: CredentialInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    for credential in db.scalars(select(AgentCredential).where(
        AgentCredential.organization_id == principal.organization_id, AgentCredential.agent_id == agent_id,
        AgentCredential.revoked_at.is_(None), AgentCredential.environment == payload.environment,
    )).all():
        credential.revoked_at = utcnow()
    db.flush()
    return create_credential(agent_id, payload, principal, db)


@router.get("/credentials")
def list_credentials(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> list[dict]:
    return [{field: getattr(item, field) for field in ("id", "agent_id", "key_prefix", "environment", "scopes", "expires_at", "last_used_at", "revoked_at", "created_at")}
            for item in db.scalars(select(AgentCredential).where(
                AgentCredential.organization_id == principal.organization_id
            ).order_by(AgentCredential.created_at.desc())).all()]


@router.delete("/credentials/{credential_id}", status_code=204)
def revoke_credential(credential_id: str, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> Response:
    item = db.scalar(select(AgentCredential).where(
        AgentCredential.id == credential_id, AgentCredential.organization_id == principal.organization_id
    ))
    if not item:
        raise HTTPException(status_code=404, detail="Credential not found")
    item.revoked_at = utcnow()
    db.commit()
    return Response(status_code=204)


@router.get("/tools")
def list_tools(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> list[dict]:
    return [_tool_json(item) for item in db.scalars(select(Tool).where(
        Tool.organization_id == principal.organization_id
    ).order_by(Tool.created_at.desc())).all()]


@router.post("/tools", status_code=201)
def create_tool(payload: ToolInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    from jsonschema.validators import validator_for

    organization = db.get(Organization, principal.organization_id)
    limit = PLAN_LIMITS.get(organization.plan, PLAN_LIMITS["free"])["tools"]
    count = db.scalar(select(func.count(Tool.id)).where(Tool.organization_id == principal.organization_id)) or 0
    if count >= limit:
        raise HTTPException(status_code=402, detail="Tool plan limit reached")
    try:
        if payload.input_schema:
            validator_for(payload.input_schema).check_schema(payload.input_schema)
        if payload.output_schema:
            validator_for(payload.output_schema).check_schema(payload.output_schema)
    except Exception as exc:
        raise HTTPException(status_code=422, detail="Tool JSON Schema is invalid") from exc
    if payload.adapter in {"http", "mcp"}:
        _safe_url(str(payload.config.get("url", "")), allowed_hosts=payload.config.get("allowed_hosts"))
    item = Tool(organization_id=principal.organization_id, owner_id=_owner_id(db, principal), **payload.model_dump())
    db.add(item)
    _commit(db)
    return _tool_json(item)


@router.patch("/tools/{tool_id}")
def update_tool(tool_id: str, payload: ToolInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    item = _tool(db, principal, tool_id)
    if payload.adapter in {"http", "mcp"}:
        _safe_url(str(payload.config.get("url", "")), allowed_hosts=payload.config.get("allowed_hosts"))
    for key, value in payload.model_dump().items():
        setattr(item, key, value)
    _commit(db)
    return _tool_json(item)


@router.delete("/tools/{tool_id}", status_code=204)
def disable_tool(tool_id: str, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> Response:
    item = _tool(db, principal, tool_id)
    item.disabled = True
    append_audit(db, organization_id=principal.organization_id, user_id=_owner_id(db, principal), tool_id=item.id,
                 correlation_id=new_id(), event_type="tool.disabled")
    db.commit()
    return Response(status_code=204)


def _policy_json(item: Policy, version: PolicyVersion | None) -> dict[str, Any]:
    return {
        "id": item.id, "name": item.name, "workspace_id": item.workspace_id, "priority": item.priority,
        "enabled": item.enabled, "current_version": item.current_version,
        "document": version.document if version else None,
        "checksum": version.checksum if version else None, "created_at": item.created_at, "updated_at": item.updated_at,
    }


def _parse_policy_http(document: dict | str) -> dict:
    try:
        return parse_policy(document)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid policy: {exc}") from exc


@router.get("/policies")
def list_policies(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> list[dict]:
    result = []
    for item in db.scalars(select(Policy).where(
        Policy.organization_id == principal.organization_id
    ).order_by(Policy.priority.desc(), Policy.name)).all():
        version = db.scalar(select(PolicyVersion).where(
            PolicyVersion.policy_id == item.id, PolicyVersion.version == item.current_version
        ))
        result.append(_policy_json(item, version))
    return result


@router.post("/policies", status_code=201)
def create_policy(payload: PolicyInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    document = _parse_policy_http(payload.document)
    if payload.workspace_id:
        _workspace(db, principal, payload.workspace_id)
    item = Policy(
        organization_id=principal.organization_id, workspace_id=payload.workspace_id, name=payload.name,
        priority=payload.priority, enabled=True, current_version=1,
    )
    db.add(item)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Policy name already exists") from exc
    version = PolicyVersion(
        organization_id=principal.organization_id, policy_id=item.id, version=1, document=document,
        checksum=hash_payload(document), created_by=_owner_id(db, principal),
    )
    db.add(version)
    _commit(db)
    return _policy_json(item, version)


@router.patch("/policies/{policy_id}")
def update_policy(policy_id: str, payload: PolicyInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    item = db.scalar(select(Policy).where(
        Policy.id == policy_id, Policy.organization_id == principal.organization_id
    ).with_for_update())
    if not item:
        raise HTTPException(status_code=404, detail="Policy not found")
    document = _parse_policy_http(payload.document)
    if payload.workspace_id:
        _workspace(db, principal, payload.workspace_id)
    item.name, item.priority, item.workspace_id = payload.name, payload.priority, payload.workspace_id
    item.current_version += 1
    version = PolicyVersion(
        organization_id=principal.organization_id, policy_id=item.id, version=item.current_version,
        document=document, checksum=hash_payload(document), created_by=_owner_id(db, principal),
    )
    db.add(version)
    _commit(db)
    return _policy_json(item, version)


@router.post("/policies/{policy_id}/status")
def policy_status(policy_id: str, enabled: bool, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    item = db.scalar(select(Policy).where(Policy.id == policy_id, Policy.organization_id == principal.organization_id))
    if not item:
        raise HTTPException(status_code=404, detail="Policy not found")
    item.enabled = enabled
    db.commit()
    return {"id": item.id, "enabled": item.enabled}


@router.post("/policies/simulate")
def simulate_policy(payload: PolicySimulationInput, _: Principal = Depends(current_principal)) -> dict:
    document = _parse_policy_http(payload.document)
    return evaluate([{"id": "simulation", "version": 1, "document": document}], payload.facts)


def _validate_scope(db: Session, principal: Principal, scope: str, scope_id: str | None) -> None:
    if scope == "organization":
        if scope_id and scope_id != principal.organization_id:
            raise HTTPException(status_code=422, detail="Organization scope ID does not match current tenant")
        return
    if not scope_id:
        raise HTTPException(status_code=422, detail=f"{scope} scope requires scope_id")
    model = {"workspace": Workspace, "team": Team, "agent": Agent, "tool": Tool}.get(scope)
    if model and not db.scalar(select(model.id).where(model.id == scope_id, model.organization_id == principal.organization_id)):
        raise HTTPException(status_code=422, detail=f"{scope} scope is outside the current tenant")


@router.get("/budgets")
def list_budgets(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> list[dict]:
    result = []
    for item in db.scalars(select(Budget).where(Budget.organization_id == principal.organization_id)).all():
        usage = db.scalar(select(BudgetUsage).where(BudgetUsage.budget_id == item.id).order_by(BudgetUsage.period_start.desc()).limit(1))
        result.append({field: getattr(item, field) for field in (
            "id", "name", "scope", "scope_id", "period", "limit_minor", "currency", "active", "created_at", "updated_at"
        )} | {"used_minor": usage.used_minor if usage else 0, "reserved_minor": usage.reserved_minor if usage else 0})
    return result


@router.post("/budgets", status_code=201)
def create_budget(payload: BudgetInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    _validate_scope(db, principal, payload.scope, payload.scope_id)
    item = Budget(organization_id=principal.organization_id, **payload.model_dump(), active=True)
    db.add(item)
    db.commit()
    return {field: getattr(item, field) for field in (
        "id", "name", "scope", "scope_id", "period", "limit_minor", "currency", "active", "created_at", "updated_at"
    )}


@router.get("/rate-limits")
def list_rate_limits(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> list[dict]:
    return [{field: getattr(item, field) for field in (
        "id", "scope", "scope_id", "window_seconds", "max_requests", "active", "created_at", "updated_at"
    )} for item in db.scalars(select(RateLimit).where(RateLimit.organization_id == principal.organization_id)).all()]


@router.post("/rate-limits", status_code=201)
def create_rate_limit(payload: RateLimitInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    _validate_scope(db, principal, payload.scope, payload.scope_id)
    item = RateLimit(organization_id=principal.organization_id, **payload.model_dump(), active=True)
    db.add(item)
    db.commit()
    return {field: getattr(item, field) for field in (
        "id", "scope", "scope_id", "window_seconds", "max_requests", "active", "created_at", "updated_at"
    )}


@router.get("/kill-switch")
def list_kill_switches(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> list[dict]:
    return [{field: getattr(item, field) for field in (
        "id", "scope", "scope_id", "active", "reason", "created_at", "updated_at"
    )} for item in db.scalars(select(KillSwitch).where(
        KillSwitch.organization_id == principal.organization_id
    ).order_by(KillSwitch.created_at.desc())).all()]


@router.post("/kill-switch", status_code=201)
def set_kill_switch(payload: KillSwitchInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    _validate_scope(db, principal, payload.scope, payload.scope_id)
    item = db.scalar(select(KillSwitch).where(
        KillSwitch.organization_id == principal.organization_id,
        KillSwitch.scope == payload.scope, KillSwitch.scope_id == payload.scope_id,
    ))
    if item:
        item.active, item.reason = payload.active, payload.reason
    else:
        item = KillSwitch(
            organization_id=principal.organization_id, scope=payload.scope, scope_id=payload.scope_id,
            active=payload.active, reason=payload.reason, created_by=_owner_id(db, principal),
        )
        db.add(item)
    append_audit(
        db, organization_id=principal.organization_id, user_id=_owner_id(db, principal), correlation_id=new_id(),
        event_type="kill_switch.changed", data={"scope": payload.scope, "scope_id": payload.scope_id,
                                                  "active": payload.active, "reason": payload.reason},
    )
    db.commit()
    return {field: getattr(item, field) for field in ("id", "scope", "scope_id", "active", "reason", "created_at", "updated_at")}


def _request_json(item: AuthorizationRequest) -> dict[str, Any]:
    return {field: getattr(item, field) for field in (
        "id", "agent_id", "tool_id", "correlation_id", "sanitized_arguments", "policy_id", "policy_version",
        "risk_score", "decision", "reason", "status", "approval_id", "result", "expires_at", "created_at", "completed_at",
    )}


def _approval_json(item: ApprovalRequest, request: AuthorizationRequest) -> dict[str, Any]:
    return {
        "id": item.id, "request_id": request.id, "agent_id": request.agent_id, "tool_id": request.tool_id,
        "arguments": request.sanitized_arguments, "risk_score": request.risk_score, "reason": request.reason,
        "mode": item.mode, "threshold": item.threshold, "state": item.state,
        "expires_at": item.expires_at, "created_at": item.created_at,
    }


@router.get("/requests")
def list_requests(
    status: str | None = None, limit: int = Query(50, ge=1, le=200),
    principal: Principal = Depends(current_principal), db: Session = Depends(get_db),
) -> list[dict]:
    statement = select(AuthorizationRequest).where(AuthorizationRequest.organization_id == principal.organization_id)
    if status:
        statement = statement.where(AuthorizationRequest.status == status)
    return [_request_json(item) for item in db.scalars(statement.order_by(
        AuthorizationRequest.created_at.desc()
    ).limit(limit)).all()]


@router.get("/approvals")
def list_approvals(
    state: str | None = None, limit: int = Query(100, ge=1, le=200),
    principal: Principal = Depends(current_principal), db: Session = Depends(get_db),
) -> list[dict]:
    statement = select(ApprovalRequest, AuthorizationRequest).join(
        AuthorizationRequest, AuthorizationRequest.id == ApprovalRequest.authorization_request_id
    ).where(ApprovalRequest.organization_id == principal.organization_id)
    if state:
        statement = statement.where(ApprovalRequest.state == state)
    return [_approval_json(approval, request) for approval, request in db.execute(
        statement.order_by(ApprovalRequest.created_at.desc()).limit(limit)
    ).all()]


def decide_approval(
    db: Session, approval: ApprovalRequest, request: AuthorizationRequest, user_id: str,
    role: str, decision_value: str, comment: str,
) -> dict:
    now = datetime.now(timezone.utc)
    if role not in approval.eligible_roles:
        raise HTTPException(status_code=403, detail="User is not an eligible approver")
    if approval.state != "pending" or request.status != "pending_approval":
        raise HTTPException(status_code=409, detail="Approval has already been resolved")
    if is_expired(approval.expires_at):
        approval.state, approval.resolved_at, request.status = "expired", now, "expired"
        settle_budget_reservations(db, request.id, False)
        db.commit()
        raise HTTPException(status_code=410, detail="Approval has expired")
    prior = db.scalar(select(ApprovalDecision).where(
        ApprovalDecision.approval_request_id == approval.id, ApprovalDecision.user_id == user_id
    ))
    if prior:
        raise HTTPException(status_code=409, detail="This approver has already decided")
    db.add(ApprovalDecision(
        organization_id=approval.organization_id, approval_request_id=approval.id, user_id=user_id,
        decision=decision_value, comment=comment,
    ))
    db.flush()
    decisions = db.scalars(select(ApprovalDecision).where(
        ApprovalDecision.approval_request_id == approval.id
    )).all()
    approvals = sum(item.decision == "approve" for item in decisions)
    rejects = sum(item.decision == "reject" for item in decisions)
    eligible_count = db.scalar(select(func.count(OrganizationMember.user_id)).where(
        OrganizationMember.organization_id == approval.organization_id,
        OrganizationMember.status == "active", OrganizationMember.role.in_(approval.eligible_roles),
    )) or 0
    threshold = eligible_count if approval.mode == "all" else approval.threshold
    resolved: str | None = None
    if approvals >= threshold:
        approval.state, request.status, resolved = "approved", "approved", "approved"
    elif rejects and (approval.mode in {"any", "all"} or eligible_count - rejects < threshold):
        approval.state, request.status, resolved = "rejected", "rejected", "rejected"
        settle_budget_reservations(db, request.id, False)
    if resolved:
        approval.resolved_at = now
    append_audit(
        db, organization_id=approval.organization_id, workspace_id=request.workspace_id, agent_id=request.agent_id,
        tool_id=request.tool_id, request_id=request.id, user_id=user_id, correlation_id=request.correlation_id,
        event_type="approval.decision", decision=decision_value,
        data={"approval_id": approval.id, "resolution": resolved, "comment": comment},
    )
    db.commit()
    return {"id": approval.id, "state": approval.state, "request_status": request.status,
            "approvals": approvals, "rejects": rejects, "threshold": threshold}


@router.post("/approvals/{approval_id}/decide")
def approval_decide(
    approval_id: str, payload: ApprovalDecisionInput,
    principal: Principal = Depends(require_roles("owner", "admin", "approver")), db: Session = Depends(get_db),
) -> dict:
    if principal.user_id is None:
        raise HTTPException(status_code=403, detail="Human approval requires a user session")
    approval = db.scalar(select(ApprovalRequest).where(
        ApprovalRequest.id == approval_id, ApprovalRequest.organization_id == principal.organization_id
    ).with_for_update())
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")
    request = db.scalar(select(AuthorizationRequest).where(
        AuthorizationRequest.id == approval.authorization_request_id,
        AuthorizationRequest.organization_id == principal.organization_id,
    ).with_for_update())
    return decide_approval(db, approval, request, principal.user_id, principal.role, payload.decision, payload.comment)


@router.get("/audit")
def list_audit(
    limit: int = Query(100, ge=1, le=500), decision: str | None = None,
    principal: Principal = Depends(current_principal), db: Session = Depends(get_db),
) -> list[dict]:
    statement = select(AuditEvent).where(AuditEvent.organization_id == principal.organization_id)
    if decision:
        statement = statement.where(AuditEvent.decision == decision)
    return [{field: getattr(item, field) for field in (
        "id", "workspace_id", "agent_id", "user_id", "tool_id", "request_id", "correlation_id", "event_type",
        "decision", "risk_score", "arguments_hash", "sanitized_data", "result", "latency_ms", "previous_hash",
        "event_hash", "occurred_at",
    )} for item in db.scalars(statement.order_by(AuditEvent.occurred_at.desc()).limit(limit)).all()]


@router.get("/audit/verify")
def audit_verify(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> dict:
    events = db.scalars(select(AuditEvent).where(
        AuditEvent.organization_id == principal.organization_id
    ).order_by(AuditEvent.occurred_at)).all()
    checkpoint = db.get(AuditCheckpoint, principal.organization_id)
    return {"valid": verify_audit_chain(list(events), checkpoint.archived_through_hash if checkpoint else None),
            "event_count": len(events), "checkpoint": checkpoint.archived_through_hash if checkpoint else None}


@router.get("/audit/export")
def export_audit(
    format: str = Query("json", pattern="^(json|csv)$"),
    principal: Principal = Depends(current_principal), db: Session = Depends(get_db),
) -> Response:
    events = list_audit(500, None, principal, db)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if format == "json":
        body = json.dumps(events, default=str, separators=(",", ":"))
        return Response(body, media_type="application/json", headers={
            "Content-Disposition": f'attachment; filename="agentguard-audit-{stamp}.json"'
        })
    output = io.StringIO()
    fields = list(events[0]) if events else ["id", "event_type", "occurred_at"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    for event in events:
        writer.writerow({key: json.dumps(value, default=str) if isinstance(value, (dict, list)) else value for key, value in event.items()})
    return Response(output.getvalue(), media_type="text/csv", headers={
        "Content-Disposition": f'attachment; filename="agentguard-audit-{stamp}.csv"'
    })


def _overview(db: Session, organization_id: str) -> dict[str, Any]:
    start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    active_agents = db.scalar(select(func.count(Agent.id)).where(
        Agent.organization_id == organization_id, Agent.status == "active", Agent.deleted_at.is_(None)
    )) or 0
    protected = db.scalar(select(func.count(AuthorizationRequest.id)).where(
        AuthorizationRequest.organization_id == organization_id, AuthorizationRequest.created_at >= start
    )) or 0
    blocked = db.scalar(select(func.count(AuthorizationRequest.id)).where(
        AuthorizationRequest.organization_id == organization_id,
        AuthorizationRequest.decision.in_(["deny", "rate_limited", "budget_exceeded", "agent_disabled"]),
        AuthorizationRequest.created_at >= start,
    )) or 0
    pending = db.scalar(select(func.count(ApprovalRequest.id)).where(
        ApprovalRequest.organization_id == organization_id, ApprovalRequest.state == "pending"
    )) or 0
    high_risk = db.scalar(select(func.count(AuthorizationRequest.id)).where(
        AuthorizationRequest.organization_id == organization_id, AuthorizationRequest.risk_score >= 70,
        AuthorizationRequest.created_at >= start,
    )) or 0
    spend = db.scalar(select(func.coalesce(func.sum(BudgetUsage.used_minor), 0)).where(
        BudgetUsage.organization_id == organization_id, BudgetUsage.period_start >= start
    )) or 0
    decision_rows = db.execute(select(AuthorizationRequest.decision, func.count(AuthorizationRequest.id)).where(
        AuthorizationRequest.organization_id == organization_id, AuthorizationRequest.created_at >= start
    ).group_by(AuthorizationRequest.decision)).all()
    policy_count = db.scalar(select(func.count(Policy.id)).where(
        Policy.organization_id == organization_id, Policy.enabled.is_(True)
    )) or 0
    active_kills = db.scalar(select(func.count(KillSwitch.id)).where(
        KillSwitch.organization_id == organization_id, KillSwitch.active.is_(True)
    )) or 0
    organization = db.get(Organization, organization_id)
    security_score = max(0, 100 - (30 if not policy_count else 0) - (10 if organization.dlp_action == "allow" else 0) - min(30, active_kills * 10))
    daily_rows = db.execute(select(
        func.date(AuthorizationRequest.created_at), func.count(AuthorizationRequest.id)
    ).where(
        AuthorizationRequest.organization_id == organization_id, AuthorizationRequest.created_at >= start
    ).group_by(func.date(AuthorizationRequest.created_at)).order_by(func.date(AuthorizationRequest.created_at))).all()
    return {
        "active_agents": int(active_agents), "protected_actions": int(protected), "blocked_actions": int(blocked),
        "pending_approvals": int(pending), "high_risk_actions": int(high_risk), "monthly_spend_minor": int(spend),
        "security_score": int(security_score), "decision_counts": {key: count for key, count in decision_rows},
        "daily_actions": [{"date": str(day), "count": count} for day, count in daily_rows],
    }


@router.get("/overview")
@router.get("/analytics")
def overview(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> dict:
    return _overview(db, principal.organization_id)


@router.get("/integrations")
def list_integrations(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> list[dict]:
    return [{field: getattr(item, field) for field in (
        "id", "provider", "name", "config", "secret_ref", "enabled", "created_at", "updated_at"
    )} for item in db.scalars(select(Integration).where(
        Integration.organization_id == principal.organization_id
    ).order_by(Integration.created_at.desc())).all()]


@router.post("/integrations", status_code=201)
def create_integration(payload: IntegrationInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    if any(str(key).lower() in {"secret", "password", "token", "api_key", "authorization", "private_key"} for key in payload.config):
        raise HTTPException(status_code=422, detail="Integration secrets must use a Key Vault secret_ref")
    if "url" in payload.config and payload.provider in {"http", "mcp", "webhook"}:
        _safe_url(str(payload.config["url"]), allowed_hosts=payload.config.get("allowed_hosts"))
    item = Integration(organization_id=principal.organization_id, **payload.model_dump(), enabled=True)
    db.add(item)
    db.commit()
    return {field: getattr(item, field) for field in (
        "id", "provider", "name", "config", "secret_ref", "enabled", "created_at", "updated_at"
    )}


@router.get("/webhooks")
def list_webhooks(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> list[dict]:
    return [{field: getattr(item, field) for field in (
        "id", "url", "events", "secret_ref", "active", "created_at", "updated_at"
    )} for item in db.scalars(select(Webhook).where(Webhook.organization_id == principal.organization_id)).all()]


@router.post("/webhooks", status_code=201)
def create_webhook(payload: WebhookInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    _safe_url(str(payload.url))
    item = Webhook(organization_id=principal.organization_id, url=str(payload.url), events=payload.events,
                   secret_ref=payload.secret_ref, active=True)
    db.add(item)
    db.commit()
    return {field: getattr(item, field) for field in (
        "id", "url", "events", "secret_ref", "active", "created_at", "updated_at"
    )}


@router.get("/api-keys")
def list_api_keys(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> list[dict]:
    return [{field: getattr(item, field) for field in (
        "id", "name", "key_prefix", "scopes", "expires_at", "revoked_at", "last_used_at", "created_at"
    )} for item in db.scalars(select(ApiKey).where(
        ApiKey.organization_id == principal.organization_id
    ).order_by(ApiKey.created_at.desc())).all()]


@router.post("/api-keys", status_code=201)
def create_api_key(payload: ApiKeyInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    key = ApiKey(
        organization_id=principal.organization_id, created_by=_owner_id(db, principal), name=payload.name,
        key_hash="pending", key_prefix="pending", scopes=payload.scopes,
        expires_at=utcnow() + timedelta(days=payload.expires_in_days) if payload.expires_in_days else None,
    )
    db.add(key)
    db.flush()
    raw, key_hash, prefix = make_admin_key(get_settings().environment, principal.organization_id, key.id)
    key.key_hash, key.key_prefix = key_hash, prefix
    db.commit()
    return {"api_key": raw, "key": {"id": key.id, "name": key.name, "key_prefix": prefix,
                                     "scopes": key.scopes, "expires_at": key.expires_at}}


@router.delete("/api-keys/{key_id}", status_code=204)
def revoke_api_key(key_id: str, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> Response:
    key = db.scalar(select(ApiKey).where(ApiKey.id == key_id, ApiKey.organization_id == principal.organization_id))
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    key.revoked_at = utcnow()
    db.commit()
    return Response(status_code=204)


@router.get("/settings")
def get_org_settings(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> dict:
    organization = db.get(Organization, principal.organization_id)
    return {"name": organization.name, "dlp_action": organization.dlp_action,
            "custom_dlp_patterns": organization.custom_dlp_patterns}


@router.patch("/settings")
def update_org_settings(payload: SettingsInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    organization = db.get(Organization, principal.organization_id)
    values = payload.model_dump(exclude_unset=True)
    if "custom_dlp_patterns" in values:
        validate_custom_patterns(values["custom_dlp_patterns"])
    for key, value in values.items():
        setattr(organization, key, value)
    db.commit()
    return {"name": organization.name, "dlp_action": organization.dlp_action,
            "custom_dlp_patterns": organization.custom_dlp_patterns}


def _billing_record(db: Session, organization_id: str) -> BillingSubscription:
    item = db.scalar(select(BillingSubscription).where(BillingSubscription.organization_id == organization_id))
    if not item:
        item = BillingSubscription(organization_id=organization_id, plan="free", status="active")
        db.add(item)
        db.flush()
    return item


@router.get("/billing")
def billing(principal: Principal = Depends(current_principal), db: Session = Depends(get_db)) -> dict:
    organization = db.get(Organization, principal.organization_id)
    item = _billing_record(db, principal.organization_id)
    start = datetime.now(timezone.utc).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    actions = db.scalar(select(func.coalesce(func.sum(UsageEvent.quantity), 0)).where(
        UsageEvent.organization_id == principal.organization_id, UsageEvent.kind == "protected_action",
        UsageEvent.occurred_at >= start,
    )) or 0
    db.commit()
    return {"plan": organization.plan, "status": item.status, "usage": {"protected_actions": int(actions)},
            "limits": PLAN_LIMITS.get(organization.plan, PLAN_LIMITS["free"]),
            "configured": bool(get_secret_store().get("stripe-secret-key", required=False))}


def _stripe_request(path: str, data: dict[str, Any]) -> dict[str, Any]:
    secret = get_secret_store().get("stripe-secret-key")
    response = httpx.post(
        f"https://api.stripe.com/v1/{path}", data=data, headers={"Authorization": f"Bearer {secret}"}, timeout=15,
    )
    if response.is_error:
        raise HTTPException(status_code=502, detail=f"Stripe returned HTTP {response.status_code}")
    return response.json()


@router.post("/billing/checkout")
def billing_checkout(payload: CheckoutInput, principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    item = _billing_record(db, principal.organization_id)
    if not item.provider_customer_id:
        organization = db.get(Organization, principal.organization_id)
        customer = _stripe_request("customers", {"name": organization.name, "metadata[organization_id]": organization.id})
        item.provider_customer_id = customer["id"]
        db.commit()
    price = get_secret_store().get(f"stripe-{payload.plan}-price-id")
    result = _stripe_request("checkout/sessions", {
        "mode": "subscription", "customer": item.provider_customer_id,
        "line_items[0][price]": price, "line_items[0][quantity]": 1,
        "success_url": f"{get_settings().web_url.rstrip('/')}/billing?checkout=success",
        "cancel_url": f"{get_settings().web_url.rstrip('/')}/billing?checkout=cancelled",
        "subscription_data[metadata][organization_id]": principal.organization_id,
        "metadata[organization_id]": principal.organization_id,
    })
    return {"url": result["url"]}


@router.post("/billing/portal")
def billing_portal(principal: Principal = Depends(admin), db: Session = Depends(get_db)) -> dict:
    item = _billing_record(db, principal.organization_id)
    if not item.provider_customer_id:
        raise HTTPException(status_code=409, detail="No billing customer exists yet")
    result = _stripe_request("billing_portal/sessions", {
        "customer": item.provider_customer_id,
        "return_url": f"{get_settings().web_url.rstrip('/')}/billing",
    })
    return {"url": result["url"]}
