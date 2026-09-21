from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import HTTPException
from jsonschema import SchemaError, ValidationError, validate
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from agentguard_policy import evaluate
from agentguard_risk import score
from agentguard_shared import scan_and_redact

from .audit import append_audit, hash_payload
from .config import get_settings
from .limits import acquire_rate_limits, action_quota_available, amount_to_minor, reserve_budgets
from .models import (
    Agent, AgentCredential, AgentToolPermission, ApprovalRequest, AuthorizationRequest, KillSwitch,
    Notification, Organization, Policy, PolicyVersion, Tool, UsageEvent, utcnow,
)
from .schemas import AuthorizationInput
from .security import api_key_pepper, get_payload_cipher, is_expired, parse_machine_key, verify_digest


def _to_dict(item: Any, fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: getattr(item, field) for field in fields}


def tool_snapshot(tool: Tool) -> dict[str, Any]:
    return {key: getattr(tool, key) for key in (
        "id", "name", "provider", "adapter", "config", "environment", "input_schema", "output_schema"
    )}


def authenticate_agent(db: Session, raw_key: str, claimed_agent_id: str | None = None) -> tuple[AgentCredential, Agent]:
    parsed = parse_machine_key(raw_key)
    if not parsed:
        raise HTTPException(status_code=401, detail="Invalid agent credential")
    organization_id, credential_id, environment = parsed
    from .database import set_tenant_context

    set_tenant_context(db, organization_id)
    credential = db.scalar(
        select(AgentCredential).where(
            AgentCredential.id == credential_id, AgentCredential.organization_id == organization_id
        )
    )
    if (
        not credential or credential.revoked_at or is_expired(credential.expires_at)
        or credential.environment != environment
        or not verify_digest(raw_key, credential.key_hash, api_key_pepper())
    ):
        raise HTTPException(status_code=401, detail="Invalid agent credential")
    agent = db.scalar(select(Agent).where(Agent.id == credential.agent_id, Agent.organization_id == organization_id))
    if not agent or (claimed_agent_id and claimed_agent_id != agent.id):
        raise HTTPException(status_code=401, detail="Invalid agent credential")
    organization = db.get(Organization, organization_id)
    if not organization or not organization.active:
        raise HTTPException(status_code=403, detail="Organization is inactive")
    credential.last_used_at = utcnow()
    agent.last_seen_at = utcnow()
    return credential, agent


def _active_kill_reason(db: Session, agent: Agent, tool: Tool | None) -> str | None:
    switches = db.scalars(
        select(KillSwitch).where(KillSwitch.organization_id == agent.organization_id, KillSwitch.active.is_(True))
    ).all()
    expected = {
        "organization": agent.organization_id,
        "workspace": agent.workspace_id,
        "team": agent.team_id,
        "agent": agent.id,
        "tool": tool.id if tool else None,
        "environment": agent.environment,
    }
    for switch in switches:
        if switch.scope == "organization" or (switch.scope in expected and expected[switch.scope] == switch.scope_id):
            return switch.reason
    return None


def _current_policies(db: Session, organization_id: str, workspace_id: str) -> list[dict[str, Any]]:
    policies = db.scalars(
        select(Policy).where(
            Policy.organization_id == organization_id,
            Policy.enabled.is_(True),
            (Policy.workspace_id.is_(None) | (Policy.workspace_id == workspace_id)),
        )
    ).all()
    result: list[dict[str, Any]] = []
    for policy in policies:
        version = db.scalar(
            select(PolicyVersion).where(
                PolicyVersion.policy_id == policy.id, PolicyVersion.version == policy.current_version
            )
        )
        if version:
            result.append({
                "id": policy.id, "version": version.version, "priority": policy.priority,
                "enabled": policy.enabled, "document": version.document,
            })
    return result


def _history(db: Session, agent: Agent, tool: Tool) -> dict[str, Any]:
    tool_uses = db.scalar(
        select(func.count(AuthorizationRequest.id)).where(
            AuthorizationRequest.organization_id == agent.organization_id,
            AuthorizationRequest.agent_id == agent.id,
            AuthorizationRequest.tool_id == tool.id,
        )
    ) or 0
    agent_uses = db.scalar(
        select(func.count(AuthorizationRequest.id)).where(
            AuthorizationRequest.organization_id == agent.organization_id, AuthorizationRequest.agent_id == agent.id
        )
    ) or 0
    recent_since = datetime.now(timezone.utc) - timedelta(minutes=1)
    recent = db.scalar(
        select(func.count(AuthorizationRequest.id)).where(
            AuthorizationRequest.organization_id == agent.organization_id,
            AuthorizationRequest.agent_id == agent.id,
            AuthorizationRequest.created_at >= recent_since,
        )
    ) or 0
    return {"tool_uses": int(tool_uses), "agent_uses": int(agent_uses), "recent_requests": int(recent)}


def request_output(request: AuthorizationRequest) -> dict[str, Any]:
    decision = request.decision
    if request.status in {"approved", "authorized", "executing", "succeeded"} and decision == "require_approval":
        decision = "allow"
    if request.status in {"rejected", "expired", "failed"} and decision == "require_approval":
        decision = "deny"
    return {
        "decision": decision,
        "request_id": request.id,
        "approval_id": request.approval_id,
        "risk_score": request.risk_score,
        "approval_required": request.decision == "require_approval" and request.status == "pending_approval",
        "reason": request.reason,
        "status": request.status,
        "result": request.result,
    }


def authorize(
    db: Session,
    *,
    credential: AgentCredential,
    agent: Agent,
    payload: AuthorizationInput,
    correlation_id: str,
) -> tuple[AuthorizationRequest, Tool]:
    started = time.perf_counter()
    if payload.idempotency_key:
        previous = db.scalar(
            select(AuthorizationRequest).where(
                AuthorizationRequest.organization_id == agent.organization_id,
                AuthorizationRequest.agent_id == agent.id,
                AuthorizationRequest.idempotency_key == payload.idempotency_key,
            )
        )
        if previous:
            if previous.credential_id != credential.id:
                raise HTTPException(status_code=409, detail="Idempotency key belongs to another credential")
            tool = db.get(Tool, previous.tool_id)
            if tool is None:
                raise HTTPException(status_code=409, detail="Idempotent request references a deleted tool")
            if tool.name != payload.tool or previous.arguments_hash != hash_payload(payload.arguments):
                raise HTTPException(status_code=409, detail="Idempotency key cannot be reused with different arguments or tool")
            return previous, tool

    tool = db.scalar(
        select(Tool).where(
            Tool.organization_id == agent.organization_id,
            Tool.name == payload.tool,
            Tool.environment == agent.environment,
        )
    )
    if tool is None:
        raise HTTPException(status_code=404, detail="Tool is not registered for this agent environment")
    if credential.scopes and tool.name not in credential.scopes and "*" not in credential.scopes:
        permission_denied = "Credential is not scoped to this tool"
    else:
        permission = db.scalar(
            select(AgentToolPermission).where(
                AgentToolPermission.organization_id == agent.organization_id,
                AgentToolPermission.agent_id == agent.id,
                AgentToolPermission.tool_id == tool.id,
            )
        )
        permission_denied = "Agent-to-tool permission is disabled" if permission and not permission.allowed else None

    if tool.input_schema:
        try:
            validate(instance=payload.arguments, schema=tool.input_schema)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=f"Tool arguments do not match schema: {exc.message}") from exc
        except SchemaError as exc:
            raise HTTPException(status_code=503, detail="Registered tool schema is invalid") from exc

    organization = db.get(Organization, agent.organization_id)
    if not organization or not organization.active:
        raise HTTPException(status_code=401, detail="Organization is inactive")
    dlp = scan_and_redact(payload.arguments, organization.custom_dlp_patterns)
    amount_minor = amount_to_minor(payload.arguments, required=tool.financial)
    trusted_amount = amount_minor / 100
    currency = str(payload.arguments.get("currency") or tool.config.get("currency") or "USD").upper()
    if len(currency) != 3 or not currency.isalpha():
        raise HTTPException(status_code=422, detail="Currency must be a three-letter code")
    trusted_context = {
        "amount": trusted_amount,
        "currency": currency,
        "arguments": {"amount": trusted_amount},
        "destination": payload.context.get("destination"),
    }
    history = _history(db, agent, tool)
    risk = score(
        _to_dict(tool, ("financial", "destructive", "read_write_classification", "sensitive_data", "environment")),
        _to_dict(agent, ("environment", "risk_level")), trusted_context, history,
    )
    facts = {
        "organization": organization.name,
        "organization_id": organization.id,
        "workspace_id": agent.workspace_id,
        "team_id": agent.team_id,
        "agent": agent.name,
        "agent_id": agent.id,
        "tool": tool.name,
        "tool_id": tool.id,
        "provider": tool.provider,
        "amount": trusted_amount,
        "environment": agent.environment,
        "resource": payload.context.get("resource"),
        "customer": payload.arguments.get("customer_id"),
        "customer_id": payload.arguments.get("customer_id"),
        "ip": payload.context.get("ip"),
        "tags": tool.tags,
        "risk_score": risk["score"],
        "data_classification": "sensitive" if tool.sensitive_data or dlp["findings"] else "normal",
        "request_count": history.get("recent_requests", 0),
        "destination": trusted_context.get("destination"),
    }
    policy = evaluate(_current_policies(db, agent.organization_id, agent.workspace_id), facts)
    decision, reason = policy["decision"], policy["reason"]
    kill_reason = _active_kill_reason(db, agent, tool)
    if agent.status != "active" or kill_reason:
        decision = "agent_disabled"
        reason = kill_reason or f"Agent is {agent.status}"
    elif tool.disabled:
        decision, reason = "agent_disabled", "Tool is disabled"
    elif permission_denied:
        decision, reason = "deny", permission_denied
    elif payload.context.get("environment") and payload.context["environment"] != agent.environment:
        decision, reason = "deny", "Caller environment does not match credential-bound agent environment"
    elif dlp["findings"] and organization.dlp_action == "block":
        decision, reason = "deny", "DLP policy blocked sensitive content"
    elif dlp["findings"] and organization.dlp_action == "approval" and decision == "allow":
        decision, reason = "require_approval", "DLP policy requires human approval for sensitive content"

    execute_arguments = payload.arguments
    obligations = policy.get("obligations", [])
    if (dlp["findings"] and organization.dlp_action == "redact") or any(
        item.get("action") == "redact" for item in obligations
    ):
        execute_arguments = dlp["sanitized"]

    request = AuthorizationRequest(
        organization_id=agent.organization_id,
        workspace_id=agent.workspace_id,
        agent_id=agent.id,
        tool_id=tool.id,
        credential_id=credential.id,
        correlation_id=correlation_id,
        idempotency_key=payload.idempotency_key,
        arguments_hash=hash_payload(payload.arguments),
        sanitized_arguments=dlp["sanitized"],
        encrypted_payload=get_payload_cipher().encrypt({
            "arguments": execute_arguments,
            "context": scan_and_redact(payload.context, organization.custom_dlp_patterns)["sanitized"],
            "tool_snapshot_hash": hash_payload(tool_snapshot(tool)),
        }),
        policy_id=policy.get("policy_id"),
        policy_version=policy.get("policy_version"),
        risk_score=int(risk["score"]),
        decision="evaluating",
        reason="Evaluation in progress",
        status="evaluating",
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=get_settings().authorization_ttl_seconds),
    )
    db.add(request)
    db.flush()

    if decision in {"allow", "require_approval"}:
        rate_ok, rate_reason = acquire_rate_limits(db, agent.organization_id, facts)
        if not rate_ok:
            decision, reason = "rate_limited", rate_reason or "Rate limit exceeded"
        elif not action_quota_available(db, agent.organization_id, organization.plan):
            decision, reason = "budget_exceeded", "Subscription protected-action limit reached"
        else:
            budget_ok, budget_reason = reserve_budgets(
                db, agent.organization_id, facts, request.id, amount_minor
            )
            if not budget_ok:
                decision, reason = "budget_exceeded", budget_reason or "Budget exceeded"

    request.decision = decision
    request.reason = reason
    request.status = {
        "allow": "authorized", "require_approval": "pending_approval", "deny": "denied",
        "rate_limited": "rate_limited", "budget_exceeded": "budget_exceeded", "agent_disabled": "agent_disabled",
    }.get(decision, "denied")
    if decision == "require_approval":
        approval = ApprovalRequest(
            organization_id=agent.organization_id,
            authorization_request_id=request.id,
            mode="any",
            threshold=1,
            eligible_roles=["owner", "admin", "approver"],
            state="pending",
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=get_settings().approval_ttl_seconds),
        )
        db.add(approval)
        db.flush()
        request.approval_id = approval.id
        db.add(Notification(
            organization_id=agent.organization_id, channel="approval", title=f"Approval required: {tool.name}",
            body=json.dumps({"approval_id": approval.id, "request_id": request.id}, separators=(",", ":")),
        ))
    db.add(UsageEvent(
        organization_id=agent.organization_id, kind="protected_action", quantity=1, request_id=request.id
    ))
    append_audit(
        db, organization_id=agent.organization_id, workspace_id=agent.workspace_id, agent_id=agent.id,
        tool_id=tool.id, request_id=request.id, correlation_id=correlation_id,
        event_type="authorization.decision", decision=decision, risk_score=request.risk_score,
        arguments_hash=request.arguments_hash,
        data={"reason": reason, "policy_id": request.policy_id, "policy_version": request.policy_version,
              "risk_factors": risk["factors"], "dlp_findings": dlp["findings"], "obligations": obligations,
              "approval_id": request.approval_id},
        latency_ms=(time.perf_counter() - started) * 1000,
    )
    db.commit()
    db.refresh(request)
    return request, tool
