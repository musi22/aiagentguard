from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException
from jsonschema import ValidationError, validate
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from agentguard_shared import scan_and_redact

from .audit import append_audit
from .authorization import _active_kill_reason, authenticate_agent, authorize, request_output, tool_snapshot
from .audit import hash_payload
from .config import get_settings
from .connectors import ConnectorError, execute_connector
from .database import get_db
from .limits import settle_budget_reservations
from .models import Agent, AgentCredential, AgentToolPermission, ApprovalRequest, AuthorizationRequest, Organization, Tool, utcnow
from .schemas import AuthorizationInput, ResultInput
from .security import digest_secret, get_payload_cipher, is_expired, random_token, verify_digest

router = APIRouter(prefix="/api/v1", tags=["runtime"])


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer agk_"):
        raise HTTPException(status_code=401, detail="Agent credential required")
    return authorization.split(" ", 1)[1]


def _owned_request(
    db: Session, request_id: str, raw_key: str,
    *, lock: bool = False,
) -> tuple[AuthorizationRequest, AgentCredential, Agent, Tool]:
    credential, agent = authenticate_agent(db, raw_key)
    statement = select(AuthorizationRequest).where(
        AuthorizationRequest.id == request_id,
        AuthorizationRequest.organization_id == agent.organization_id,
        AuthorizationRequest.agent_id == agent.id,
        AuthorizationRequest.credential_id == credential.id,
    )
    if lock:
        statement = statement.with_for_update()
    request = db.scalar(statement)
    if not request:
        raise HTTPException(status_code=404, detail="Request not found")
    tool = db.scalar(select(Tool).where(
        Tool.id == request.tool_id, Tool.organization_id == request.organization_id
    ))
    if not tool:
        raise HTTPException(status_code=409, detail="Request tool no longer exists")
    return request, credential, agent, tool


def _expire_if_needed(db: Session, item: AuthorizationRequest) -> None:
    if item.status == "pending_approval" and is_expired(item.expires_at):
        item.status = "expired"
        if item.approval_id:
            approval = db.scalar(select(ApprovalRequest).where(ApprovalRequest.id == item.approval_id))
            if approval and approval.state == "pending":
                approval.state, approval.resolved_at = "expired", utcnow()
        settle_budget_reservations(db, item.id, False)
        append_audit(
            db, organization_id=item.organization_id, workspace_id=item.workspace_id, agent_id=item.agent_id,
            tool_id=item.tool_id, request_id=item.id, correlation_id=item.correlation_id,
            event_type="approval.expired", decision="deny",
        )
        db.commit()


@router.post("/authorize")
def authorize_action(
    payload: AuthorizationInput, authorization: str | None = Header(default=None),
    x_correlation_id: str | None = Header(default=None, max_length=100), db: Session = Depends(get_db),
) -> dict[str, Any]:
    raw = _bearer(authorization)
    credential, agent = authenticate_agent(db, raw, payload.agent_id)
    item, _ = authorize(
        db, credential=credential, agent=agent, payload=payload, correlation_id=x_correlation_id or random_token(16)
    )
    return request_output(item)


def _finalize(
    db: Session, request: AuthorizationRequest, organization: Organization, *, status: str, result: Any,
    budget_succeeded: bool | None = None,
) -> dict[str, Any]:
    sanitized = scan_and_redact(result, organization.custom_dlp_patterns)["sanitized"]
    request.result = sanitized
    request.status = status
    request.completed_at = utcnow()
    request.execution_claim_hash = None
    request.claim_expires_at = None
    request.encrypted_payload = None
    settle_budget_reservations(db, request.id, True if status == "succeeded" else budget_succeeded)
    append_audit(
        db, organization_id=request.organization_id, workspace_id=request.workspace_id, agent_id=request.agent_id,
        tool_id=request.tool_id, request_id=request.id, correlation_id=request.correlation_id,
        event_type="tool.execution", decision=request.decision, risk_score=request.risk_score,
        arguments_hash=request.arguments_hash, result=sanitized, data={"status": status},
    )
    db.commit()
    db.refresh(request)
    return request_output(request)


def _check_execution_allowed(db: Session, request: AuthorizationRequest, tool: Tool) -> None:
    agent = db.get(Agent, request.agent_id)
    credential = db.get(AgentCredential, request.credential_id)
    organization = db.get(Organization, request.organization_id)
    permission = db.scalar(select(AgentToolPermission).where(
        AgentToolPermission.organization_id == request.organization_id,
        AgentToolPermission.agent_id == request.agent_id, AgentToolPermission.tool_id == tool.id,
    ))
    if (
        not organization or not organization.active or not agent or agent.status != "active" or tool.disabled
        or not credential or credential.revoked_at or is_expired(credential.expires_at)
        or credential.environment != agent.environment or tool.environment != agent.environment
        or (credential.scopes and tool.name not in credential.scopes and "*" not in credential.scopes)
        or (permission and not permission.allowed) or _active_kill_reason(db, agent, tool)
    ):
        request.status, request.reason = "agent_disabled", "Execution blocked by current emergency or access controls"
        settle_budget_reservations(db, request.id, False)
        append_audit(db, organization_id=request.organization_id, request_id=request.id,
                     agent_id=request.agent_id, tool_id=tool.id, event_type="tool.execution_blocked",
                     correlation_id=request.correlation_id,
                     decision="agent_disabled", data={"reason": request.reason})
        db.commit()
        raise HTTPException(status_code=403, detail=request.reason)


def _execute_remote(db: Session, request: AuthorizationRequest, tool: Tool) -> dict[str, Any]:
    if tool.adapter == "sdk":
        raise HTTPException(status_code=409, detail="SDK tools must be claimed and executed in the agent process")
    if request.status not in {"authorized", "approved"}:
        return request_output(request)
    _check_execution_allowed(db, request, tool)
    if is_expired(request.expires_at):
        request.status = "expired"
        settle_budget_reservations(db, request.id, False)
        db.commit()
        return request_output(request)
    if not request.encrypted_payload:
        raise HTTPException(status_code=409, detail="Executable payload is unavailable")
    payload = get_payload_cipher().decrypt(request.encrypted_payload)
    if payload.get("tool_snapshot_hash") != hash_payload(tool_snapshot(tool)):
        request.status, request.reason = "failed", "Tool configuration changed after authorization"
        settle_budget_reservations(db, request.id, False)
        db.commit()
        raise HTTPException(status_code=409, detail=request.reason)
    changed = db.execute(
        update(AuthorizationRequest).where(
            AuthorizationRequest.id == request.id,
            AuthorizationRequest.status.in_(["authorized", "approved"]),
        ).values(status="executing", started_at=utcnow())
    )
    if changed.rowcount != 1:
        db.rollback()
        db.refresh(request)
        return request_output(request)
    db.commit()  # durable compare-and-set occurs before the non-idempotent provider call
    db.refresh(request)
    organization = db.get(Organization, request.organization_id)
    try:
        outcome = execute_connector(tool, request, payload["arguments"])
        if tool.output_schema:
            validate(instance=outcome.result, schema=tool.output_schema)
        return _finalize(db, request, organization, status="succeeded", result=outcome.result)
    except (ConnectorError, ValidationError) as exc:
        return _finalize(db, request, organization, status="failed", result={"error": str(exc)[:1000]})


@router.post("/execute")
def authorize_and_execute(
    payload: AuthorizationInput, authorization: str | None = Header(default=None),
    x_correlation_id: str | None = Header(default=None, max_length=100), db: Session = Depends(get_db),
) -> dict[str, Any]:
    raw = _bearer(authorization)
    credential, agent = authenticate_agent(db, raw, payload.agent_id)
    item, tool = authorize(
        db, credential=credential, agent=agent, payload=payload, correlation_id=x_correlation_id or random_token(16)
    )
    return _execute_remote(db, item, tool) if item.status in {"authorized", "approved"} else request_output(item)


@router.get("/requests/{request_id}")
def request_status(
    request_id: str, authorization: str | None = Header(default=None), db: Session = Depends(get_db),
) -> dict[str, Any]:
    item, _, _, _ = _owned_request(db, request_id, _bearer(authorization), lock=True)
    _expire_if_needed(db, item)
    return request_output(item)


@router.post("/requests/{request_id}/execute")
def execute_approved_request(
    request_id: str, authorization: str | None = Header(default=None), db: Session = Depends(get_db),
) -> dict[str, Any]:
    item, _, _, tool = _owned_request(db, request_id, _bearer(authorization), lock=True)
    _expire_if_needed(db, item)
    return _execute_remote(db, item, tool)


@router.post("/requests/{request_id}/claim")
def claim_sdk_request(
    request_id: str, authorization: str | None = Header(default=None), db: Session = Depends(get_db),
) -> dict[str, Any]:
    item, _, _, tool = _owned_request(db, request_id, _bearer(authorization), lock=True)
    _expire_if_needed(db, item)
    if tool.adapter != "sdk":
        raise HTTPException(status_code=409, detail="Only SDK tools can be claimed by an agent process")
    if item.status not in {"authorized", "approved"}:
        raise HTTPException(status_code=409, detail=f"Request cannot be claimed from state {item.status}")
    _check_execution_allowed(db, item, tool)
    if is_expired(item.expires_at) or not item.encrypted_payload:
        raise HTTPException(status_code=410, detail="Request has expired")
    frozen = get_payload_cipher().decrypt(item.encrypted_payload)
    if frozen.get("tool_snapshot_hash") != hash_payload(tool_snapshot(tool)):
        item.status, item.reason = "failed", "Tool configuration changed after authorization"
        settle_budget_reservations(db, item.id, False)
        db.commit()
        raise HTTPException(status_code=409, detail=item.reason)
    claim_token = random_token(32)
    claim_expires_at = datetime.now(timezone.utc) + timedelta(seconds=get_settings().execution_claim_ttl_seconds)
    started_at = utcnow()
    changed = db.execute(update(AuthorizationRequest).where(
        AuthorizationRequest.id == item.id,
        AuthorizationRequest.status.in_(["authorized", "approved"]),
    ).values(
        execution_claim_hash=digest_secret(claim_token), claim_expires_at=claim_expires_at,
        status="executing", started_at=started_at,
    ))
    if changed.rowcount != 1:
        db.rollback()
        raise HTTPException(status_code=409, detail="Request was already claimed")
    item.execution_claim_hash = digest_secret(claim_token)
    item.claim_expires_at = claim_expires_at
    item.status, item.started_at = "executing", started_at
    append_audit(
        db, organization_id=item.organization_id, workspace_id=item.workspace_id, agent_id=item.agent_id,
        tool_id=item.tool_id, request_id=item.id, correlation_id=item.correlation_id,
        event_type="tool.execution_claimed", decision=item.decision,
    )
    db.commit()
    return {"claim_token": claim_token, "arguments": frozen["arguments"], "context": frozen.get("context", {})}


@router.post("/requests/{request_id}/result")
def report_sdk_result(
    request_id: str, payload: ResultInput, authorization: str | None = Header(default=None),
    x_agentguard_claim: str | None = Header(default=None), db: Session = Depends(get_db),
) -> dict[str, Any]:
    item, _, _, tool = _owned_request(db, request_id, _bearer(authorization), lock=True)
    if (
        item.status != "executing" or not item.execution_claim_hash or not x_agentguard_claim
        or not verify_digest(x_agentguard_claim, item.execution_claim_hash)
    ):
        raise HTTPException(status_code=409, detail="Execution claim is invalid or already consumed")
    if is_expired(item.claim_expires_at):
        item.status = "failed"
        item.execution_claim_hash = None
        settle_budget_reservations(db, item.id, None)
        db.commit()
        raise HTTPException(status_code=410, detail="Execution claim expired")
    result = payload.result if payload.error is None else {"error": payload.error}
    if payload.status == "succeeded" and tool.output_schema:
        try:
            validate(instance=result, schema=tool.output_schema)
        except ValidationError as exc:
            payload.status = "failed"
            result = {"error": f"Tool result did not match output schema: {exc.message}"}
    organization = db.get(Organization, item.organization_id)
    return _finalize(db, item, organization, status=payload.status, result=result)
