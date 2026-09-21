from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from agentguard_shared import scan_and_redact

from .models import AuditCheckpoint, AuditEvent, Webhook, WebhookDelivery, new_id


def _json_default(value: Any) -> str:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, Decimal):
        return str(value)
    raise TypeError(f"Cannot serialize {type(value).__name__}")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=_json_default, allow_nan=False)


def hash_payload(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def append_audit(
    db: Session,
    *,
    organization_id: str,
    event_type: str,
    correlation_id: str,
    workspace_id: str | None = None,
    agent_id: str | None = None,
    user_id: str | None = None,
    tool_id: str | None = None,
    request_id: str | None = None,
    decision: str | None = None,
    risk_score: int | None = None,
    arguments_hash: str | None = None,
    data: dict[str, Any] | None = None,
    result: Any = None,
    latency_ms: float | None = None,
) -> AuditEvent:
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"audit:{organization_id}"})
    previous = db.scalar(
        select(AuditEvent).where(AuditEvent.organization_id == organization_id).order_by(AuditEvent.occurred_at.desc()).limit(1)
    )
    occurred_at = datetime.now(timezone.utc)
    event_id = new_id()
    sanitized_data = scan_and_redact(data or {})["sanitized"]
    sanitized_result = scan_and_redact(result)["sanitized"] if result is not None else None
    checkpoint = db.get(AuditCheckpoint, organization_id) if previous is None else None
    previous_hash = previous.event_hash if previous else (checkpoint.archived_through_hash if checkpoint else None)
    normalized_latency = Decimal(str(latency_ms)).quantize(Decimal("0.001")) if latency_ms is not None else None
    material = {
        "id": event_id,
        "organization_id": organization_id,
        "event_type": event_type,
        "correlation_id": correlation_id,
        "workspace_id": workspace_id,
        "agent_id": agent_id,
        "user_id": user_id,
        "tool_id": tool_id,
        "request_id": request_id,
        "decision": decision,
        "risk_score": risk_score,
        "arguments_hash": arguments_hash,
        "sanitized_data": sanitized_data,
        "result": sanitized_result,
        "latency_ms": str(normalized_latency) if normalized_latency is not None else None,
        "occurred_at": occurred_at,
        "previous_hash": previous_hash,
    }
    event_hash = hashlib.sha256(((previous_hash or "") + canonical_json(material)).encode()).hexdigest()
    event = AuditEvent(
        id=event_id,
        organization_id=organization_id,
        workspace_id=workspace_id,
        agent_id=agent_id,
        user_id=user_id,
        tool_id=tool_id,
        request_id=request_id,
        correlation_id=correlation_id,
        event_type=event_type,
        decision=decision,
        risk_score=risk_score,
        arguments_hash=arguments_hash,
        sanitized_data=sanitized_data,
        result=sanitized_result,
        latency_ms=normalized_latency,
        previous_hash=previous_hash,
        event_hash=event_hash,
        occurred_at=occurred_at,
    )
    db.add(event)
    db.flush()
    webhooks = db.scalars(select(Webhook).where(
        Webhook.organization_id == organization_id, Webhook.active.is_(True)
    )).all()
    for webhook in webhooks:
        if "*" in (webhook.events or []) or event_type in (webhook.events or []):
            db.add(WebhookDelivery(
                organization_id=organization_id, webhook_id=webhook.id, event_id=event.id,
                payload={"id": event.id, "type": event_type, "occurred_at": occurred_at.isoformat(),
                         "organization_id": organization_id, "request_id": request_id,
                         "decision": decision, "risk_score": risk_score, "data": sanitized_data,
                         "event_hash": event_hash},
            ))
    return event


def verify_audit_chain(events: list[AuditEvent], initial_hash: str | None = None) -> bool:
    previous_hash: str | None = initial_hash
    for event in sorted(events, key=lambda item: item.occurred_at):
        if event.previous_hash != previous_hash:
            return False
        material = {
            "id": event.id, "organization_id": event.organization_id, "event_type": event.event_type,
            "correlation_id": event.correlation_id, "workspace_id": event.workspace_id, "agent_id": event.agent_id,
            "user_id": event.user_id, "tool_id": event.tool_id, "request_id": event.request_id,
            "decision": event.decision, "risk_score": event.risk_score, "arguments_hash": event.arguments_hash,
            "sanitized_data": event.sanitized_data, "result": event.result,
            "latency_ms": str(event.latency_ms) if event.latency_ms is not None else None,
            "occurred_at": event.occurred_at, "previous_hash": event.previous_hash,
        }
        expected = hashlib.sha256(((previous_hash or "") + canonical_json(material)).encode()).hexdigest()
        if not __import__("hmac").compare_digest(expected, event.event_hash):
            return False
        previous_hash = event.event_hash
    return True
