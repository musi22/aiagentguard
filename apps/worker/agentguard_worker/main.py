from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import httpx
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from agentguard_api.audit import append_audit
from agentguard_api.config import configure_logging, get_settings
from agentguard_api.connectors import _safe_url
from agentguard_api.database import SessionLocal, set_tenant_context
from agentguard_api.limits import PLAN_LIMITS, settle_budget_reservations
from agentguard_api.models import (
    Agent, ApprovalRequest, AuditCheckpoint, AuditEvent, AuthorizationRequest, Integration, Notification, Organization,
    Tool, Webhook, WebhookDelivery,
)
from agentguard_api.security import get_secret_store

logger = logging.getLogger("agentguard.worker")
settings = get_settings()
configure_logging(settings)


def expire_stale(db: Session) -> int:
    now = datetime.now(timezone.utc)
    count = 0
    approvals = db.scalars(select(ApprovalRequest).where(
        ApprovalRequest.state == "pending", ApprovalRequest.expires_at <= now
    ).limit(settings.worker_batch_size)).all()
    for approval in approvals:
        set_tenant_context(db, approval.organization_id)
        request = db.scalar(select(AuthorizationRequest).where(
            AuthorizationRequest.id == approval.authorization_request_id,
            AuthorizationRequest.organization_id == approval.organization_id,
        ).with_for_update())
        if request and request.status == "pending_approval":
            approval.state, approval.resolved_at, request.status = "expired", now, "expired"
            settle_budget_reservations(db, request.id, False)
            append_audit(
                db, organization_id=request.organization_id, workspace_id=request.workspace_id,
                agent_id=request.agent_id, tool_id=request.tool_id, request_id=request.id,
                correlation_id=request.correlation_id, event_type="approval.expired", decision="deny",
            )
            count += 1
    claims = db.scalars(select(AuthorizationRequest).where(
        AuthorizationRequest.status == "executing", AuthorizationRequest.claim_expires_at.is_not(None),
        AuthorizationRequest.claim_expires_at <= now,
    ).limit(settings.worker_batch_size)).all()
    for request in claims:
        set_tenant_context(db, request.organization_id)
        request.status, request.execution_claim_hash, request.claim_expires_at = "failed", None, None
        settle_budget_reservations(db, request.id, None)
        append_audit(
            db, organization_id=request.organization_id, workspace_id=request.workspace_id,
            agent_id=request.agent_id, tool_id=request.tool_id, request_id=request.id,
            correlation_id=request.correlation_id, event_type="tool.execution_claim_expired", decision="deny",
        )
        count += 1
    db.commit()
    return count


def _approval_message(db: Session, request: AuthorizationRequest) -> dict:
    agent, tool = db.get(Agent, request.agent_id), db.get(Tool, request.tool_id)
    amount = request.sanitized_arguments.get("amount") if isinstance(request.sanitized_arguments, dict) else None
    text = f"{agent.name} requests {tool.name}. Risk {request.risk_score}/100."
    fields = [
        {"type": "mrkdwn", "text": f"*Agent*\n{agent.name}"},
        {"type": "mrkdwn", "text": f"*Tool*\n{tool.name}"},
        {"type": "mrkdwn", "text": f"*Risk*\n{request.risk_score} / 100"},
        {"type": "mrkdwn", "text": f"*Amount*\n{amount if amount is not None else 'N/A'}"},
    ]
    return {"text": text, "blocks": [
        {"type": "header", "text": {"type": "plain_text", "text": "AgentGuard approval required"}},
        {"type": "section", "fields": fields},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Reason*\n{request.reason}"}},
        {"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": "Approve"}, "style": "primary",
             "value": f"{request.organization_id}:approve:{request.approval_id}", "action_id": "agentguard_approve"},
            {"type": "button", "text": {"type": "plain_text", "text": "Reject"}, "style": "danger",
             "value": f"{request.organization_id}:reject:{request.approval_id}", "action_id": "agentguard_reject"},
        ]},
    ]}


def send_notifications(db: Session) -> int:
    sent = 0
    notifications = db.scalars(select(Notification).where(
        Notification.state == "pending"
    ).order_by(Notification.created_at).limit(settings.worker_batch_size)).all()
    for notification in notifications:
        set_tenant_context(db, notification.organization_id)
        try:
            identifiers = json.loads(notification.body)
            request = db.scalar(select(AuthorizationRequest).where(
                AuthorizationRequest.id == identifiers["request_id"],
                AuthorizationRequest.organization_id == notification.organization_id,
            ))
            integrations = db.scalars(select(Integration).where(
                Integration.organization_id == notification.organization_id, Integration.enabled.is_(True),
                Integration.provider.in_(["slack", "email"]),
            )).all()
            if not integrations:
                continue
            for integration in integrations:
                if integration.provider == "slack":
                    payload = _approval_message(db, request)
                    payload["channel"] = integration.config["channel_id"]
                    secret = get_secret_store().get(integration.secret_ref or "slack-bot-token")
                    response = httpx.post(
                        "https://slack.com/api/chat.postMessage", json=payload,
                        headers={"Authorization": f"Bearer {secret}"}, timeout=10,
                    )
                    response.raise_for_status()
                    if not response.json().get("ok"):
                        raise RuntimeError("Slack rejected approval notification")
                else:
                    url = _safe_url(str(integration.config["url"]))
                    secret = get_secret_store().get(integration.secret_ref or "approval-email-secret")
                    response = httpx.post(
                        url, json={"template": "agentguard_approval", "request": _approval_message(db, request)["text"],
                                   "approval_id": request.approval_id},
                        headers={"Authorization": f"Bearer {secret}"}, timeout=10, follow_redirects=False,
                    )
                    response.raise_for_status()
            notification.state = "sent"
            sent += 1
        except Exception as exc:
            logger.warning("notification delivery failed id=%s type=%s", notification.id, type(exc).__name__)
    db.commit()
    return sent


def deliver_webhooks(db: Session) -> int:
    now = datetime.now(timezone.utc)
    delivered = 0
    items = db.scalars(select(WebhookDelivery).where(
        WebhookDelivery.state == "pending", WebhookDelivery.next_attempt_at <= now
    ).order_by(WebhookDelivery.next_attempt_at).limit(settings.worker_batch_size)).all()
    for delivery in items:
        set_tenant_context(db, delivery.organization_id)
        webhook = db.scalar(select(Webhook).where(
            Webhook.id == delivery.webhook_id, Webhook.organization_id == delivery.organization_id,
            Webhook.active.is_(True),
        ))
        if not webhook:
            delivery.state = "failed"
            continue
        body = json.dumps(delivery.payload, sort_keys=True, separators=(",", ":")).encode()
        try:
            url = _safe_url(webhook.url)
            secret = get_secret_store().get(webhook.secret_ref)
            timestamp = str(int(now.timestamp()))
            signature = hmac.new(str(secret).encode(), timestamp.encode() + b"." + body, hashlib.sha256).hexdigest()
            response = httpx.post(
                url, content=body, headers={"Content-Type": "application/json", "X-AgentGuard-Timestamp": timestamp,
                                             "X-AgentGuard-Signature": f"v1={signature}",
                                             "Idempotency-Key": delivery.id},
                timeout=10, follow_redirects=False,
            )
            delivery.response_status = response.status_code
            response.raise_for_status()
            delivery.state = "delivered"
            delivered += 1
        except Exception as exc:
            delivery.attempts += 1
            if delivery.attempts >= 10:
                delivery.state = "failed"
            else:
                delivery.next_attempt_at = now + timedelta(seconds=min(3600, 2 ** delivery.attempts * 10))
            logger.warning("webhook delivery failed id=%s type=%s", delivery.id, type(exc).__name__)
    db.commit()
    return delivered


def archive_audit(db: Session) -> int:
    if not settings.audit_storage_account_url:
        return 0
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobServiceClient

    organizations = db.scalars(select(Organization)).all()
    archived = 0
    service = BlobServiceClient(
        account_url=settings.audit_storage_account_url,
        credential=DefaultAzureCredential(managed_identity_client_id=settings.azure_client_id),
    )
    container = service.get_container_client(settings.archive_container)
    try:
        container.create_container()
    except Exception as exc:
        logger.debug("audit archive container already exists or was not creatable: %s", type(exc).__name__)
    for organization in organizations:
        retention = PLAN_LIMITS.get(organization.plan, PLAN_LIMITS["free"])["retention_days"]
        cutoff = datetime.now(timezone.utc) - timedelta(days=retention)
        events = db.scalars(select(AuditEvent).where(
            AuditEvent.organization_id == organization.id, AuditEvent.occurred_at < cutoff
        ).order_by(AuditEvent.occurred_at).limit(settings.worker_batch_size)).all()
        if not events:
            continue
        lines = "\n".join(json.dumps({column.name: getattr(event, column.name) for column in AuditEvent.__table__.columns}, default=str,
                                     sort_keys=True, separators=(",", ":")) for event in events) + "\n"
        name = f"{organization.id}/{datetime.now(timezone.utc):%Y/%m/%d}/{uuid4()}.jsonl"
        container.upload_blob(name=name, data=lines.encode(), overwrite=False)
        checkpoint = db.get(AuditCheckpoint, organization.id)
        if checkpoint:
            checkpoint.archived_through_hash = events[-1].event_hash
            checkpoint.archived_through_at = events[-1].occurred_at
            checkpoint.archive_blob = name
        else:
            db.add(AuditCheckpoint(
                organization_id=organization.id, archived_through_hash=events[-1].event_hash,
                archived_through_at=events[-1].occurred_at, archive_blob=name,
            ))
        ids = [event.id for event in events]
        db.execute(delete(AuditEvent).where(AuditEvent.id.in_(ids), AuditEvent.organization_id == organization.id))
        db.commit()
        archived += len(ids)
    return archived


def process_once() -> dict[str, int]:
    with SessionLocal() as db:
        expired = expire_stale(db)
        notifications = send_notifications(db)
        webhooks = deliver_webhooks(db)
        archived = archive_audit(db)
    return {"expired": expired, "notifications": notifications, "webhooks": webhooks, "archived": archived}


def main() -> None:
    once = os.getenv("WORKER_ONCE", "true").lower() == "true"
    while True:
        result = process_once()
        logger.info("worker cycle completed counts=%s", result)
        if once:
            return
        time.sleep(30)


if __name__ == "__main__":
    main()
