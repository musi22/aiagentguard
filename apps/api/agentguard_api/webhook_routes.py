from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .admin_routes import decide_approval
from .audit import hash_payload
from .database import get_db, set_tenant_context
from .models import (
    ApprovalRequest, AuthorizationRequest, BillingSubscription, InboundWebhookEvent, Integration,
    Organization, OrganizationMember, User,
)
from .security import get_secret_store, verify_slack_signature

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])


def _verify_stripe(body: bytes, signature: str) -> None:
    parts: dict[str, list[str]] = {}
    for part in signature.split(","):
        key, _, value = part.partition("=")
        parts.setdefault(key, []).append(value)
    try:
        timestamp = int(parts.get("t", [""])[0])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid Stripe signature") from exc
    if abs(int(datetime.now(timezone.utc).timestamp()) - timestamp) > 300:
        raise HTTPException(status_code=400, detail="Expired Stripe signature")
    secret = get_secret_store().get("stripe-webhook-secret")
    expected = hmac.new(str(secret).encode(), f"{timestamp}.".encode() + body, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, candidate) for candidate in parts.get("v1", [])):
        raise HTTPException(status_code=400, detail="Invalid Stripe signature")


@router.post("/stripe")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)) -> dict:
    body = await request.body()
    _verify_stripe(body, request.headers.get("stripe-signature", ""))
    try:
        event = json.loads(body)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid webhook JSON") from exc
    event_id, event_type = str(event.get("id", "")), str(event.get("type", ""))
    if not event_id:
        raise HTTPException(status_code=400, detail="Missing event ID")
    if db.scalar(select(InboundWebhookEvent.id).where(
        InboundWebhookEvent.provider == "stripe", InboundWebhookEvent.provider_event_id == event_id
    )):
        return {"received": True, "duplicate": True}
    obj = event.get("data", {}).get("object", {})
    organization_id = (obj.get("metadata") or {}).get("organization_id")
    if event_type.startswith("customer.subscription.") and organization_id:
        set_tenant_context(db, organization_id)
        organization = db.get(Organization, organization_id)
        if organization:
            subscription = db.scalar(select(BillingSubscription).where(
                BillingSubscription.organization_id == organization_id
            )) or BillingSubscription(organization_id=organization_id)
            db.add(subscription)
            subscription.provider_customer_id = obj.get("customer")
            subscription.provider_subscription_id = obj.get("id")
            subscription.status = obj.get("status", "unknown")
            price_id = (((obj.get("items") or {}).get("data") or [{}])[0].get("price") or {}).get("id")
            plan = "free"
            for candidate in ("pro", "team"):
                configured = get_secret_store().get(f"stripe-{candidate}-price-id", required=False)
                if configured and configured == price_id:
                    plan = candidate
            if event_type == "customer.subscription.deleted":
                plan = "free"
            subscription.plan = plan
            organization.plan = plan
    db.add(InboundWebhookEvent(
        provider="stripe", provider_event_id=event_id, organization_id=organization_id,
        payload_hash=hash_payload(event),
    ))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return {"received": True, "duplicate": True}
    return {"received": True}


@router.post("/slack/interactions")
async def slack_interaction(request: Request, db: Session = Depends(get_db)) -> dict:
    body = await request.body()
    secret = get_secret_store().get("slack-signing-secret")
    if not verify_slack_signature(
        str(secret), request.headers.get("x-slack-request-timestamp", ""), body,
        request.headers.get("x-slack-signature", ""),
    ):
        raise HTTPException(status_code=401, detail="Invalid Slack signature")
    form = parse_qs(body.decode("utf-8", errors="strict"))
    try:
        payload = json.loads(form["payload"][0])
        action_value = payload["actions"][0]["value"]
        organization_id, decision_value, approval_id = action_value.split(":", 2)
        slack_user_id = payload["user"]["id"]
        slack_team_id = payload["team"]["id"]
    except (KeyError, IndexError, ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Malformed Slack interaction") from exc
    if decision_value not in {"approve", "reject"}:
        raise HTTPException(status_code=400, detail="Unsupported Slack action")
    set_tenant_context(db, organization_id)
    integrations = db.scalars(select(Integration).where(
        Integration.organization_id == organization_id,
        Integration.provider == "slack", Integration.enabled.is_(True)
    )).all()
    integration = next((item for item in integrations if item.config.get("team_id") == slack_team_id), None)
    if not integration:
        raise HTTPException(status_code=403, detail="Slack workspace is not connected")
    set_tenant_context(db, integration.organization_id)
    email = (integration.config.get("user_map") or {}).get(slack_user_id)
    row = db.execute(select(User, OrganizationMember).join(
        OrganizationMember, OrganizationMember.user_id == User.id
    ).where(
        OrganizationMember.organization_id == integration.organization_id,
        User.email == str(email).lower(), OrganizationMember.status == "active",
    )).first()
    if not row:
        raise HTTPException(status_code=403, detail="Slack user is not mapped to an AgentGuard member")
    user, member = row
    approval = db.scalar(select(ApprovalRequest).where(
        ApprovalRequest.id == approval_id, ApprovalRequest.organization_id == integration.organization_id
    ).with_for_update())
    if not approval:
        raise HTTPException(status_code=404, detail="Approval not found")
    authorization = db.scalar(select(AuthorizationRequest).where(
        AuthorizationRequest.id == approval.authorization_request_id,
        AuthorizationRequest.organization_id == integration.organization_id,
    ).with_for_update())
    result = decide_approval(db, approval, authorization, user.id, member.role, decision_value, "Slack interaction")
    return {"response_type": "ephemeral", "text": f"AgentGuard request {result['state']}."}
