from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from .models import Budget, BudgetReservation, BudgetUsage, RateLimit, RateLimitBucket, UsageEvent


def amount_to_minor(arguments: dict[str, Any], *, required: bool = False) -> int:
    from fastapi import HTTPException

    raw = arguments.get("amount", None if required else 0)
    if isinstance(raw, bool) or raw is None:
        raise HTTPException(status_code=422, detail="A valid nonnegative amount is required")
    try:
        amount = Decimal(str(raw))
    except (InvalidOperation, ValueError):
        raise HTTPException(status_code=422, detail="Amount must be a finite nonnegative decimal") from None
    if not amount.is_finite() or amount < 0 or amount > Decimal("90000000000"):
        raise HTTPException(status_code=422, detail="Amount is outside the supported monetary range")
    return int((amount * 100).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def _lock_org(db: Session, organization_id: str, namespace: str) -> None:
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"{namespace}:{organization_id}"})


def _scope_matches(scope: str, scope_id: str | None, facts: dict[str, Any]) -> bool:
    if scope == "organization":
        return True
    return bool(scope_id and str(facts.get(f"{scope}_id" if scope != "provider" else "provider")) == scope_id)


def _bucket_start(now: datetime, seconds: int) -> datetime:
    epoch = int(now.timestamp())
    return datetime.fromtimestamp(epoch - epoch % seconds, timezone.utc)


def acquire_rate_limits(db: Session, organization_id: str, facts: dict[str, Any]) -> tuple[bool, str | None]:
    limits = db.scalars(
        select(RateLimit).where(RateLimit.organization_id == organization_id, RateLimit.active.is_(True))
    ).all()
    matched = [limit for limit in limits if _scope_matches(limit.scope, limit.scope_id, facts)]
    if not matched:
        return True, None
    from .config import get_settings

    settings = get_settings()
    if settings.redis_host:
        try:
            from redis import Redis
            from redis_entraid.cred_provider import create_from_default_azure_credential

            options: dict[str, Any] = {}
            if settings.redis_auth == "entra":
                options["credential_provider"] = create_from_default_azure_credential(
                    ("https://redis.azure.com/.default",)
                )
            client = Redis(
                host=settings.redis_host, port=settings.redis_port, ssl=settings.redis_ssl,
                ssl_cert_reqs="required" if settings.redis_ssl else None,
                socket_connect_timeout=2, socket_timeout=2, decode_responses=True, **options,
            )
            script = """
            local value = redis.call('INCR', KEYS[1])
            if value == 1 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
            if value > tonumber(ARGV[1]) then return 0 end
            return 1
            """
            now_epoch = int(datetime.now(timezone.utc).timestamp())
            for limit in matched:
                bucket = now_epoch - now_epoch % limit.window_seconds
                key = f"agentguard:rate:{organization_id}:{limit.id}:{bucket}"
                if int(client.eval(script, 1, key, limit.max_requests, limit.window_seconds)) != 1:
                    return False, f"Rate limit exceeded: {limit.max_requests} requests per {limit.window_seconds} seconds"
            return True, None
        except Exception:
            # Mixing a Redis counter with fallback counters can permit an overrun; production fails closed.
            return False, "Distributed rate-limit service is unavailable"

    _lock_org(db, organization_id, "rate")
    now = datetime.now(timezone.utc)
    for limit in matched:
        start = _bucket_start(now, limit.window_seconds)
        bucket = db.scalar(
            select(RateLimitBucket).where(
                RateLimitBucket.rate_limit_id == limit.id, RateLimitBucket.bucket_start == start
            ).with_for_update()
        )
        if bucket is None:
            bucket = RateLimitBucket(
                organization_id=organization_id, rate_limit_id=limit.id, bucket_start=start, count=0
            )
            db.add(bucket)
            db.flush()
        if bucket.count >= limit.max_requests:
            return False, f"Rate limit exceeded: {limit.max_requests} requests per {limit.window_seconds} seconds"
        bucket.count += 1
    return True, None


def _period_start(now: datetime, period: str) -> datetime:
    day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "daily":
        return day
    if period == "weekly":
        return day - timedelta(days=day.weekday())
    return day.replace(day=1)


def reserve_budgets(
    db: Session,
    organization_id: str,
    facts: dict[str, Any],
    request_id: str,
    amount_minor: int,
) -> tuple[bool, str | None]:
    if amount_minor <= 0:
        return True, None
    _lock_org(db, organization_id, "budget")
    budgets = db.scalars(select(Budget).where(Budget.organization_id == organization_id, Budget.active.is_(True))).all()
    now = datetime.now(timezone.utc)
    pending: list[tuple[BudgetUsage, int]] = []
    for budget in budgets:
        if not _scope_matches(budget.scope, budget.scope_id, facts):
            continue
        if str(facts.get("currency", "USD")).upper() != budget.currency.upper():
            return False, f"Budget {budget.name!r} currency does not match this action"
        if budget.period == "action":
            if amount_minor > budget.limit_minor:
                return False, f"Per-action budget {budget.name!r} exceeded"
            continue
        start = _period_start(now, budget.period)
        usage = db.scalar(
            select(BudgetUsage).where(BudgetUsage.budget_id == budget.id, BudgetUsage.period_start == start).with_for_update()
        )
        if usage is None:
            usage = BudgetUsage(
                organization_id=organization_id, budget_id=budget.id, period_start=start, used_minor=0, reserved_minor=0
            )
            db.add(usage)
            db.flush()
        if usage.used_minor + usage.reserved_minor + amount_minor > budget.limit_minor:
            return False, f"{budget.period.title()} budget {budget.name!r} exceeded"
        pending.append((usage, amount_minor))
    for usage, amount in pending:
        usage.reserved_minor += amount
        db.add(BudgetReservation(
            organization_id=organization_id, budget_usage_id=usage.id, request_id=request_id, amount_minor=amount
        ))
    return True, None


def settle_budget_reservations(db: Session, request_id: str, succeeded: bool | None) -> None:
    # None means the provider outcome is unknown: preserve capacity until manual reconciliation.
    if succeeded is None:
        return
    reservations = db.scalars(
        select(BudgetReservation).where(
            BudgetReservation.request_id == request_id, BudgetReservation.state == "reserved"
        ).with_for_update()
    ).all()
    for reservation in reservations:
        usage = db.get(BudgetUsage, reservation.budget_usage_id, with_for_update=True)
        if usage:
            usage.reserved_minor = max(0, usage.reserved_minor - reservation.amount_minor)
            if succeeded:
                usage.used_minor += reservation.amount_minor
        reservation.state = "spent" if succeeded else "released"


PLAN_LIMITS = {
    "free": {"agents": 3, "tools": 5, "actions": 10_000, "retention_days": 7},
    "pro": {"agents": 20, "tools": 100, "actions": 100_000, "retention_days": 30},
    "team": {"agents": 100, "tools": 1000, "actions": 1_000_000, "retention_days": 90},
    "enterprise": {"agents": 10_000_000, "tools": 10_000_000, "actions": 10_000_000_000, "retention_days": 3650},
}


def action_quota_available(db: Session, organization_id: str, plan: str) -> bool:
    _lock_org(db, organization_id, "quota")
    start = _period_start(datetime.now(timezone.utc), "monthly")
    count = db.scalar(
        select(__import__("sqlalchemy").func.coalesce(__import__("sqlalchemy").func.sum(UsageEvent.quantity), 0)).where(
            UsageEvent.organization_id == organization_id,
            UsageEvent.kind == "protected_action",
            UsageEvent.occurred_at >= start,
        )
    ) or 0
    return int(count) < PLAN_LIMITS.get(plan, PLAN_LIMITS["free"])["actions"]
