"""PostgreSQL tenant row security and domain constraints.

Revision ID: 0002_tenant_rls
Revises: 45ba96f4f84c
"""
from typing import Sequence, Union

from alembic import op

revision: str = "0002_tenant_rls"
down_revision: Union[str, None] = "45ba96f4f84c"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TENANT_TABLES = [
    "api_keys", "audit_checkpoints", "audit_events", "billing_subscriptions", "budgets", "integrations",
    "kill_switches", "notifications", "rate_limits", "tools", "usage_events",
    "webhooks", "workspaces", "budget_usage", "policies", "rate_limit_buckets", "teams", "webhook_deliveries",
    "agents", "policy_versions", "team_members", "agent_credentials", "agent_tool_permissions",
    "authorization_requests", "approval_requests", "budget_reservations", "approval_decisions",
]

CHECKS = {
    "organizations": [("ck_organizations_plan", "plan IN ('free','pro','team','enterprise')"),
                      ("ck_organizations_dlp", "dlp_action IN ('allow','warn','redact','approval','block')")],
    "agents": [("ck_agents_status", "status IN ('active','suspended','revoked','killed')")],
    "tools": [("ck_tools_adapter", "adapter IN ('sdk','http','stripe','github','postgres','mcp')")],
    "authorization_requests": [
        ("ck_requests_risk", "risk_score >= 0 AND risk_score <= 100"),
        ("ck_requests_decision", "decision IN ('evaluating','allow','deny','require_approval','rate_limited','budget_exceeded','agent_disabled')"),
    ],
    "approval_requests": [("ck_approval_state", "state IN ('pending','approved','rejected','expired')"),
                           ("ck_approval_threshold", "threshold > 0")],
    "approval_decisions": [("ck_approval_decision", "decision IN ('approve','reject')")],
    "budgets": [("ck_budget_limit", "limit_minor > 0"),
                ("ck_budget_period", "period IN ('action','daily','weekly','monthly')")],
    "budget_usage": [("ck_budget_usage_nonnegative", "used_minor >= 0 AND reserved_minor >= 0")],
    "budget_reservations": [("ck_reservation_amount", "amount_minor >= 0"),
                            ("ck_reservation_state", "state IN ('reserved','spent','released')")],
    "rate_limits": [("ck_rate_positive", "window_seconds > 0 AND max_requests > 0")],
    "rate_limit_buckets": [("ck_rate_count", "count >= 0")],
    "webhook_deliveries": [("ck_delivery_attempts", "attempts >= 0")],
}


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    expression = "organization_id = NULLIF(current_setting('app.current_organization', true), '')"
    for table in TENANT_TABLES:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'CREATE POLICY tenant_isolation ON "{table}" USING ({expression}) WITH CHECK ({expression})')
    op.execute('ALTER TABLE "organizations" ENABLE ROW LEVEL SECURITY')
    op.execute("CREATE POLICY tenant_isolation ON organizations USING (id = NULLIF(current_setting('app.current_organization', true), '')) WITH CHECK (id = NULLIF(current_setting('app.current_organization', true), ''))")
    for table, entries in CHECKS.items():
        for name, expression in entries:
            op.execute(f'ALTER TABLE "{table}" ADD CONSTRAINT "{name}" CHECK ({expression})')


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for table, entries in CHECKS.items():
        for name, _ in entries:
            op.execute(f'ALTER TABLE "{table}" DROP CONSTRAINT IF EXISTS "{name}"')
    for table in [*TENANT_TABLES, "organizations"]:
        op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
        op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
