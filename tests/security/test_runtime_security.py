"""Real persistence-backed authorization security regressions.

SQLite checks below cover transitions and tenancy, not PostgreSQL row-lock
behavior. Distributed counter/claim races need the PostgreSQL job in CI.
"""

from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from agentguard_api import database
from agentguard_api.connectors import ConnectorError, ConnectorResult
from agentguard_api.database import Base, create_database_engine
from agentguard_api.main import app
from agentguard_api.models import AuthorizationRequest, BudgetReservation, BudgetUsage, Organization


@pytest.fixture
def runtime(tmp_path, monkeypatch):
    engine = create_database_engine(f"sqlite:///{tmp_path / 'security.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(database, "SessionLocal", sessions)
    client = TestClient(app)
    registered = client.post(
        "/api/v1/auth/register",
        json={
            "email": "security-owner@example.com",
            "password": "security test correct horse battery",
            "name": "Security Owner",
            "organization_name": "Security Tenant",
        },
    )
    assert registered.status_code == 201, registered.text
    body = registered.json()
    csrf = {"X-CSRF-Token": body["csrf_token"]}
    workspace = body["workspaces"][0]["id"]
    agent = client.post("/api/v1/agents", headers=csrf, json={"name": "SecurityAgent", "workspace_id": workspace})
    assert agent.status_code == 201, agent.text
    agent_id = agent.json()["id"]

    def add_tool(name="sdk.refund", adapter="sdk", financial=True):
        config = {"url": "https://example.com/action", "allowed_hosts": ["example.com"]} if adapter == "http" else {}
        tool = client.post(
            "/api/v1/tools",
            headers=csrf,
            json={
                "name": name,
                "provider": name.split(".")[0],
                "adapter": adapter,
                "financial": financial,
                "config": config,
            },
        )
        assert tool.status_code == 201, tool.text
        policy = client.post(
            "/api/v1/policies",
            headers=csrf,
            json={
                "name": f"security-{name}",
                "priority": 100,
                "document": {
                    "name": f"security-{name}",
                    "resource": {"tool": name},
                    "rules": [{"when": {}, "action": "allow"}],
                },
            },
        )
        assert policy.status_code == 201, policy.text
        return tool.json()["id"]

    def credential(tools):
        key = client.post(
            f"/api/v1/agents/{agent_id}/credentials", headers=csrf, json={"environment": "development", "tools": tools}
        )
        assert key.status_code == 201, key.text
        return {"Authorization": f"Bearer {key.json()['api_key']}"}

    tool_id = add_tool()
    machine = credential(["sdk.refund"])
    yield client, csrf, agent_id, machine, tool_id, sessions, add_tool, credential
    client.close()
    engine.dispose()


def authorize(client, machine, key="security-authorize-0001", *, tool="sdk.refund", amount=50):
    return client.post(
        "/api/v1/authorize",
        headers=machine,
        json={
            "tool": tool,
            "arguments": {"amount": amount},
            "idempotency_key": key,
        },
    )


def test_claim_and_result_token_are_single_use(runtime):
    client, _, _, machine, _, _, _, _ = runtime
    allowed = authorize(client, machine).json()
    path = f"/api/v1/requests/{allowed['request_id']}"
    claim = client.post(path + "/claim", headers=machine, json={})
    assert claim.status_code == 200
    assert client.post(path + "/claim", headers=machine, json={}).status_code == 409
    assert client.post(path + "/result", headers=machine, json={"status": "succeeded", "result": {}}).status_code == 409
    assert (
        client.post(
            path + "/result",
            headers={**machine, "X-AgentGuard-Claim": "wrong-token"},
            json={"status": "succeeded", "result": {}},
        ).status_code
        == 409
    )
    reported = client.post(
        path + "/result",
        headers={**machine, "X-AgentGuard-Claim": claim.json()["claim_token"]},
        json={"status": "succeeded", "result": {"password": "test-sensitive-value"}},
    )
    assert reported.status_code == 200
    assert reported.json()["result"]["password"] == "[REDACTED]"  # noqa: S105
    assert (
        client.post(
            path + "/result",
            headers={**machine, "X-AgentGuard-Claim": claim.json()["claim_token"]},
            json={"status": "succeeded", "result": {}},
        ).status_code
        == 409
    )


def test_concurrent_claim_has_exactly_one_winner(runtime, monkeypatch):
    """FOR UPDATE protects PostgreSQL; compare-and-set must also protect startup/local stores."""
    client, _, _, machine, _, _, _, _ = runtime
    request_id = authorize(client, machine).json()["request_id"]
    gate = Barrier(2)
    from agentguard_api import runtime_routes

    original = runtime_routes._check_execution_allowed

    def synchronized_check(db, request, tool):
        original(db, request, tool)
        gate.wait(timeout=5)

    monkeypatch.setattr(runtime_routes, "_check_execution_allowed", synchronized_check)

    def claim():
        with TestClient(app, raise_server_exceptions=False) as caller:
            return caller.post(f"/api/v1/requests/{request_id}/claim", headers=machine, json={}).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = sorted(pool.map(lambda _: claim(), range(2)))
    assert statuses == [200, 409]


def test_new_credential_cannot_read_or_claim_previous_credentials_request(runtime):
    client, _, _, machine, _, _, _, credential = runtime
    allowed = authorize(client, machine).json()
    other_key = credential(["sdk.refund"])
    path = f"/api/v1/requests/{allowed['request_id']}"
    assert client.get(path, headers=other_key).status_code == 404
    assert client.post(path + "/claim", headers=other_key, json={}).status_code == 404


def test_foreign_tenant_machine_cannot_read_claim_or_report(runtime):
    client, _, _, machine, _, _, _, _ = runtime
    allowed = authorize(client, machine).json()
    other = TestClient(app)
    registered = other.post(
        "/api/v1/auth/register",
        json={
            "email": "foreign-security@example.com",
            "password": "another security correct horse battery",
            "name": "Foreign",
            "organization_name": "Foreign Security Tenant",
        },
    ).json()
    foreign_csrf = {"X-CSRF-Token": registered["csrf_token"]}
    agent = other.post(
        "/api/v1/agents",
        headers=foreign_csrf,
        json={"name": "Foreign", "workspace_id": registered["workspaces"][0]["id"]},
    ).json()
    key = other.post(
        f"/api/v1/agents/{agent['id']}/credentials",
        headers=foreign_csrf,
        json={"environment": "development", "tools": ["sdk.refund"]},
    ).json()
    foreign = {"Authorization": f"Bearer {key['api_key']}"}
    path = f"/api/v1/requests/{allowed['request_id']}"
    assert other.get(path, headers=foreign).status_code == 404
    assert other.post(path + "/claim", headers=foreign, json={}).status_code == 404
    assert other.post(path + "/result", headers=foreign, json={"status": "succeeded", "result": {}}).status_code == 404
    other.close()


@pytest.mark.parametrize("scope", ["agent", "tool", "environment"])
def test_kill_switch_blocks_previously_authorized_sdk_claim(runtime, scope):
    client, csrf, agent_id, machine, tool_id, _, _, _ = runtime
    allowed = authorize(client, machine).json()
    target = {"agent": agent_id, "tool": tool_id, "environment": "development"}[scope]
    killed = client.post(
        "/api/v1/kill-switch",
        headers=csrf,
        json={"scope": scope, "scope_id": target, "active": True, "reason": "Security incident"},
    )
    assert killed.status_code == 201
    claimed = client.post(f"/api/v1/requests/{allowed['request_id']}/claim", headers=machine, json={})
    assert claimed.status_code in {403, 409, 410}, claimed.text


def test_suspended_agent_cannot_claim_previous_authorization(runtime):
    client, csrf, agent_id, machine, _, _, _, _ = runtime
    allowed = authorize(client, machine).json()
    assert (
        client.post(f"/api/v1/agents/{agent_id}/status", headers=csrf, json={"status": "suspended"}).status_code == 200
    )
    claimed = client.post(f"/api/v1/requests/{allowed['request_id']}/claim", headers=machine, json={})
    assert claimed.status_code in {401, 403, 409, 410}, claimed.text


def test_idempotency_cannot_transfer_an_execution_to_narrower_credentials(runtime, monkeypatch):
    client, _, _, _, _, _, add_tool, credential = runtime
    add_tool("github.read", adapter="github", financial=False)
    broad = credential(["github.read"])
    narrow = credential(["sdk.refund"])
    pending = authorize(client, broad, "prior-broad-credential-0001", tool="github.read", amount=0)
    assert pending.json()["decision"] == "allow"
    executed = []

    def connector(tool, request, arguments):
        executed.append(tool.name)
        return ConnectorResult("succeeded", {"executed": tool.name})

    monkeypatch.setattr("agentguard_api.runtime_routes.execute_connector", connector)
    attempted = client.post(
        "/api/v1/execute",
        headers=narrow,
        json={
            "tool": "github.read",
            "arguments": {"amount": 0},
            "idempotency_key": "prior-broad-credential-0001",
        },
    )
    assert attempted.status_code in {403, 404, 409} or attempted.json().get("decision") == "deny", attempted.text
    assert not executed


@pytest.mark.parametrize("arguments", [{}, {"amount": "not-money"}, {"amount": -1}, {"amount": True}])
def test_financial_amount_missing_or_malformed_fails_closed(runtime, arguments):
    client, _, _, machine, _, _, _, _ = runtime
    attempted = client.post("/api/v1/authorize", headers=machine, json={"tool": "sdk.refund", "arguments": arguments})
    assert attempted.status_code == 422 or attempted.json().get("decision") == "deny", attempted.text


def test_inactive_organization_machine_credential_is_rejected(runtime):
    client, _, _, machine, _, sessions, _, _ = runtime
    with sessions() as db:
        tenant = db.scalar(select(Organization).where(Organization.name == "Security Tenant"))
        tenant.active = False
        db.commit()
    attempted = authorize(client, machine)
    assert attempted.status_code in {401, 403} or attempted.json().get("decision") == "deny", attempted.text


def test_expired_claim_releases_token_and_cannot_report_success(runtime):
    client, _, _, machine, _, sessions, _, _ = runtime
    allowed = authorize(client, machine).json()
    path = f"/api/v1/requests/{allowed['request_id']}"
    claim = client.post(path + "/claim", headers=machine, json={}).json()
    with sessions() as db:
        item = db.get(AuthorizationRequest, allowed["request_id"])
        item.claim_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    rejected = client.post(
        path + "/result",
        headers={**machine, "X-AgentGuard-Claim": claim["claim_token"]},
        json={"status": "succeeded", "result": {}},
    )
    assert rejected.status_code == 410
    with sessions() as db:
        assert db.get(AuthorizationRequest, allowed["request_id"]).execution_claim_hash is None


def test_period_budget_counts_outstanding_authorizations_and_settles_once(runtime):
    client, csrf, agent_id, machine, _, sessions, _, _ = runtime
    assert (
        client.post(
            "/api/v1/budgets",
            headers=csrf,
            json={"name": "Daily", "scope": "agent", "scope_id": agent_id, "period": "daily", "limit_minor": 10000},
        ).status_code
        == 201
    )
    first = authorize(client, machine, "daily-first-0001", amount=60).json()
    assert first["decision"] == "allow"
    second = authorize(client, machine, "daily-second-0001", amount=60).json()
    assert second["decision"] == "budget_exceeded"
    path = f"/api/v1/requests/{first['request_id']}"
    claim = client.post(path + "/claim", headers=machine, json={}).json()
    report = {**machine, "X-AgentGuard-Claim": claim["claim_token"]}
    assert client.post(path + "/result", headers=report, json={"status": "succeeded", "result": {}}).status_code == 200
    assert client.post(path + "/result", headers=report, json={"status": "succeeded", "result": {}}).status_code == 409
    with sessions() as db:
        usage = db.scalar(select(BudgetUsage))
        assert (usage.used_minor, usage.reserved_minor) == (6000, 0)
        assert db.scalar(select(BudgetReservation)).state == "spent"


def test_uncertain_provider_failure_does_not_release_spending_capacity(runtime, monkeypatch):
    client, csrf, agent_id, _, _, sessions, add_tool, credential = runtime
    add_tool("stripe.refund", adapter="stripe")
    machine = credential(["stripe.refund"])
    assert (
        client.post(
            "/api/v1/budgets",
            headers=csrf,
            json={
                "name": "Financial ceiling",
                "scope": "agent",
                "scope_id": agent_id,
                "period": "daily",
                "limit_minor": 10000,
            },
        ).status_code
        == 201
    )

    def lost_response(tool, request, arguments):
        raise ConnectorError("Provider response was lost after request transmission")

    monkeypatch.setattr("agentguard_api.runtime_routes.execute_connector", lost_response)
    result = client.post(
        "/api/v1/execute",
        headers=machine,
        json={"tool": "stripe.refund", "arguments": {"amount": 60}, "idempotency_key": "uncertain-payment-0001"},
    )
    assert result.status_code == 200
    with sessions() as db:
        usage = db.scalar(select(BudgetUsage))
        assert usage.used_minor + usage.reserved_minor == 6000, (
            "An unknown provider outcome must stay reserved pending reconciliation"
        )


def test_approved_request_rejects_tool_configuration_drift(runtime, monkeypatch):
    client, csrf, _, _, _, _, add_tool, credential = runtime
    tool_id = add_tool("http.approved", adapter="http", financial=False)
    policy = client.post(
        "/api/v1/policies",
        headers=csrf,
        json={
            "name": "approval-http",
            "priority": 200,
            "document": {
                "name": "approval-http",
                "resource": {"tool": "http.approved"},
                "rules": [
                    {"when": {}, "action": "require_approval", "reason": "Human review"},
                ],
            },
        },
    )
    assert policy.status_code == 201, policy.text
    machine = credential(["http.approved"])
    pending = client.post(
        "/api/v1/authorize",
        headers=machine,
        json={
            "tool": "http.approved",
            "arguments": {"target": "reviewed"},
            "idempotency_key": "tool-drift-request-0001",
        },
    ).json()
    assert pending["decision"] == "require_approval"
    assert (
        client.post(
            f"/api/v1/approvals/{pending['approval_id']}/decide", headers=csrf, json={"decision": "approve"}
        ).status_code
        == 200
    )
    changed = client.patch(
        f"/api/v1/tools/{tool_id}",
        headers=csrf,
        json={
            "name": "http.approved",
            "provider": "http",
            "adapter": "github",
            "config": {"owner": "changed", "repo": "changed"},
        },
    )
    assert changed.status_code == 200, changed.text
    executed = []

    def connector(tool, request, arguments):
        executed.append(tool.adapter)
        return ConnectorResult("succeeded", {})

    monkeypatch.setattr("agentguard_api.runtime_routes.execute_connector", connector)
    resumed = client.post(f"/api/v1/requests/{pending['request_id']}/execute", headers=machine, json={})
    assert resumed.status_code == 409 or resumed.json().get("decision") == "deny", resumed.text
    assert not executed
