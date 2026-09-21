from __future__ import annotations

from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

from agentguard_api import database
from agentguard_api.connectors import ConnectorResult
from agentguard_api.database import Base, create_database_engine
from agentguard_api.main import app


def setup_client(tmp_path, monkeypatch):
    engine = create_database_engine(f"sqlite:///{tmp_path / 'test.db'}")
    Base.metadata.create_all(engine)
    monkeypatch.setattr(database, "SessionLocal", sessionmaker(bind=engine, autoflush=False, expire_on_commit=False))
    client = TestClient(app)
    response = client.post("/api/v1/auth/register", json={
        "email": "owner@example.com", "password": "correct horse battery staple",
        "name": "Owner", "organization_name": "Acme",
    })
    assert response.status_code == 201, response.text
    body = response.json()
    csrf = body["csrf_token"]
    return client, {"X-CSRF-Token": csrf}, body["workspaces"][0]["id"]


def create_runtime(client, user_headers, workspace_id, *, adapter="sdk", name="stripe.refund"):
    tool = client.post("/api/v1/tools", headers=user_headers, json={
        "name": name, "provider": name.split(".")[0], "environment": "development",
        "financial": name == "stripe.refund", "adapter": adapter,
        "config": {"url": "https://example.com/action", "allowed_hosts": ["example.com"]} if adapter == "http" else {},
    })
    assert tool.status_code == 201, tool.text
    agent = client.post("/api/v1/agents", headers=user_headers, json={
        "name": "FinanceAgent", "workspace_id": workspace_id, "environment": "development",
    })
    assert agent.status_code == 201, agent.text
    agent_id = agent.json()["id"]
    policy = client.post("/api/v1/policies", headers=user_headers, json={
        "name": f"policy-{name}", "priority": 100, "document": {
            "name": "refund-policy", "subject": {"agent": "FinanceAgent"}, "resource": {"tool": name},
            "rules": [
                {"when": {"amount_lte": 500}, "action": "allow", "reason": "Within autonomous threshold"},
                {"when": {"amount_gt": 500, "amount_lte": 5000}, "action": "require_approval", "reason": "Above autonomous threshold"},
                {"when": {"amount_gt": 5000}, "action": "deny", "reason": "Above maximum threshold"},
            ],
        },
    })
    assert policy.status_code == 201, policy.text
    credential = client.post(f"/api/v1/agents/{agent_id}/credentials", headers=user_headers, json={
        "environment": "development", "tools": [name],
    })
    assert credential.status_code == 201, credential.text
    return agent_id, {"Authorization": f"Bearer {credential.json()['api_key']}"}, tool.json()["id"]


def test_allow_approval_deny_claim_and_audit(tmp_path, monkeypatch):
    client, user_headers, workspace_id = setup_client(tmp_path, monkeypatch)
    with client:
        agent_id, machine, _ = create_runtime(client, user_headers, workspace_id)

        allowed = client.post("/api/v1/authorize", headers=machine, json={
            "agent_id": agent_id, "tool": "stripe.refund", "arguments": {"amount": 50},
            "context": {"environment": "development"}, "idempotency_key": "allow-request-0001",
        })
        assert allowed.status_code == 200
        assert allowed.json()["decision"] == "allow"

        pending = client.post("/api/v1/authorize", headers=machine, json={
            "agent_id": agent_id, "tool": "stripe.refund", "arguments": {"amount": 850},
            "context": {"environment": "development"}, "idempotency_key": "approval-request-0001",
        })
        assert pending.json()["decision"] == "require_approval"
        approval_id, request_id = pending.json()["approval_id"], pending.json()["request_id"]
        approval = client.post(f"/api/v1/approvals/{approval_id}/decide", headers=user_headers,
                               json={"decision": "approve", "comment": "Reviewed"})
        assert approval.status_code == 200, approval.text
        state = client.get(f"/api/v1/requests/{request_id}", headers=machine)
        assert state.json()["decision"] == "allow" and state.json()["status"] == "approved"
        claim = client.post(f"/api/v1/requests/{request_id}/claim", headers=machine, json={})
        assert claim.status_code == 200 and claim.json()["arguments"]["amount"] == 850
        result = client.post(f"/api/v1/requests/{request_id}/result", headers={
            **machine, "X-AgentGuard-Claim": claim.json()["claim_token"]
        }, json={"status": "succeeded", "result": {"refund_id": "real-result"}})
        assert result.json()["status"] == "succeeded"
        replay = client.post(f"/api/v1/requests/{request_id}/result", headers={
            **machine, "X-AgentGuard-Claim": claim.json()["claim_token"]
        }, json={"status": "succeeded", "result": {}})
        assert replay.status_code == 409

        denied = client.post("/api/v1/authorize", headers=machine, json={
            "agent_id": agent_id, "tool": "stripe.refund", "arguments": {"amount": 10000},
            "idempotency_key": "deny-request-0001",
        })
        assert denied.json()["decision"] == "deny"
        audit = client.get("/api/v1/audit", headers=user_headers)
        assert {row["event_type"] for row in audit.json()} >= {
            "authorization.decision", "approval.decision", "tool.execution_claimed", "tool.execution"
        }
        assert client.get("/api/v1/audit/verify", headers=user_headers).json()["valid"] is True


def test_budget_rate_kill_dlp_and_tenant_isolation(tmp_path, monkeypatch):
    client, user_headers, workspace_id = setup_client(tmp_path, monkeypatch)
    with client:
        agent_id, machine, tool_id = create_runtime(client, user_headers, workspace_id)
        budget = client.post("/api/v1/budgets", headers=user_headers, json={
            "name": "Small action", "scope": "agent", "scope_id": agent_id,
            "period": "action", "limit_minor": 1000, "currency": "USD",
        })
        assert budget.status_code == 201
        exceeded = client.post("/api/v1/authorize", headers=machine, json={
            "tool": "stripe.refund", "arguments": {"amount": 11}, "idempotency_key": "budget-request-0001",
        })
        assert exceeded.json()["decision"] == "budget_exceeded"

        rate = client.post("/api/v1/rate-limits", headers=user_headers, json={
            "scope": "agent", "scope_id": agent_id, "window_seconds": 60, "max_requests": 1,
        })
        assert rate.status_code == 201
        first = client.post("/api/v1/authorize", headers=machine, json={
            "tool": "stripe.refund", "arguments": {"amount": 1}, "idempotency_key": "rate-request-0001",
        })
        assert first.json()["decision"] == "allow"
        second = client.post("/api/v1/authorize", headers=machine, json={
            "tool": "stripe.refund", "arguments": {"amount": 1}, "idempotency_key": "rate-request-0002",
        })
        assert second.json()["decision"] == "rate_limited"

        killed = client.post("/api/v1/kill-switch", headers=user_headers, json={
            "scope": "agent", "scope_id": agent_id, "active": True, "reason": "Incident containment",
        })
        assert killed.status_code == 201
        stopped = client.post("/api/v1/authorize", headers=machine, json={
            "tool": "stripe.refund", "arguments": {"amount": 1}, "idempotency_key": "kill-request-0001",
        })
        assert stopped.json()["decision"] == "agent_disabled"

        # A second organization's authenticated browser cannot address the first tenant's agent.
        other = TestClient(app)
        registration = other.post("/api/v1/auth/register", json={
            "email": "other@example.com", "password": "another correct horse battery",
            "name": "Other", "organization_name": "Other Org",
        })
        cross = other.post(f"/api/v1/agents/{agent_id}/status", headers={
            "X-CSRF-Token": registration.json()["csrf_token"]
        }, json={"status": "suspended"})
        assert cross.status_code == 404


def test_remote_execution_is_single_and_records_real_result(tmp_path, monkeypatch):
    client, user_headers, workspace_id = setup_client(tmp_path, monkeypatch)
    calls = []

    def fake_execute(tool, request, arguments):
        calls.append((tool.name, arguments))
        return ConnectorResult("succeeded", {"provider_id": "provider-123"})

    monkeypatch.setattr("agentguard_api.runtime_routes.execute_connector", fake_execute)
    with client:
        agent_id, machine, _ = create_runtime(client, user_headers, workspace_id, adapter="http", name="http.refund")
        result = client.post("/api/v1/execute", headers=machine, json={
            "agent_id": agent_id, "tool": "http.refund", "arguments": {"amount": 50},
            "idempotency_key": "remote-execute-0001",
        })
        assert result.status_code == 200, result.text
        assert result.json()["status"] == "succeeded"
        assert result.json()["result"] == {"provider_id": "provider-123"}
        repeated = client.post("/api/v1/execute", headers=machine, json={
            "agent_id": agent_id, "tool": "http.refund", "arguments": {"amount": 50},
            "idempotency_key": "remote-execute-0001",
        })
        assert repeated.json()["status"] == "succeeded"
        assert len(calls) == 1
