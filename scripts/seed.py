"""Opt-in local-development seed. Never runs automatically in deployed environments."""
from __future__ import annotations

import json
import os
from pathlib import Path
from sys import path

ROOT = Path(__file__).resolve().parents[1]
for relative in ("apps/api", "packages/policy-engine", "packages/risk-engine", "packages/shared-types"):
    path.insert(0, str(ROOT / relative))

from sqlalchemy import select  # noqa: E402

from agentguard_api.database import SessionLocal  # noqa: E402
from agentguard_api.models import (  # noqa: E402
    Agent, AgentCredential, Organization, OrganizationMember, Policy, PolicyVersion, Tool, User, Workspace,
)
from agentguard_api.security import hash_password, make_machine_key  # noqa: E402
from agentguard_api.audit import hash_payload  # noqa: E402


def main() -> None:
    if os.getenv("ENVIRONMENT", "development") not in {"development", "test"}:
        raise SystemExit("The development seed is disabled outside development/test")
    password = os.getenv("SEED_ADMIN_PASSWORD")
    if not password or len(password) < 12:
        raise SystemExit("Set SEED_ADMIN_PASSWORD to at least 12 characters")
    github_owner, github_repo = os.getenv("DEMO_GITHUB_OWNER", "your-owner"), os.getenv("DEMO_GITHUB_REPO", "your-repo")
    with SessionLocal() as db:
        if db.scalar(select(Organization.id).where(Organization.slug == "acme-local")):
            raise SystemExit("Acme local seed already exists; no data was changed")
        user = User(email="admin@acme.com", name="Acme Admin", password_hash=hash_password(password))
        organization = Organization(name="Acme", slug="acme-local", plan="pro", dlp_action="redact")
        db.add_all([user, organization])
        db.flush()
        workspace = Workspace(organization_id=organization.id, name="Default", environment="development")
        db.add(workspace)
        db.add(OrganizationMember(organization_id=organization.id, user_id=user.id, role="owner", status="active"))
        db.flush()
        agents = {}
        for name, framework in (("FinanceAgent", "LangGraph"), ("SupportAgent", "custom Python"), ("CodingAgent", "OpenAI Agents SDK")):
            agent = Agent(
                organization_id=organization.id, workspace_id=workspace.id, owner_id=user.id, name=name,
                framework=framework, model_provider="configurable", environment="development", status="active",
            )
            db.add(agent)
            agents[name] = agent
        db.flush()
        tools = [
            Tool(organization_id=organization.id, owner_id=user.id, name="stripe.refund", provider="stripe",
                 financial=True, adapter="stripe", environment="development", config={"secret_ref": "stripe-secret-key"}),
            Tool(organization_id=organization.id, owner_id=user.id, name="github.read_repository", provider="github",
                 adapter="github", read_write_classification="read", environment="development",
                 config={"owner": github_owner, "repo": github_repo, "secret_ref": "github-token"}),
            Tool(organization_id=organization.id, owner_id=user.id, name="github.create_branch", provider="github",
                 adapter="github", environment="development",
                 config={"owner": github_owner, "repo": github_repo, "secret_ref": "github-token"}),
            Tool(organization_id=organization.id, owner_id=user.id, name="github.merge_pull_request", provider="github",
                 adapter="github", environment="development",
                 config={"owner": github_owner, "repo": github_repo, "secret_ref": "github-token"}),
            Tool(organization_id=organization.id, owner_id=user.id, name="github.delete_repository", provider="github",
                 adapter="github", destructive=True, risk_category="critical", environment="development",
                 config={"owner": github_owner, "repo": github_repo, "secret_ref": "github-token"}),
        ]
        db.add_all(tools)
        refund_policy = {
            "name": "refund-policy", "subject": {"agent": "FinanceAgent"}, "resource": {"tool": "stripe.refund"},
            "rules": [
                {"when": {"amount_lte": 500}, "action": "allow", "reason": "Refund is within autonomous threshold"},
                {"when": {"amount_gt": 500, "amount_lte": 5000}, "action": "require_approval", "reason": "Refund exceeds autonomous threshold"},
                {"when": {"amount_gt": 5000}, "action": "deny", "reason": "Refund exceeds maximum permitted amount"},
            ],
        }
        coding_policy = {
            "name": "coding-policy", "subject": {"agent": "CodingAgent"}, "resource": {},
            "rules": [
                {"when": {"tool_in": ["github.read_repository", "github.create_branch"]}, "action": "allow"},
                {"when": {"tool": "github.merge_pull_request"}, "action": "require_approval"},
                {"when": {"tool": "github.delete_repository"}, "action": "deny"},
            ],
        }
        # Each rule set is a real versioned policy; seed data is isolated to an explicit local command.
        for name, priority, document in (("Refund controls", 100, refund_policy), ("GitHub controls", 100, coding_policy)):
            policy = Policy(organization_id=organization.id, workspace_id=workspace.id, name=name,
                            priority=priority, enabled=True, current_version=1)
            db.add(policy)
            db.flush()
            db.add(PolicyVersion(
                organization_id=organization.id, policy_id=policy.id, version=1, document=document,
                checksum=hash_payload(document), created_by=user.id,
            ))
        credentials = {}
        scopes = {
            "FinanceAgent": ["stripe.refund"], "SupportAgent": [],
            "CodingAgent": [tool.name for tool in tools if tool.provider == "github"],
        }
        for name, agent in agents.items():
            credential = AgentCredential(
                organization_id=organization.id, agent_id=agent.id, key_hash="pending", key_prefix="pending",
                environment="development", scopes=scopes[name],
            )
            db.add(credential)
            db.flush()
            raw, key_hash, prefix = make_machine_key("development", organization.id, credential.id)
            credential.key_hash, credential.key_prefix = key_hash, prefix
            credentials[name] = raw
        db.commit()
    print(json.dumps({
        "login": "admin@acme.com", "agent_credentials_shown_once": credentials,
        "next": "Store credentials in a password manager; they cannot be recovered from AgentGuard.",
    }, indent=2))


if __name__ == "__main__":
    main()
