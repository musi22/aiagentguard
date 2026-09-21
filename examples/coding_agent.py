"""GitHub operations routed through AgentGuard's real GitHub connector."""
from __future__ import annotations

import os
from agentguard import AgentGuard

guard = AgentGuard(
    api_key=os.environ["AGENTGUARD_API_KEY"],
    base_url=os.getenv("AGENTGUARD_GATEWAY_URL", "http://localhost:8001"),
)


def read_repository() -> dict:
    return guard.execute("github.read_repository", {}, idempotency_key="read-current-repository")


def create_branch(ref: str, sha: str) -> dict:
    return guard.execute("github.create_branch", {"ref": ref, "sha": sha}, idempotency_key=f"branch-{ref}-{sha}")


def merge_pull_request(number: int, sha: str) -> dict:
    return guard.execute(
        "github.merge_pull_request", {"pull_number": number, "sha": sha},
        idempotency_key=f"merge-pr-{number}-{sha}",
    )


def delete_repository() -> dict:
    # The seeded policy denies this before GitHub receives any HTTP request.
    return guard.execute("github.delete_repository", {}, idempotency_key="delete-repository")
