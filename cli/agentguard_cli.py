"""Scriptable AgentGuard command line client."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

import httpx
from agentguard import AgentGuard, AgentGuardError


def json_value(value: str) -> Any:
    if value.startswith("@"):
        value = Path(value[1:]).read_text(encoding="utf-8")
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(f"invalid JSON: {exc}") from exc


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="agentguard", description="Manage and invoke AgentGuard")
    root.add_argument("--url", default=os.getenv("AGENTGUARD_URL", "http://localhost:8000"))
    root.add_argument("--api-key", default=os.getenv("AGENTGUARD_API_KEY"))
    sub = root.add_subparsers(dest="command", required=True)
    for resource in ("agents", "tools", "policies"):
        group = sub.add_parser(resource)
        actions = group.add_subparsers(dest="action", required=True)
        actions.add_parser("list")
        get = actions.add_parser("get")
        get.add_argument("id")
        create = actions.add_parser("create")
        create.add_argument("--data", required=True, type=json_value)
        update = actions.add_parser("update")
        update.add_argument("id")
        update.add_argument("--data", required=True, type=json_value)
        delete = actions.add_parser("delete")
        delete.add_argument("id")
    for name in ("authorize", "execute"):
        action = sub.add_parser(name)
        action.add_argument("tool")
        action.add_argument("--agent-id")
        action.add_argument("--arguments", default={}, type=json_value)
        action.add_argument("--context", default={}, type=json_value)
        action.add_argument("--idempotency-key")
    audit = sub.add_parser("audit")
    audit.add_argument("--request-id")
    audit.add_argument("--limit", type=int, default=50)
    approval = sub.add_parser("approval")
    ap = approval.add_subparsers(dest="action", required=True)
    status = ap.add_parser("status")
    status.add_argument("request_id")
    decide = ap.add_parser("decide")
    decide.add_argument("approval_id")
    decide.add_argument("decision", choices=["approve", "reject"])
    decide.add_argument("--reason")
    return root


def direct(client: httpx.Client, args: argparse.Namespace) -> Any:
    base = f"/api/v1/{args.command}"
    if args.action == "list":
        response = client.get(base)
    elif args.action == "get":
        response = client.get(f"{base}/{args.id}")
    elif args.action == "create":
        response = client.post(base, json=args.data)
    elif args.action == "update":
        response = client.patch(f"{base}/{args.id}", json=args.data)
    else:
        response = client.delete(f"{base}/{args.id}")
    response.raise_for_status()
    return response.json() if response.content else {"status": "ok"}


def run(args: argparse.Namespace) -> Any:
    if not args.api_key:
        raise ValueError("API key required: pass --api-key or set AGENTGUARD_API_KEY")
    if args.command in {"authorize", "execute"}:
        guard = AgentGuard(args.api_key, args.url, agent_id=args.agent_id)
        try:
            method = guard.authorize if args.command == "authorize" else guard.execute
            return method(args.tool, args.arguments, context=args.context, idempotency_key=args.idempotency_key)
        finally:
            guard.close()
    headers = {"Authorization": f"Bearer {args.api_key}"}
    with httpx.Client(base_url=args.url.rstrip("/"), headers=headers, timeout=10) as client:
        if args.command in {"agents", "tools", "policies"}:
            return direct(client, args)
        if args.command == "audit":
            response = client.get(
                "/api/v1/audit",
                params={
                    key: value
                    for key, value in {"request_id": args.request_id, "limit": args.limit}.items()
                    if value is not None
                },
            )
        elif args.action == "status":
            response = client.get(f"/api/v1/requests/{args.request_id}")
        else:
            response = client.post(
                f"/api/v1/approvals/{args.approval_id}/{args.decision}",
                json={"reason": args.reason} if args.reason else {},
            )
        response.raise_for_status()
        return response.json()


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result = run(args)
    except (AgentGuardError, httpx.HTTPError, ValueError, OSError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
