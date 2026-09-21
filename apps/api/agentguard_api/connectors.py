from __future__ import annotations

import ipaddress
import json
import re
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlparse

import httpx

from .config import get_settings
from .models import AuthorizationRequest, Tool
from .security import get_secret_store


class ConnectorError(RuntimeError):
    pass


@dataclass
class ConnectorResult:
    status: str
    result: Any


def _safe_url(url: str, *, allowed_hosts: list[str] | None = None) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ConnectorError("Connector URL must be an HTTPS origin without embedded credentials")
    host = parsed.hostname.lower().rstrip(".")
    if host in {"localhost", "metadata.google.internal"} or host.endswith((".local", ".internal")):
        raise ConnectorError("Private connector destinations are blocked")
    if allowed_hosts and host not in {item.lower().rstrip(".") for item in allowed_hosts}:
        raise ConnectorError("Connector destination is not on the configured allowlist")
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, parsed.port or 443, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise ConnectorError("Connector destination cannot be resolved") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ConnectorError("Connector destination resolves to a non-public address")
    return url


def _json_response(response: httpx.Response) -> Any:
    response.raise_for_status()
    content_type = response.headers.get("content-type", "")
    if "json" in content_type:
        value = response.json()
        return value if len(json.dumps(value, default=str)) <= 1_048_576 else {"truncated": True}
    text = response.text
    return {"text": text[:65_536], "truncated": len(text) > 65_536}


def _http(tool: Tool, request: AuthorizationRequest, arguments: dict[str, Any]) -> ConnectorResult:
    url = str(tool.config.get("url", ""))
    _safe_url(url, allowed_hosts=tool.config.get("allowed_hosts"))
    method = str(tool.config.get("method", "POST")).upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise ConnectorError("Unsupported HTTP method")
    headers = {"Accept": "application/json", "User-Agent": "AgentGuard/0.1"}
    secret_ref = tool.config.get("secret_ref")
    if secret_ref:
        token = get_secret_store().get(str(secret_ref))
        header = str(tool.config.get("auth_header", "Authorization"))
        prefix = str(tool.config.get("auth_prefix", "Bearer "))
        headers[header] = prefix + str(token)
    if request.idempotency_key:
        headers["Idempotency-Key"] = request.idempotency_key
    with httpx.Client(timeout=get_settings().connector_timeout_seconds, follow_redirects=False) as client:
        if method == "GET":
            response = client.request(method, url, params=arguments, headers=headers)
        else:
            response = client.request(method, url, json=arguments, headers=headers)
    return ConnectorResult("succeeded", _json_response(response))


def _stripe(tool: Tool, request: AuthorizationRequest, arguments: dict[str, Any]) -> ConnectorResult:
    if tool.name != "stripe.refund":
        raise ConnectorError("Unsupported Stripe operation")
    if not request.idempotency_key:
        raise ConnectorError("Stripe writes require an idempotency key")
    secret_ref = str(tool.config.get("secret_ref", "stripe-secret-key"))
    secret = get_secret_store().get(secret_ref)
    data: dict[str, str | int] = {}
    for field in ("charge", "payment_intent", "reason", "metadata"):
        if field in arguments:
            data[field] = arguments[field]
    if "amount" in arguments:
        from .limits import amount_to_minor

        data["amount"] = amount_to_minor(arguments)
    headers = {"Authorization": f"Bearer {secret}", "Idempotency-Key": request.idempotency_key}
    response = httpx.post(
        "https://api.stripe.com/v1/refunds", data=data, headers=headers,
        timeout=get_settings().connector_timeout_seconds,
    )
    return ConnectorResult("succeeded", _json_response(response))


_SLUG = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


def _github(tool: Tool, request: AuthorizationRequest, arguments: dict[str, Any]) -> ConnectorResult:
    owner, repo = str(tool.config.get("owner", "")), str(tool.config.get("repo", ""))
    if not _SLUG.fullmatch(owner) or not _SLUG.fullmatch(repo):
        raise ConnectorError("GitHub connector needs valid preconfigured owner and repository")
    token = get_secret_store().get(str(tool.config.get("secret_ref", "github-token")))
    base = f"https://api.github.com/repos/{quote(owner)}/{quote(repo)}"
    headers = {
        "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "AgentGuard/0.1",
    }
    if tool.name in {"github.read", "github.read_repository"}:
        method, url, payload = "GET", base, None
    elif tool.name == "github.create_branch":
        ref, sha = str(arguments.get("ref", "")), str(arguments.get("sha", ""))
        if not ref.startswith("refs/heads/") or not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
            raise ConnectorError("create_branch requires refs/heads/... and a full commit SHA")
        method, url, payload = "POST", f"{base}/git/refs", {"ref": ref, "sha": sha}
    elif tool.name == "github.merge_pull_request":
        number = int(arguments.get("pull_number", 0))
        if number < 1:
            raise ConnectorError("merge_pull_request requires pull_number")
        method, url = "PUT", f"{base}/pulls/{number}/merge"
        payload = {key: arguments[key] for key in ("commit_title", "commit_message", "sha", "merge_method") if key in arguments}
    elif tool.name == "github.delete_repository":
        method, url, payload = "DELETE", base, None
    else:
        raise ConnectorError("Unsupported GitHub operation")
    with httpx.Client(timeout=get_settings().connector_timeout_seconds, follow_redirects=False) as client:
        response = client.request(method, url, json=payload, headers=headers)
    return ConnectorResult("succeeded", _json_response(response))


def _postgres(tool: Tool, request: AuthorizationRequest, arguments: dict[str, Any]) -> ConnectorResult:
    import psycopg
    from psycopg.rows import dict_row

    statement = tool.config.get("statement")
    if not isinstance(statement, str) or not statement.strip() or len(statement) > 100_000:
        raise ConnectorError("PostgreSQL connector requires an administrator-defined statement")
    secret_ref = str(tool.config.get("secret_ref", "postgres-connection-string"))
    connection_string = get_secret_store().get(secret_ref)
    timeout_ms = int(get_settings().connector_timeout_seconds * 1000)
    with psycopg.connect(connection_string, connect_timeout=max(1, int(timeout_ms / 1000)), row_factory=dict_row) as connection:
        with connection.transaction():
            connection.execute("SET LOCAL statement_timeout = %s", (timeout_ms,))
            cursor = connection.execute(statement, arguments)
            rows = cursor.fetchmany(1001) if cursor.description else []
            if len(rows) > 1000:
                rows = rows[:1000]
                truncated = True
            else:
                truncated = False
    return ConnectorResult("succeeded", {"rows": rows, "row_count": len(rows), "truncated": truncated})


def _mcp(tool: Tool, request: AuthorizationRequest, arguments: dict[str, Any]) -> ConnectorResult:
    url = str(tool.config.get("url", ""))
    _safe_url(url, allowed_hosts=tool.config.get("allowed_hosts"))
    mcp_tool = str(tool.config.get("tool", ""))
    if not mcp_tool:
        raise ConnectorError("MCP connector requires a fixed tool name")
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    secret_ref = tool.config.get("secret_ref")
    if secret_ref:
        headers["Authorization"] = f"Bearer {get_secret_store().get(str(secret_ref))}"
    payload = {"jsonrpc": "2.0", "id": request.id, "method": "tools/call", "params": {"name": mcp_tool, "arguments": arguments}}
    response = httpx.post(url, json=payload, headers=headers, timeout=get_settings().connector_timeout_seconds)
    result = _json_response(response)
    if isinstance(result, dict) and result.get("error"):
        raise ConnectorError(f"MCP tool error: {str(result['error'])[:500]}")
    return ConnectorResult("succeeded", result)


def execute_connector(tool: Tool, request: AuthorizationRequest, arguments: dict[str, Any]) -> ConnectorResult:
    if tool.adapter == "sdk":
        raise ConnectorError("SDK tools execute in the calling process through a one-time claim")
    connector = {
        "http": _http, "stripe": _stripe, "github": _github, "postgres": _postgres, "mcp": _mcp,
    }.get(tool.adapter)
    if not connector:
        raise ConnectorError(f"Unsupported connector adapter: {tool.adapter}")
    try:
        return connector(tool, request, arguments)
    except httpx.HTTPStatusError as exc:
        raise ConnectorError(f"Provider returned HTTP {exc.response.status_code}") from exc
    except httpx.HTTPError as exc:
        raise ConnectorError("Provider request failed") from exc
