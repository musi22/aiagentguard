import asyncio

import httpx
import pytest

from agentguard import AgentGuard, AuthorizationDenied, ServiceUnavailable


def response(method, path, data, status=200):
    return httpx.Response(status, json=data, request=httpx.Request(method, "https://guard.test" + path))


def test_sync_protect_binds_executes_and_reports():
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path, request.content))
        assert request.headers["Authorization"] == "Bearer ag_secret"
        if request.url.path == "/api/v1/authorize":
            return response("POST", request.url.path, {"decision": "allow", "request_id": "req-1", "reason": "ok"})
        if request.url.path.endswith("/claim"):
            return response(
                "POST", request.url.path, {"claim_token": "claim-secret", "arguments": {"a": 4, "b": 2}, "context": {}}
            )
        assert request.headers["X-AgentGuard-Claim"] == "claim-secret"
        return response(
            "POST", request.url.path, {"status": "ok", "request_id": "req-1", "decision": "allow", "reason": "ok"}
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    guard = AgentGuard("ag_secret", "https://guard.test", client=client)
    executed = []

    @guard.protect(tool="math.add")
    def add(a, b=2):
        executed.append(True)
        return a + b

    assert add(3) == 6 and executed  # executes the server-frozen values, not mutable caller state
    assert [path for _, path, _ in calls] == [
        "/api/v1/authorize",
        "/api/v1/requests/req-1/claim",
        "/api/v1/requests/req-1/result",
    ]
    assert b'"a":3' in calls[0][2] and b'"b":2' in calls[0][2]


def test_denied_and_network_failure_fail_closed():
    ran = []
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: response("POST", request.url.path, {"decision": "deny", "request_id": "r", "reason": "no"})
        )
    )
    guard = AgentGuard("key", "https://guard.test", client=client)

    @guard.protect(tool="danger")
    def danger():
        ran.append(True)

    with pytest.raises(AuthorizationDenied):
        danger()
    assert not ran

    attempts = []

    def fail(request):
        attempts.append(1)
        raise httpx.ConnectError("offline", request=request)

    guard = AgentGuard("key", "https://guard.test", client=httpx.Client(transport=httpx.MockTransport(fail)))
    with pytest.raises(ServiceUnavailable):
        guard.authorize("x")
    assert len(attempts) == 1  # no idempotency key means no authorization retry


def test_safe_authorize_retry_but_execute_never_retries():
    attempts = []

    def flaky(request):
        attempts.append(request.url.path)
        raise httpx.ConnectError("lost", request=request)

    guard = AgentGuard("key", "https://guard.test", client=httpx.Client(transport=httpx.MockTransport(flaky)))
    with pytest.raises(ServiceUnavailable):
        guard.authorize("x", idempotency_key="idem")
    assert len(attempts) == 2
    attempts.clear()
    with pytest.raises(ServiceUnavailable):
        guard.execute("x", idempotency_key="idem")
    assert len(attempts) == 1


def test_gateway_execute_waits_then_resumes_once():
    calls = []
    poll_count = 0

    def handler(request):
        nonlocal poll_count
        calls.append((request.method, request.url.path))
        if request.url.path == "/api/v1/execute":
            return response(
                "POST",
                request.url.path,
                {
                    "decision": "require_approval",
                    "request_id": "remote",
                    "reason": "approval",
                    "status": "pending_approval",
                },
            )
        if request.method == "GET":
            poll_count += 1
            return response(
                "GET",
                request.url.path,
                {
                    "decision": "require_approval",
                    "request_id": "remote",
                    "reason": "approved",
                    "status": "pending_approval" if poll_count == 1 else "approved",
                },
            )
        return response(
            "POST",
            request.url.path,
            {"decision": "allow", "request_id": "remote", "reason": "executed", "status": "succeeded", "result": 42},
        )

    guard = AgentGuard(
        "key", "https://guard.test", poll_interval=0, client=httpx.Client(transport=httpx.MockTransport(handler))
    )
    result = guard.execute("remote.action", {"value": 1}, idempotency_key="same-request")
    assert result["result"] == 42
    assert calls == [
        ("POST", "/api/v1/execute"),
        ("GET", "/api/v1/requests/remote"),
        ("GET", "/api/v1/requests/remote"),
        ("POST", "/api/v1/requests/remote/execute"),
    ]


def test_async_protect_real_result():
    async def scenario():
        calls = []

        async def handler(request):
            calls.append(request.url.path)
            if request.url.path.endswith("/claim"):
                return response(
                    request.method,
                    request.url.path,
                    {"claim_token": "async-claim", "arguments": {"value": 5}, "context": {}},
                )
            if request.url.path.endswith("/result"):
                assert request.headers["X-AgentGuard-Claim"] == "async-claim"
            return response(
                request.method,
                request.url.path,
                {"decision": "allow", "request_id": "ar", "reason": "ok", "status": "ok"},
            )

        async_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        guard = AgentGuard("key", "https://guard.test", async_client=async_client)

        @guard.protect(tool="async.real")
        async def real(value):
            await asyncio.sleep(0)
            return {"value": value}

        assert await real(4) == {"value": 5}
        assert calls == ["/api/v1/authorize", "/api/v1/requests/ar/claim", "/api/v1/requests/ar/result"]
        await guard.aclose()

    asyncio.run(scenario())
