"""AgentGuard Python SDK.

Protected functions execute only after an allow/approved request is atomically
claimed. Their real return value or failure is then reported to AgentGuard.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import time
import uuid
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote

import httpx


class AgentGuardError(RuntimeError):
    """Base SDK exception."""


class AuthorizationDenied(AgentGuardError):
    def __init__(self, reason: str, request_id: str | None = None):
        super().__init__(reason)
        self.request_id = request_id


class ApprovalTimeout(AgentGuardError):
    pass


class ServiceUnavailable(AgentGuardError):
    pass


@dataclass(frozen=True)
class Decision:
    decision: str
    request_id: str
    reason: str
    risk_score: int | None = None
    approval_id: str | None = None
    status: str | None = None


class AgentGuard:
    def __init__(
        self,
        api_key: str,
        base_url: str = "http://localhost:8000",
        *,
        agent_id: str | None = None,
        timeout: float = 10.0,
        approval_timeout: float = 300.0,
        poll_interval: float = 1.0,
        client: httpx.Client | None = None,
        async_client: httpx.AsyncClient | None = None,
    ):
        if not api_key:
            raise ValueError("api_key is required")
        self.api_key, self.base_url, self.agent_id = api_key, base_url.rstrip("/"), agent_id
        self.timeout, self.approval_timeout, self.poll_interval = timeout, approval_timeout, poll_interval
        self._headers = {"Authorization": f"Bearer {api_key}", "User-Agent": "agentguard-python/0.1.0"}
        self._client = client or httpx.Client(timeout=timeout)
        self._async_client = async_client or httpx.AsyncClient(timeout=timeout)

    def close(self):
        self._client.close()

    async def aclose(self):
        await self._async_client.aclose()

    def _payload(self, tool: str, arguments: dict, context: dict | None, idempotency_key: str | None) -> dict:
        payload = {"tool": tool, "arguments": arguments, "context": context or {}}
        if self.agent_id:
            payload["agent_id"] = self.agent_id
        if idempotency_key:
            payload["idempotency_key"] = idempotency_key
        return payload

    @staticmethod
    def _data(response: httpx.Response) -> dict:
        try:
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ServiceUnavailable(
                "AgentGuard returned an invalid or failed response; action was not executed"
            ) from exc
        if not isinstance(data, dict):
            raise ServiceUnavailable("AgentGuard returned an invalid response; action was not executed")
        return data

    def _post(self, path: str, payload: dict, retry: bool = False, headers: dict | None = None) -> dict:
        attempts = 2 if retry else 1
        for index in range(attempts):
            try:
                return self._data(
                    self._client.post(self.base_url + path, json=payload, headers={**self._headers, **(headers or {})})
                )
            except (httpx.TransportError, TypeError) as exc:
                if index + 1 == attempts:
                    raise ServiceUnavailable("AgentGuard is unavailable; action was not executed") from exc
        raise AssertionError

    async def _apost(self, path: str, payload: dict, retry: bool = False, headers: dict | None = None) -> dict:
        attempts = 2 if retry else 1
        for index in range(attempts):
            try:
                return self._data(
                    await self._async_client.post(
                        self.base_url + path, json=payload, headers={**self._headers, **(headers or {})}
                    )
                )
            except (httpx.TransportError, TypeError) as exc:
                if index + 1 == attempts:
                    raise ServiceUnavailable("AgentGuard is unavailable; action was not executed") from exc
        raise AssertionError

    def authorize(
        self,
        tool: str,
        arguments: dict | None = None,
        *,
        context: dict | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        return self._post(
            "/api/v1/authorize",
            self._payload(tool, arguments or {}, context, idempotency_key),
            retry=bool(idempotency_key),
        )

    async def authorize_async(
        self,
        tool: str,
        arguments: dict | None = None,
        *,
        context: dict | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        return await self._apost(
            "/api/v1/authorize",
            self._payload(tool, arguments or {}, context, idempotency_key),
            retry=bool(idempotency_key),
        )

    def execute(
        self,
        tool: str,
        arguments: dict | None = None,
        *,
        context: dict | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        # Gateway-owned actions are not retried: a lost response may follow execution.
        initial = self._post("/api/v1/execute", self._payload(tool, arguments or {}, context, idempotency_key))
        if initial.get("decision") != "require_approval":
            return initial
        state = self._wait(initial)
        request_id = initial.get("request_id") or state.get("request_id")
        safe_id = quote(str(request_id), safe="")
        return self._post(f"/api/v1/requests/{safe_id}/execute", {})

    async def execute_async(
        self,
        tool: str,
        arguments: dict | None = None,
        *,
        context: dict | None = None,
        idempotency_key: str | None = None,
    ) -> dict:
        initial = await self._apost("/api/v1/execute", self._payload(tool, arguments or {}, context, idempotency_key))
        if initial.get("decision") != "require_approval":
            return initial
        state = await self._await(initial)
        request_id = initial.get("request_id") or state.get("request_id")
        safe_id = quote(str(request_id), safe="")
        return await self._apost(f"/api/v1/requests/{safe_id}/execute", {})

    def _wait(self, response: dict) -> dict:
        decision, request_id = response.get("decision"), response.get("request_id")
        if decision == "deny" or decision not in {"allow", "require_approval"}:
            raise AuthorizationDenied(response.get("reason", "Action denied"), request_id)
        if not request_id:
            raise ServiceUnavailable("AgentGuard omitted request_id; action was not executed")
        if decision == "allow":
            return response
        deadline = time.monotonic() + self.approval_timeout
        safe_id = quote(str(request_id), safe="")
        while time.monotonic() < deadline:
            try:
                state = self._data(
                    self._client.get(f"{self.base_url}/api/v1/requests/{safe_id}", headers=self._headers)
                )
            except httpx.TransportError as exc:
                raise ServiceUnavailable("Approval status unavailable; action was not executed") from exc
            status = state.get("status")
            if status in {"approved", "allowed"}:
                return state
            if status in {"rejected", "denied", "expired", "cancelled", "failed"}:
                raise AuthorizationDenied(state.get("reason", f"Approval {status}"), request_id)
            time.sleep(self.poll_interval)
        raise ApprovalTimeout(f"Approval timed out for request {request_id}")

    async def _await(self, response: dict) -> dict:
        decision, request_id = response.get("decision"), response.get("request_id")
        if decision == "deny" or decision not in {"allow", "require_approval"}:
            raise AuthorizationDenied(response.get("reason", "Action denied"), request_id)
        if not request_id:
            raise ServiceUnavailable("AgentGuard omitted request_id; action was not executed")
        if decision == "allow":
            return response
        deadline = time.monotonic() + self.approval_timeout
        safe_id = quote(str(request_id), safe="")
        while time.monotonic() < deadline:
            try:
                state = self._data(
                    await self._async_client.get(f"{self.base_url}/api/v1/requests/{safe_id}", headers=self._headers)
                )
            except httpx.TransportError as exc:
                raise ServiceUnavailable("Approval status unavailable; action was not executed") from exc
            status = state.get("status")
            if status in {"approved", "allowed"}:
                return state
            if status in {"rejected", "denied", "expired", "cancelled", "failed"}:
                raise AuthorizationDenied(state.get("reason", f"Approval {status}"), request_id)
            await asyncio.sleep(self.poll_interval)
        raise ApprovalTimeout(f"Approval timed out for request {request_id}")

    @staticmethod
    def _arguments(function: Callable, args: tuple, kwargs: dict) -> dict:
        bound = inspect.signature(function).bind(*args, **kwargs)
        bound.apply_defaults()
        return {name: value for name, value in bound.arguments.items() if name not in {"self", "cls"}}

    @staticmethod
    def _frozen_call(function: Callable, args: tuple, kwargs: dict, frozen: dict) -> tuple[tuple, dict]:
        """Rebind server-frozen (and possibly redacted) values to the real call."""
        if not isinstance(frozen, dict):
            raise ServiceUnavailable("AgentGuard claim omitted frozen arguments; action was not executed")
        signature = inspect.signature(function)
        bound = signature.bind(*args, **kwargs)
        for name, value in frozen.items():
            if name not in bound.arguments and name not in signature.parameters:
                raise ServiceUnavailable("AgentGuard returned an unknown frozen argument; action was not executed")
            bound.arguments[name] = value
        return bound.args, bound.kwargs

    @staticmethod
    def _claim(data: dict) -> tuple[str, dict]:
        token, arguments = data.get("claim_token"), data.get("arguments")
        if not isinstance(token, str) or not token or not isinstance(arguments, dict):
            raise ServiceUnavailable("AgentGuard returned an invalid execution claim; action was not executed")
        return token, arguments

    def protect(self, *, tool: str, context: dict | Callable[..., dict] | None = None):
        if not tool:
            raise ValueError("tool is required")

        def decorate(function: Callable):
            if inspect.iscoroutinefunction(function):

                @functools.wraps(function)
                async def async_wrapper(*args, **kwargs):
                    arguments = self._arguments(function, args, kwargs)
                    call_context = context(*args, **kwargs) if callable(context) else context
                    response = await self.authorize_async(
                        tool, arguments, context=call_context, idempotency_key=str(uuid.uuid4())
                    )
                    state = await self._await(response)
                    request_id = response.get("request_id") or state.get("request_id")
                    safe_id = quote(str(request_id), safe="")
                    claim_token, frozen = self._claim(await self._apost(f"/api/v1/requests/{safe_id}/claim", {}))
                    call_args, call_kwargs = self._frozen_call(function, args, kwargs, frozen)
                    try:
                        result = await function(*call_args, **call_kwargs)
                    except BaseException as exc:
                        try:
                            await self._apost(
                                f"/api/v1/requests/{safe_id}/result",
                                {"status": "failed", "result": {"error_type": type(exc).__name__}},
                                headers={"X-AgentGuard-Claim": claim_token},
                            )
                        finally:
                            raise
                    await self._apost(
                        f"/api/v1/requests/{safe_id}/result",
                        {"status": "succeeded", "result": result},
                        headers={"X-AgentGuard-Claim": claim_token},
                    )
                    return result

                return async_wrapper

            @functools.wraps(function)
            def wrapper(*args, **kwargs):
                arguments = self._arguments(function, args, kwargs)
                call_context = context(*args, **kwargs) if callable(context) else context
                response = self.authorize(tool, arguments, context=call_context, idempotency_key=str(uuid.uuid4()))
                state = self._wait(response)
                request_id = response.get("request_id") or state.get("request_id")
                safe_id = quote(str(request_id), safe="")
                claim_token, frozen = self._claim(self._post(f"/api/v1/requests/{safe_id}/claim", {}))
                call_args, call_kwargs = self._frozen_call(function, args, kwargs, frozen)
                try:
                    result = function(*call_args, **call_kwargs)
                except BaseException as exc:
                    try:
                        self._post(
                            f"/api/v1/requests/{safe_id}/result",
                            {"status": "failed", "result": {"error_type": type(exc).__name__}},
                            headers={"X-AgentGuard-Claim": claim_token},
                        )
                    finally:
                        raise
                self._post(
                    f"/api/v1/requests/{safe_id}/result",
                    {"status": "succeeded", "result": result},
                    headers={"X-AgentGuard-Claim": claim_token},
                )
                return result

            return wrapper

        return decorate


__all__ = ["AgentGuard", "AgentGuardError", "AuthorizationDenied", "ApprovalTimeout", "ServiceUnavailable", "Decision"]
