from __future__ import annotations

import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

API_URL = os.getenv("AGENTGUARD_API_INTERNAL_URL", "http://localhost:8000").rstrip("/")
MAX_BODY = int(os.getenv("REQUEST_BODY_LIMIT_BYTES", "262144"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.client = httpx.AsyncClient(timeout=30, follow_redirects=False, limits=httpx.Limits(max_connections=200))
    yield
    await app.state.client.aclose()


app = FastAPI(title="AgentGuard Gateway", version="0.1.0", docs_url=None, redoc_url=None, lifespan=lifespan)


async def proxy(request: Request, path: str) -> Response:
    body = await request.body()
    if len(body) > MAX_BODY:
        return JSONResponse({"detail": "Request body too large"}, status_code=413)
    headers = {
        key: value for key, value in request.headers.items()
        if key.lower() in {"authorization", "content-type", "x-correlation-id", "x-agentguard-claim", "idempotency-key"}
    }
    try:
        upstream = await request.app.state.client.request(
            request.method, f"{API_URL}{path}", content=body, headers=headers,
        )
    except httpx.HTTPError:
        return JSONResponse(
            {"decision": "deny", "reason": "Authorization service unavailable; action was not executed"}, status_code=503
        )
    excluded = {"content-length", "connection", "transfer-encoding", "content-encoding"}
    response_headers = {key: value for key, value in upstream.headers.items() if key.lower() not in excluded}
    return Response(upstream.content, status_code=upstream.status_code, headers=response_headers,
                    media_type=upstream.headers.get("content-type"))


@app.api_route("/api/v1/authorize", methods=["POST"])
async def authorize(request: Request) -> Response:
    return await proxy(request, "/api/v1/authorize")


@app.api_route("/api/v1/execute", methods=["POST"])
async def execute(request: Request) -> Response:
    return await proxy(request, "/api/v1/execute")


@app.api_route("/api/v1/requests/{request_id}", methods=["GET"])
async def status(request_id: str, request: Request) -> Response:
    return await proxy(request, f"/api/v1/requests/{request_id}")


@app.api_route("/api/v1/requests/{request_id}/{action}", methods=["POST"])
async def request_action(request_id: str, action: str, request: Request) -> Response:
    if action not in {"claim", "result", "execute"}:
        return JSONResponse({"detail": "Not found"}, status_code=404)
    return await proxy(request, f"/api/v1/requests/{request_id}/{action}")


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/ready")
async def ready(request: Request) -> Response:
    try:
        response = await request.app.state.client.get(f"{API_URL}/ready", timeout=3)
        if response.is_success:
            return JSONResponse({"status": "ok"})
    except httpx.HTTPError:
        pass
    return JSONResponse({"status": "degraded"}, status_code=503)
