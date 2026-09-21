from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from . import models  # noqa: F401 - registers SQLAlchemy metadata
from .admin_routes import router as admin_router
from .auth_routes import router as auth_router
from .config import configure_logging, get_settings
from .database import Base, SessionLocal, engine
from .runtime_routes import router as runtime_router
from .security import get_payload_cipher
from .webhook_routes import router as webhook_router

settings = get_settings()
configure_logging(settings)


class BodyLimitMiddleware:
    def __init__(self, app: Any, max_bytes: int):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope: dict, receive: Callable[..., Awaitable[dict]], send: Callable[..., Awaitable[None]]) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        consumed = 0

        async def limited_receive() -> dict:
            nonlocal consumed
            message = await receive()
            if message.get("type") == "http.request":
                consumed += len(message.get("body", b""))
                if consumed > self.max_bytes:
                    raise ValueError("request body too large")
            return message

        try:
            await self.app(scope, limited_receive, send)
        except ValueError as exc:
            if str(exc) != "request body too large":
                raise
            response = JSONResponse({"detail": "Request body too large"}, status_code=413)
            await response(scope, receive, send)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.environment in {"development", "test"}:
        Base.metadata.create_all(engine)
    # Fail at startup in production if Managed Identity cannot obtain encryption material.
    get_payload_cipher()
    yield


app = FastAPI(
    title="AgentGuard API", version="0.1.0",
    description="Runtime authorization, approval gates, spending controls, and audit infrastructure for AI agents.",
    docs_url="/docs" if settings.environment != "production" else None,
    redoc_url=None, lifespan=lifespan,
)
app.add_middleware(BodyLimitMiddleware, max_bytes=settings.request_body_limit_bytes)
app.add_middleware(
    CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token", "X-Correlation-ID", "X-AgentGuard-Claim"],
)


@app.middleware("http")
async def security_and_correlation(request: Request, call_next):
    started = time.perf_counter()
    correlation_id = request.headers.get("x-correlation-id") or __import__("secrets").token_urlsafe(12)
    request.state.correlation_id = correlation_id
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Server-Timing"] = f"app;dur={(time.perf_counter() - started) * 1000:.2f}"
    return response


app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(runtime_router)
app.include_router(webhook_router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "time": datetime.now(timezone.utc)}


@app.get("/ready")
def ready() -> dict:
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
        return {"status": "ok", "time": datetime.now(timezone.utc)}
    except Exception:
        return JSONResponse({"status": "degraded", "time": datetime.now(timezone.utc).isoformat()}, status_code=503)


if settings.applicationinsights_connection_string:
    from azure.monitor.opentelemetry import configure_azure_monitor
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    configure_azure_monitor(connection_string=settings.applicationinsights_connection_string)
    FastAPIInstrumentor.instrument_app(app, excluded_urls="health,ready")
