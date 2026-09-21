from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import get_db, set_tenant_context
from .models import ApiKey, Organization, OrganizationMember, User, UserSession
from .security import api_key_pepper, is_expired, parse_admin_key, verify_digest


@dataclass(frozen=True)
class Principal:
    user_id: str | None
    organization_id: str
    role: str
    via_cookie: bool
    scopes: tuple[str, ...] = ()


def _unauthorized() -> HTTPException:
    return HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")


def current_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer agu_"):
        raw = authorization.split(" ", 1)[1]
        parsed = parse_admin_key(raw)
        if not parsed:
            raise _unauthorized()
        organization_id, key_id = parsed
        set_tenant_context(db, organization_id)
        key = db.scalar(select(ApiKey).where(ApiKey.id == key_id, ApiKey.organization_id == organization_id))
        if not key or key.revoked_at or is_expired(key.expires_at) or not verify_digest(raw, key.key_hash, api_key_pepper()):
            raise _unauthorized()
        organization = db.get(Organization, organization_id)
        if not organization or not organization.active:
            raise _unauthorized()
        needed = "read" if request.method in {"GET", "HEAD", "OPTIONS"} else "write"
        if needed not in (key.scopes or []) and "admin" not in (key.scopes or []):
            raise HTTPException(status_code=403, detail=f"API key lacks {needed} scope")
        key.last_used_at = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        return Principal(None, organization_id, "api_key", False, tuple(key.scopes or []))

    raw = request.cookies.get("ag_access")
    if not raw and authorization.lower().startswith("bearer "):
        raw = authorization.split(" ", 1)[1]
    if not raw:
        raise _unauthorized()
    session = db.scalar(select(UserSession).where(UserSession.access_hash == verify_token_hash(raw)))
    if not session or session.revoked_at or is_expired(session.access_expires_at):
        raise _unauthorized()
    set_tenant_context(db, session.organization_id)
    member = db.scalar(
        select(OrganizationMember).where(
            OrganizationMember.organization_id == session.organization_id,
            OrganizationMember.user_id == session.user_id,
            OrganizationMember.status == "active",
        )
    )
    user = db.get(User, session.user_id)
    organization = db.get(Organization, session.organization_id)
    if not member or not user or not user.active or not organization or not organization.active:
        raise _unauthorized()
    if request.method not in {"GET", "HEAD", "OPTIONS"} and request.cookies.get("ag_access"):
        csrf = request.headers.get("x-csrf-token", "")
        if not csrf or not verify_digest(csrf, session.csrf_hash):
            raise HTTPException(status_code=403, detail="CSRF validation failed")
    return Principal(session.user_id, session.organization_id, member.role, bool(request.cookies.get("ag_access")))


def verify_token_hash(raw: str) -> str:
    from .security import digest_secret

    return digest_secret(raw)


def require_roles(*roles: str):
    def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if principal.role != "api_key" and principal.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return principal

    return dependency
