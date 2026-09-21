from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .config import get_settings
from .connectors import _safe_url
from .database import get_db, set_tenant_context
from .dependencies import Principal, current_principal
from .models import (
    MagicLink, OAuthFlow, OAuthIdentity, Organization, OrganizationMember, Team, User, UserSession, Workspace, new_id,
)
from .schemas import LoginInput, MagicLinkConsumeInput, MagicLinkInput, RegisterInput
from .security import (
    digest_secret, get_payload_cipher, get_secret_store, hash_password, is_expired, random_token, verify_password,
)

router = APIRouter(prefix="/api/v1/auth", tags=["authentication"])


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:70] or "organization"
    return f"{cleaned}-{random_token(4).lower()}"


def _cookies(response: Response, access: str, refresh: str) -> None:
    settings = get_settings()
    response.set_cookie(
        "ag_access", access, max_age=settings.access_token_ttl_seconds, httponly=True, secure=settings.session_secure,
        samesite="lax", path="/",
    )
    response.set_cookie(
        "ag_refresh", refresh, max_age=settings.refresh_token_ttl_seconds, httponly=True,
        secure=settings.session_secure, samesite="strict", path="/api/v1/auth",
    )


def _clear_cookies(response: Response) -> None:
    response.delete_cookie("ag_access", path="/")
    response.delete_cookie("ag_refresh", path="/api/v1/auth")


def _issue_session(db: Session, user_id: str, organization_id: str, response: Response) -> str:
    set_tenant_context(db, organization_id)
    user = db.get(User, user_id)
    organization = db.get(Organization, organization_id)
    member = db.scalar(select(OrganizationMember).where(
        OrganizationMember.user_id == user_id, OrganizationMember.organization_id == organization_id,
        OrganizationMember.status == "active",
    ))
    if not user or not user.active or not organization or not organization.active or not member:
        raise HTTPException(status_code=403, detail="No active account or organization membership")
    settings = get_settings()
    access, refresh, csrf = random_token(), random_token(), random_token()
    now = datetime.now(timezone.utc)
    db.add(UserSession(
        user_id=user_id, organization_id=organization_id,
        access_hash=digest_secret(access), refresh_hash=digest_secret(refresh), csrf_hash=digest_secret(csrf),
        access_expires_at=now + timedelta(seconds=settings.access_token_ttl_seconds),
        refresh_expires_at=now + timedelta(seconds=settings.refresh_token_ttl_seconds),
    ))
    _cookies(response, access, refresh)
    return csrf


def _me(db: Session, principal: Principal, csrf_token: str | None = None) -> dict:
    if principal.user_id is None:
        return {"user": None, "organization": {"id": principal.organization_id}, "role": "api_key", "csrf_token": None}
    user = db.get(User, principal.user_id)
    organization = db.get(Organization, principal.organization_id)
    workspaces = db.scalars(select(Workspace).where(Workspace.organization_id == principal.organization_id)).all()
    teams = db.scalars(select(Team).where(Team.organization_id == principal.organization_id)).all()
    return {
        "user": {"id": user.id, "email": user.email, "name": user.name},
        "organization": {"id": organization.id, "name": organization.name, "plan": organization.plan},
        "role": principal.role, "csrf_token": csrf_token,
        "workspaces": [{"id": item.id, "name": item.name, "environment": item.environment} for item in workspaces],
        "teams": [{"id": item.id, "name": item.name, "workspace_id": item.workspace_id} for item in teams],
    }


@router.post("/register", status_code=201)
def register(payload: RegisterInput, response: Response, db: Session = Depends(get_db)) -> dict:
    email = str(payload.email).lower()
    if db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    user = User(email=email, name=payload.name, password_hash=hash_password(payload.password))
    organization = Organization(id=new_id(), name=payload.organization_name, slug=_slug(payload.organization_name), plan="free")
    set_tenant_context(db, organization.id)
    db.add_all([user, organization])
    db.flush()
    workspace = Workspace(organization_id=organization.id, name="Default", environment="development")
    db.add(workspace)
    db.add(OrganizationMember(organization_id=organization.id, user_id=user.id, role="owner", status="active"))
    db.flush()
    csrf = _issue_session(db, user.id, organization.id, response)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="Account could not be created") from exc
    principal = Principal(user.id, organization.id, "owner", True)
    return _me(db, principal, csrf)


_DUMMY_HASH = hash_password("not-a-real-password-for-timing")


@router.post("/login")
def login(payload: LoginInput, response: Response, db: Session = Depends(get_db)) -> dict:
    user = db.scalar(select(User).where(User.email == str(payload.email).lower()))
    password_hash = user.password_hash if user else _DUMMY_HASH
    valid = verify_password(payload.password, password_hash)
    if user and user.locked_until and not is_expired(user.locked_until):
        valid = False
    if not valid:
        if user:
            user.failed_login_count += 1
            if user.failed_login_count >= 5:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
                user.failed_login_count = 0
            db.commit()
        raise HTTPException(status_code=401, detail="Invalid email or password")
    member = db.scalar(
        select(OrganizationMember).where(OrganizationMember.user_id == user.id, OrganizationMember.status == "active")
    )
    if not member:
        raise HTTPException(status_code=403, detail="No active organization membership")
    user.failed_login_count = 0
    user.locked_until = None
    csrf = _issue_session(db, user.id, member.organization_id, response)
    db.commit()
    return _me(db, Principal(user.id, member.organization_id, member.role, True), csrf)


@router.get("/me")
def me(
    request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)
) -> dict:
    csrf = None
    if principal.via_cookie:
        raw = request.cookies.get("ag_access", "")
        session = db.scalar(select(UserSession).where(UserSession.access_hash == digest_secret(raw)))
        # The raw CSRF token is intentionally not recoverable. Login/refresh responses deliver a new one.
        csrf = request.headers.get("x-csrf-token") if session else None
    return _me(db, principal, csrf)


@router.post("/refresh")
def refresh(request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    raw = request.cookies.get("ag_refresh", "")
    session = db.scalar(select(UserSession).where(UserSession.refresh_hash == digest_secret(raw)).with_for_update()) if raw else None
    if not session or session.revoked_at or is_expired(session.refresh_expires_at):
        _clear_cookies(response)
        raise HTTPException(status_code=401, detail="Refresh token is invalid")
    set_tenant_context(db, session.organization_id)
    member = db.scalar(select(OrganizationMember).where(
        OrganizationMember.organization_id == session.organization_id, OrganizationMember.user_id == session.user_id,
        OrganizationMember.status == "active",
    ))
    user, organization = db.get(User, session.user_id), db.get(Organization, session.organization_id)
    if not member or not user or not user.active or not organization or not organization.active:
        raise HTTPException(status_code=403, detail="Account or membership is inactive")
    access, refresh_token, csrf = random_token(), random_token(), random_token()
    now = datetime.now(timezone.utc)
    settings = get_settings()
    session.access_hash = digest_secret(access)
    session.refresh_hash = digest_secret(refresh_token)
    session.csrf_hash = digest_secret(csrf)
    session.access_expires_at = now + timedelta(seconds=settings.access_token_ttl_seconds)
    session.refresh_expires_at = now + timedelta(seconds=settings.refresh_token_ttl_seconds)
    _cookies(response, access, refresh_token)
    db.commit()
    member = db.scalar(select(OrganizationMember).where(
        OrganizationMember.organization_id == session.organization_id, OrganizationMember.user_id == session.user_id
    ))
    return _me(db, Principal(session.user_id, session.organization_id, member.role, True), csrf)


@router.post("/logout", status_code=204)
def logout(
    request: Request, response: Response, _: Principal = Depends(current_principal), db: Session = Depends(get_db)
) -> Response:
    raw = request.cookies.get("ag_access", "")
    if not raw and request.headers.get("authorization", "").lower().startswith("bearer "):
        raw = request.headers["authorization"].split(" ", 1)[1]
    session = db.scalar(select(UserSession).where(UserSession.access_hash == digest_secret(raw))) if raw else None
    if session:
        session.revoked_at = datetime.now(timezone.utc)
        db.commit()
    _clear_cookies(response)
    response.status_code = 204
    return response


@router.post("/magic-link")
def request_magic_link(payload: MagicLinkInput, db: Session = Depends(get_db)) -> dict:
    user = db.scalar(select(User).where(User.email == str(payload.email).lower()))
    dev_token: str | None = None
    if user:
        token = random_token(40)
        db.add(MagicLink(
            user_id=user.id, token_hash=digest_secret(token),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=15),
        ))
        db.commit()
        settings = get_settings()
        link = f"{settings.web_url.rstrip('/')}/auth/magic?token={token}"
        if settings.magic_link_webhook_url:
            _safe_url(settings.magic_link_webhook_url)
            secret = get_secret_store().get(settings.magic_link_secret_ref)
            httpx.post(
                settings.magic_link_webhook_url,
                json={"to": user.email, "template": "agentguard_magic_link", "variables": {"link": link}},
                headers={"Authorization": f"Bearer {secret}"}, timeout=10, follow_redirects=False,
            ).raise_for_status()
        elif settings.environment in {"development", "test"}:
            dev_token = token
        else:
            raise HTTPException(status_code=503, detail="Magic-link delivery is not configured")
    response = {"message": "If the account exists, a sign-in link was sent"}
    if dev_token:
        response["development_token"] = dev_token
    return response


@router.post("/magic-link/consume")
def consume_magic_link(payload: MagicLinkConsumeInput, response: Response, db: Session = Depends(get_db)) -> dict:
    link = db.scalar(select(MagicLink).where(MagicLink.token_hash == digest_secret(payload.token)).with_for_update())
    if not link or link.consumed_at or is_expired(link.expires_at):
        raise HTTPException(status_code=401, detail="Magic link is invalid or expired")
    member = db.scalar(select(OrganizationMember).where(
        OrganizationMember.user_id == link.user_id, OrganizationMember.status == "active"
    ))
    if not member:
        raise HTTPException(status_code=403, detail="No active organization membership")
    link.consumed_at = datetime.now(timezone.utc)
    csrf = _issue_session(db, link.user_id, member.organization_id, response)
    db.commit()
    return _me(db, Principal(link.user_id, member.organization_id, member.role, True), csrf)


_OAUTH = {
    "microsoft": {
        "authorize": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "userinfo": "https://graph.microsoft.com/oidc/userinfo", "scope": "openid profile email",
    },
    "google": {
        "authorize": "https://accounts.google.com/o/oauth2/v2/auth",
        "token": "https://oauth2.googleapis.com/token",
        "userinfo": "https://openidconnect.googleapis.com/v1/userinfo", "scope": "openid profile email",
    },
    "github": {
        "authorize": "https://github.com/login/oauth/authorize",
        "token": "https://github.com/login/oauth/access_token",
        "userinfo": "https://api.github.com/user", "scope": "read:user user:email",
    },
}


def _client_id(provider: str) -> str | None:
    return getattr(get_settings(), f"{provider}_client_id", None)


@router.get("/providers")
def auth_providers() -> dict:
    return {provider: bool(_client_id(provider)) for provider in _OAUTH}


@router.get("/oauth/{provider}/start")
def oauth_start(provider: str, db: Session = Depends(get_db)) -> RedirectResponse:
    definition, client_id = _OAUTH.get(provider), _client_id(provider)
    if not definition or not client_id:
        raise HTTPException(status_code=404, detail="OAuth provider is not configured")
    state, verifier = random_token(32), random_token(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    db.add(OAuthFlow(
        provider=provider, state_hash=digest_secret(state),
        encrypted_verifier=get_payload_cipher().encrypt({"verifier": verifier}),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
    ))
    db.commit()
    redirect_uri = f"{get_settings().public_url.rstrip('/')}/api/v1/auth/oauth/{provider}/callback"
    params = {
        "client_id": client_id, "redirect_uri": redirect_uri, "response_type": "code",
        "scope": definition["scope"], "state": state, "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    response = RedirectResponse(definition["authorize"] + "?" + urlencode(params), status_code=302)
    response.set_cookie("ag_oauth_state", state, max_age=600, httponly=True, secure=get_settings().session_secure, samesite="lax")
    return response


@router.get("/oauth/{provider}/callback")
def oauth_callback(provider: str, code: str, state: str, request: Request, db: Session = Depends(get_db)) -> RedirectResponse:
    definition, client_id = _OAUTH.get(provider), _client_id(provider)
    if not definition or not client_id or request.cookies.get("ag_oauth_state") != state:
        raise HTTPException(status_code=401, detail="OAuth state validation failed")
    flow = db.scalar(select(OAuthFlow).where(OAuthFlow.state_hash == digest_secret(state)))
    if not flow or flow.provider != provider or is_expired(flow.expires_at):
        raise HTTPException(status_code=401, detail="OAuth flow is invalid or expired")
    verifier = get_payload_cipher().decrypt(flow.encrypted_verifier)["verifier"]
    redirect_uri = f"{get_settings().public_url.rstrip('/')}/api/v1/auth/oauth/{provider}/callback"
    secret = get_secret_store().get(f"{provider}-oauth-client-secret")
    token_response = httpx.post(
        definition["token"], data={"client_id": client_id, "client_secret": secret, "code": code,
                                   "redirect_uri": redirect_uri, "grant_type": "authorization_code",
                                   "code_verifier": verifier},
        headers={"Accept": "application/json"}, timeout=15,
    )
    token_response.raise_for_status()
    access_token = token_response.json().get("access_token")
    if not access_token:
        raise HTTPException(status_code=401, detail="OAuth token exchange failed")
    headers = {"Authorization": f"Bearer {access_token}", "Accept": "application/json", "User-Agent": "AgentGuard/0.1"}
    info_response = httpx.get(definition["userinfo"], headers=headers, timeout=15)
    info_response.raise_for_status()
    info = info_response.json()
    subject, email = str(info.get("sub") or info.get("id") or ""), info.get("email")
    if provider == "github" and not email:
        emails = httpx.get("https://api.github.com/user/emails", headers=headers, timeout=15).json()
        email = next((item["email"] for item in emails if item.get("primary") and item.get("verified")), None)
    if not subject or not email or (provider != "github" and info.get("email_verified") is False):
        raise HTTPException(status_code=401, detail="Provider did not return a verified email identity")
    identity = db.scalar(select(OAuthIdentity).where(
        OAuthIdentity.provider == provider, OAuthIdentity.provider_subject == subject
    ))
    if identity:
        user = db.get(User, identity.user_id)
    else:
        if db.scalar(select(User.id).where(User.email == str(email).lower())):
            raise HTTPException(status_code=409, detail="Sign in first to link this provider to the existing account")
        user = User(email=str(email).lower(), name=str(info.get("name") or info.get("login") or email), password_hash=None)
        organization = Organization(id=new_id(), name=f"{user.name}'s organization", slug=_slug(user.name), plan="free")
        set_tenant_context(db, organization.id)
        db.add_all([user, organization])
        db.flush()
        db.add_all([
            Workspace(organization_id=organization.id, name="Default", environment="development"),
            OrganizationMember(organization_id=organization.id, user_id=user.id, role="owner", status="active"),
            OAuthIdentity(user_id=user.id, provider=provider, provider_subject=subject),
        ])
        db.flush()
    if identity:
        member = db.scalar(select(OrganizationMember).where(
            OrganizationMember.user_id == user.id, OrganizationMember.status == "active"
        ))
        if member:
            set_tenant_context(db, member.organization_id)
    member = db.scalar(select(OrganizationMember).where(
        OrganizationMember.user_id == user.id, OrganizationMember.status == "active"
    ))
    if not member:
        raise HTTPException(status_code=403, detail="No active organization membership")
    db.delete(flow)
    response = RedirectResponse(get_settings().web_url, status_code=302)
    csrf = _issue_session(db, user.id, member.organization_id, response)
    # CSRF is placed in a short-lived non-HttpOnly bootstrap cookie; the web app consumes and clears it.
    response.set_cookie("ag_csrf_bootstrap", csrf, max_age=120, secure=get_settings().session_secure, samesite="lax")
    response.delete_cookie("ag_oauth_state")
    db.commit()
    return response
