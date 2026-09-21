"""Database-backed session, CSRF, role, and bootstrap regressions."""

from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from agentguard_api import auth_routes, database
from agentguard_api.database import Base, create_database_engine
from agentguard_api.main import app
from agentguard_api.models import OrganizationMember, User


@pytest.fixture
def account(tmp_path, monkeypatch):
    engine = create_database_engine(f"sqlite:///{tmp_path / 'auth-security.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(database, "SessionLocal", sessions)
    client = TestClient(app)
    body = {
        "email": "auth-security@example.com",
        "password": "auth security correct horse battery",
        "name": "Auth Security",
        "organization_name": "Auth Security Org",
    }
    registered = client.post("/api/v1/auth/register", json=body)
    assert registered.status_code == 201, registered.text
    yield client, body, registered.json(), sessions
    client.close()
    engine.dispose()


def test_cookie_mutations_require_correct_csrf(account):
    client, _, body, _ = account
    tool = {"name": "safe.read", "provider": "safe"}
    assert client.post("/api/v1/tools", json=tool).status_code == 403
    assert client.post("/api/v1/tools", headers={"X-CSRF-Token": "incorrect-csrf"}, json=tool).status_code == 403
    assert client.post("/api/v1/tools", headers={"X-CSRF-Token": body["csrf_token"]}, json=tool).status_code == 201


def test_member_cannot_mutate_owner_admin_resources(account):
    client, _, body, sessions = account
    with sessions() as db:
        member = db.scalar(select(OrganizationMember).where(OrganizationMember.user_id == body["user"]["id"]))
        member.role = "member"
        db.commit()
    headers = {"X-CSRF-Token": body["csrf_token"]}
    assert client.get("/api/v1/agents").status_code == 200
    assert (
        client.post("/api/v1/tools", headers=headers, json={"name": "blocked.write", "provider": "blocked"}).status_code
        == 403
    )
    assert (
        client.post("/api/v1/api-keys", headers=headers, json={"name": "escalate", "scopes": ["admin"]}).status_code
        == 403
    )


def test_read_api_key_cannot_create_agents(account):
    client, _, body, _ = account
    key = client.post(
        "/api/v1/api-keys", headers={"X-CSRF-Token": body["csrf_token"]}, json={"name": "read-only", "scopes": ["read"]}
    ).json()["api_key"]
    other = TestClient(app)
    denied = other.post(
        "/api/v1/agents",
        headers={"Authorization": f"Bearer {key}"},
        json={"name": "Escalate", "workspace_id": body["workspaces"][0]["id"]},
    )
    assert denied.status_code == 403
    other.close()


def test_no_scope_api_key_cannot_read_audit(account):
    client, _, body, _ = account
    key = client.post(
        "/api/v1/api-keys", headers={"X-CSRF-Token": body["csrf_token"]}, json={"name": "no-authority", "scopes": []}
    ).json()["api_key"]
    other = TestClient(app)
    assert other.get("/api/v1/audit", headers={"Authorization": f"Bearer {key}"}).status_code == 403
    other.close()


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        (
            "/api/v1/tools",
            {
                "name": "nested.secret",
                "provider": "custom",
                "config": {"headers": {"Authorization": "Bearer plaintext-credential"}},
            },
        ),
        (
            "/api/v1/integrations",
            {
                "name": "Nested secret",
                "provider": "slack",
                "config": {"credentials": {"api_key": "plaintext-credential"}},
            },
        ),
    ],
)
def test_nested_inline_connector_secrets_are_rejected(account, path, payload):
    client, _, body, _ = account
    result = client.post(path, headers={"X-CSRF-Token": body["csrf_token"]}, json=payload)
    assert result.status_code == 422, result.text


def test_logout_revokes_access_and_refresh(account):
    client, _, body, _ = account
    access, refresh = client.cookies.get("ag_access"), client.cookies.get("ag_refresh")
    assert client.post("/api/v1/auth/logout", headers={"X-CSRF-Token": body["csrf_token"]}).status_code == 204
    old = TestClient(app)
    assert old.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {access}"}).status_code == 401
    assert old.post("/api/v1/auth/refresh", headers={"Cookie": f"ag_refresh={refresh}"}).status_code == 401
    old.close()


def test_bearer_logout_also_revokes_the_session(account):
    client, _, _, _ = account
    access = client.cookies.get("ag_access")
    bearer = TestClient(app)
    headers = {"Authorization": f"Bearer {access}"}
    assert bearer.post("/api/v1/auth/logout", headers=headers).status_code == 204
    assert bearer.get("/api/v1/auth/me", headers=headers).status_code == 401
    bearer.close()


def test_refresh_rotates_access_refresh_and_csrf(account):
    client, _, body, _ = account
    old_access, old_refresh = client.cookies.get("ag_access"), client.cookies.get("ag_refresh")
    refreshed = client.post("/api/v1/auth/refresh")
    assert refreshed.status_code == 200
    assert refreshed.json()["csrf_token"] != body["csrf_token"]
    old = TestClient(app)
    assert old.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {old_access}"}).status_code == 401
    assert old.post("/api/v1/auth/refresh", headers={"Cookie": f"ag_refresh={old_refresh}"}).status_code == 401
    assert client.get("/api/v1/auth/me").status_code == 200
    old.close()


def test_removed_membership_cannot_refresh(account):
    client, _, body, sessions = account
    with sessions() as db:
        member = db.scalar(select(OrganizationMember).where(OrganizationMember.user_id == body["user"]["id"]))
        member.status = "removed"
        db.commit()
    assert client.post("/api/v1/auth/refresh").status_code in {401, 403}


def test_disabled_user_cannot_log_in(account):
    client, credentials, body, sessions = account
    with sessions() as db:
        db.get(User, body["user"]["id"]).active = False
        db.commit()
    attempted = client.post(
        "/api/v1/auth/login", json={"email": credentials["email"], "password": credentials["password"]}
    )
    assert attempted.status_code in {401, 403}, attempted.text


def test_magic_link_is_single_use_and_invalid_token_rejected(account):
    client, credentials, _, _ = account
    link = client.post("/api/v1/auth/magic-link", json={"email": credentials["email"]})
    assert link.status_code == 200
    token = link.json()["development_token"]
    assert client.post("/api/v1/auth/magic-link/consume", json={"token": token}).status_code == 200
    assert client.post("/api/v1/auth/magic-link/consume", json={"token": token}).status_code == 401
    assert client.post("/api/v1/auth/magic-link/consume", json={"token": "x" * 40}).status_code == 401


def test_disabled_user_cannot_consume_magic_link(account):
    client, credentials, body, sessions = account
    token = client.post("/api/v1/auth/magic-link", json={"email": credentials["email"]}).json()["development_token"]
    with sessions() as db:
        db.get(User, body["user"]["id"]).active = False
        db.commit()
    attempted = client.post("/api/v1/auth/magic-link/consume", json={"token": token})
    assert attempted.status_code in {401, 403}, attempted.text


def test_new_oauth_identity_bootstraps_a_real_organization(account, monkeypatch):
    client, _, _, _ = account
    monkeypatch.setattr(
        auth_routes, "_client_id", lambda provider: "configured-client" if provider == "google" else None
    )
    monkeypatch.setattr(
        auth_routes, "get_secret_store", lambda: SimpleNamespace(get=lambda *args, **kwargs: "test-oauth-secret")
    )

    def provider_post(url, **kwargs):
        return httpx.Response(200, json={"access_token": "provider-test-token"}, request=httpx.Request("POST", url))

    def provider_get(url, **kwargs):
        return httpx.Response(
            200,
            json={
                "sub": "new-oauth-subject",
                "email": "new-oauth-security@example.com",
                "email_verified": True,
                "name": "OAuth Security",
            },
            request=httpx.Request("GET", url),
        )

    monkeypatch.setattr(auth_routes.httpx, "post", provider_post)
    monkeypatch.setattr(auth_routes.httpx, "get", provider_get)
    started = client.get("/api/v1/auth/oauth/google/start", follow_redirects=False)
    assert started.status_code == 302
    state = parse_qs(urlparse(started.headers["location"]).query)["state"][0]
    callback = client.get(
        "/api/v1/auth/oauth/google/callback", params={"code": "provider-code", "state": state}, follow_redirects=False
    )
    assert callback.status_code == 302, callback.text
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["user"]["email"] == "new-oauth-security@example.com"
    assert len(me.json()["workspaces"]) == 1
    replay = client.get(
        "/api/v1/auth/oauth/google/callback", params={"code": "provider-code", "state": state}, follow_redirects=False
    )
    assert replay.status_code == 401
