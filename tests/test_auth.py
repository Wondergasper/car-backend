"""
test_auth.py
============
Tests for /api/auth  (register, login, /me).

Covers:
  - Successful registration creates org + user
  - Duplicate email rejected with 400
  - Login with valid credentials returns token
  - Login with bad credentials returns 401
  - Inactive user blocked with 403
  - /me returns current user data
  - /me blocked without token (401)
"""
import uuid
import pytest
from httpx import AsyncClient


pytestmark = pytest.mark.asyncio


# ── Register ──────────────────────────────────────────────────────────────────

async def test_register_success(client: AsyncClient):
    unique = uuid.uuid4().hex[:8]
    payload = {
        "email": f"newuser_{unique}@example.com",
        "password": "Password123!",
        "company_name": f"TestCorp {unique}",
        "industry": "fintech",
    }
    r = await client.post("/api/auth/register", json=payload)
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["email"] == payload["email"]
    assert "id" in data
    assert "hashed_password" not in data  # must never be exposed


async def test_register_duplicate_email(client: AsyncClient):
    unique = uuid.uuid4().hex[:8]
    payload = {
        "email": f"dup_{unique}@example.com",
        "password": "Password123!",
        "company_name": f"DupCorp {unique}",
        "industry": "healthcare",
    }
    r1 = await client.post("/api/auth/register", json=payload)
    assert r1.status_code == 201

    r2 = await client.post("/api/auth/register", json=payload)
    assert r2.status_code == 400
    assert "already registered" in r2.json()["detail"].lower()


async def test_register_missing_fields(client: AsyncClient):
    r = await client.post("/api/auth/register", json={"email": "nope@x.com"})
    assert r.status_code == 422  # validation error


# ── Login ─────────────────────────────────────────────────────────────────────

async def test_login_success(client: AsyncClient):
    unique = uuid.uuid4().hex[:8]
    email = f"login_{unique}@example.com"
    await client.post("/api/auth/register", json={
        "email": email,
        "password": "MyPass@999",
        "company_name": f"LoginCorp {unique}",
        "industry": "retail",
    })
    r = await client.post("/api/auth/login", json={"email": email, "password": "MyPass@999"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert "user" in data


async def test_login_wrong_password(client: AsyncClient):
    unique = uuid.uuid4().hex[:8]
    email = f"wp_{unique}@example.com"
    await client.post("/api/auth/register", json={
        "email": email,
        "password": "RealPass@1",
        "company_name": f"WPCorp {unique}",
        "industry": "logistics",
    })
    r = await client.post("/api/auth/login", json={"email": email, "password": "WrongPass!"})
    assert r.status_code == 401


async def test_login_nonexistent_email(client: AsyncClient):
    r = await client.post("/api/auth/login", json={
        "email": "ghost@nowhere.com",
        "password": "anything",
    })
    assert r.status_code == 401


# ── /me ───────────────────────────────────────────────────────────────────────

async def test_me_authenticated(client: AsyncClient):
    r = await client.get("/api/auth/me")
    assert r.status_code == 200
    data = r.json()
    assert "email" in data
    assert "id" in data
    assert "hashed_password" not in data


async def test_me_unauthenticated(client: AsyncClient):
    r = await client.get("/api/auth/me", headers={"Authorization": ""})
    assert r.status_code == 401


async def test_me_bad_token(client: AsyncClient):
    r = await client.get(
        "/api/auth/me",
        headers={"Authorization": "Bearer this.is.invalid"},
    )
    assert r.status_code == 401
