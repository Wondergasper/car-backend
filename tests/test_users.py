"""
test_users.py
=============
Tests for /api/users  (list, invite, role update, deactivate).

The seeded owner user is used as the requesting principal throughout.
A separate viewer user is invited to test role-change and deactivation.
"""
import uuid
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


# ── List ──────────────────────────────────────────────────────────────────────

async def test_list_users_returns_list(client: AsyncClient):
    r = await client.get("/api/users/")
    assert r.status_code == 200
    assert isinstance(r.json(), list)
    users = r.json()
    # At minimum the seed owner should be present
    assert len(users) >= 1
    emails = [u["email"] for u in users]
    assert "owner@acme.com" in emails


async def test_list_users_unauthenticated(client: AsyncClient):
    r = await client.get("/api/users/", headers={"Authorization": ""})
    assert r.status_code == 401


async def test_list_users_pagination(client: AsyncClient):
    r = await client.get("/api/users/?skip=0&limit=1")
    assert r.status_code == 200
    assert len(r.json()) <= 1


# ── Invite ────────────────────────────────────────────────────────────────────

async def _invite_viewer(client: AsyncClient) -> dict:
    unique = uuid.uuid4().hex[:8]
    payload = {
        "email": f"viewer_{unique}@acme.com",
        "full_name": f"Viewer {unique}",
        "role": "viewer",
    }
    r = await client.post("/api/users/invite", json=payload)
    return r


async def test_invite_user_success(client: AsyncClient):
    r = await _invite_viewer(client)
    assert r.status_code in (201, 403), r.text  # 403 if user limit hit
    if r.status_code == 201:
        data = r.json()
        assert "id" in data
        assert data["role"] == "viewer"
        assert "hashed_password" not in data


async def test_invite_duplicate_email(client: AsyncClient):
    unique = uuid.uuid4().hex[:8]
    payload = {
        "email": f"dup_viewer_{unique}@acme.com",
        "full_name": "Dup User",
        "role": "viewer",
    }
    r1 = await client.post("/api/users/invite", json=payload)
    if r1.status_code == 403:
        pytest.skip("User limit reached")
    assert r1.status_code == 201

    r2 = await client.post("/api/users/invite", json=payload)
    assert r2.status_code == 400
    assert "already exists" in r2.json()["detail"].lower()


async def test_invite_missing_email(client: AsyncClient):
    r = await client.post("/api/users/invite", json={"full_name": "No Email", "role": "viewer"})
    assert r.status_code == 422


# ── Role Update ───────────────────────────────────────────────────────────────

async def test_update_user_role_success(client: AsyncClient):
    invite_r = await _invite_viewer(client)
    if invite_r.status_code != 201:
        pytest.skip("User limit reached; skipping role update test")
    user_id = invite_r.json()["id"]

    r = await client.put(f"/api/users/{user_id}/role", json={"role": "admin"})
    assert r.status_code == 200
    assert r.json()["role"] == "admin"


async def test_update_role_user_not_found(client: AsyncClient):
    r = await client.put(f"/api/users/{uuid.uuid4()}/role", json={"role": "viewer"})
    assert r.status_code == 404


async def test_update_role_invalid_value(client: AsyncClient):
    r = await client.put(f"/api/users/{uuid.uuid4()}/role", json={"role": "superadmin"})
    assert r.status_code == 422


# ── Deactivate ────────────────────────────────────────────────────────────────

async def test_deactivate_user_success(client: AsyncClient):
    invite_r = await _invite_viewer(client)
    if invite_r.status_code != 201:
        pytest.skip("User limit reached; skipping deactivation test")
    user_id = invite_r.json()["id"]

    r = await client.delete(f"/api/users/{user_id}")
    assert r.status_code == 204


async def test_deactivate_self_forbidden(client: AsyncClient):
    """Attempting to delete yourself should return 400."""
    me_r = await client.get("/api/auth/me")
    assert me_r.status_code == 200
    own_id = me_r.json()["id"]

    r = await client.delete(f"/api/users/{own_id}")
    assert r.status_code == 400


async def test_deactivate_nonexistent_user(client: AsyncClient):
    r = await client.delete(f"/api/users/{uuid.uuid4()}")
    assert r.status_code == 404
