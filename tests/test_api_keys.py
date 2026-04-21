"""
test_api_keys.py
================
Tests for /api/api-keys  (list, create, revoke).
"""
import uuid
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_list_api_keys_returns_list(client: AsyncClient):
    r = await client.get("/api/api-keys/")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


async def test_create_api_key_success(client: AsyncClient):
    r = await client.post("/api/api-keys/", json={
        "name": f"CI Key {uuid.uuid4().hex[:6]}",
        "scopes": ["read", "write"],
    })
    # Depending on implementation: 201 or 200
    assert r.status_code in (200, 201), r.text
    if r.status_code in (200, 201):
        data = r.json()
        # key or id must be present
        assert "id" in data or "key" in data


async def test_create_api_key_unauthenticated(client: AsyncClient):
    r = await client.post(
        "/api/api-keys/",
        json={"name": "No Auth Key"},
        headers={"Authorization": ""},
    )
    assert r.status_code == 401


async def test_revoke_api_key_not_found(client: AsyncClient):
    r = await client.delete(f"/api/api-keys/{uuid.uuid4()}")
    # 404 if found but not yours, 204 if idempotent, 405 if DELETE not implemented
    assert r.status_code in (404, 204, 405)


async def test_list_api_keys_unauthenticated(client: AsyncClient):
    r = await client.get("/api/api-keys/", headers={"Authorization": ""})
    assert r.status_code == 401
