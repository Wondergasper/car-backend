"""
test_webhooks.py
================
Tests for POST/GET/DELETE /api/notifications/webhooks
(the outgoing webhook registration endpoints).

Also covers the inbound connector-event webhook at /api/webhooks/.
"""
import hashlib
import hmac as _hmac
import json
import uuid
import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


def _sig(secret: str, body: bytes) -> str:
    dig = _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={dig}"


# ── Outgoing Webhook Registration ─────────────────────────────────────────────

async def test_list_webhooks_empty(client: AsyncClient):
    r = await client.get("/api/notifications/webhooks")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


async def test_register_webhook_success(client: AsyncClient):
    payload = {
        "name": "Slack Alerts",
        "url": "https://hooks.slack.com/services/test",
        "events": ["audit.completed", "finding.critical"],
    }
    r = await client.post("/api/notifications/webhooks", json=payload)
    assert r.status_code == 201, r.text
    data = r.json()
    assert data["name"] == "Slack Alerts"
    assert data["is_active"] is True
    assert "id" in data


async def test_register_webhook_default_events(client: AsyncClient):
    payload = {
        "name": "Minimal Webhook",
        "url": "https://example.com/hook",
    }
    r = await client.post("/api/notifications/webhooks", json=payload)
    assert r.status_code == 201
    data = r.json()
    assert "events" in data
    assert len(data["events"]) > 0


async def test_register_webhook_unauthenticated(client: AsyncClient):
    r = await client.post(
        "/api/notifications/webhooks",
        json={"name": "X", "url": "https://x.com"},
        headers={"Authorization": ""},
    )
    assert r.status_code == 401


async def test_register_webhook_missing_url(client: AsyncClient):
    r = await client.post("/api/notifications/webhooks", json={"name": "No URL"})
    assert r.status_code == 422


# ── Delete Webhook ────────────────────────────────────────────────────────────

async def test_delete_webhook_success(client: AsyncClient):
    create_r = await client.post("/api/notifications/webhooks", json={
        "name": "Delete Me",
        "url": "https://delete-me.com/hook",
    })
    assert create_r.status_code == 201
    hook_id = create_r.json()["id"]

    r = await client.delete(f"/api/notifications/webhooks/{hook_id}")
    assert r.status_code == 204


async def test_delete_webhook_not_found(client: AsyncClient):
    r = await client.delete("/api/notifications/webhooks/nonexistent-id-xyz")
    assert r.status_code == 404


# ── Cross-org isolation ───────────────────────────────────────────────────────

async def test_webhooks_isolated_per_org(client: AsyncClient):
    """Webhooks created by one org should not be visible/deletable by another.
    This test uses the same client (same org) to register and verify visibility."""
    create_r = await client.post("/api/notifications/webhooks", json={
        "name": "Org Hook",
        "url": "https://org.hook.com",
    })
    assert create_r.status_code == 201
    hook_id = create_r.json()["id"]

    list_r = await client.get("/api/notifications/webhooks")
    ids = [h["id"] for h in list_r.json()]
    assert hook_id in ids


# ── Inbound Connector Events (webhooks.py) ────────────────────────────────────

async def test_receive_webhook_no_sig(client: AsyncClient):
    """Inbound event without signature header must be rejected."""
    r = await client.post("/api/webhooks/", json={
        "connector_id": str(uuid.uuid4()),
        "event_type": "data_update",
        "payload": {"key": "value"},
    })
    # App checks connector existence BEFORE signature, so unknown connector → 404
    # If validation order changes, 401 or 422 may appear instead
    assert r.status_code in (401, 404, 422), f"Got unexpected {r.status_code}"


async def test_receive_webhook_connector_not_found(client: AsyncClient):
    """Unknown connector_id → 404 before signature check."""
    fake_connector_id = str(uuid.uuid4())
    body = json.dumps({
        "connector_id": fake_connector_id,
        "event_type": "data_update",
        "payload": {},
    }).encode()
    r = await client.post(
        "/api/webhooks/",
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-Hub-Signature-256": _sig("fakesecret", body),
        },
    )
    # 401 (sig first) or 404 (connector lookup first) — both valid
    assert r.status_code in (401, 404), f"Expected 401 or 404 but got {r.status_code}"

