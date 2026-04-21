"""
test_scheduled_audits.py
========================
Tests for /api/scheduled-audits  (list, create, delete).

APScheduler is mocked globally in conftest; here we just ensure the API
contract is correct.
"""
import uuid
import pytest
from unittest.mock import MagicMock, patch
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio

_CRON_WEEKLY = "0 8 * * 1"    # Monday 08:00 UTC
_CRON_DAILY  = "0 0 * * *"    # Midnight daily


# ── List ──────────────────────────────────────────────────────────────────────

async def test_list_scheduled_audits_empty(client: AsyncClient):
    r = await client.get("/api/scheduled-audits/")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


async def test_list_scheduled_audits_unauthenticated(client: AsyncClient):
    r = await client.get("/api/scheduled-audits/", headers={"Authorization": ""})
    assert r.status_code == 401


# ── Create ────────────────────────────────────────────────────────────────────

async def _create_schedule(client: AsyncClient, cron: str = _CRON_WEEKLY, name: str = None):
    name = name or f"Weekly Audit {uuid.uuid4().hex[:6]}"
    with patch("app.api.scheduled_audits.register_scheduled_audit") as mock_reg, \
         patch("app.api.scheduled_audits.scheduler") as mock_sched:

        # Mock scheduler.get_job to return a job with next_run_time
        mock_job = MagicMock()
        mock_job.next_run_time = None
        mock_sched.get_job = MagicMock(return_value=mock_job)

        r = await client.post("/api/scheduled-audits/", json={
            "name": name,
            "cron_expression": cron,
            "audit_type": "full",
        })
    return r


async def test_create_scheduled_audit_success(client: AsyncClient):
    r = await _create_schedule(client)
    assert r.status_code == 201, r.text
    data = r.json()
    assert "id" in data
    assert data["is_active"] is True
    assert _CRON_WEEKLY in data["cron_expression"]


async def test_create_scheduled_audit_daily(client: AsyncClient):
    r = await _create_schedule(client, cron=_CRON_DAILY, name="Daily Audit")
    assert r.status_code == 201
    data = r.json()
    assert data["cron_expression"] == _CRON_DAILY



async def test_create_scheduled_audit_missing_name(client: AsyncClient):
    with patch("app.api.scheduled_audits.register_scheduled_audit"), \
         patch("app.api.scheduled_audits.scheduler"):
        r = await client.post("/api/scheduled-audits/", json={
            "cron_expression": _CRON_WEEKLY,
        })
    assert r.status_code == 422


async def test_create_scheduled_audit_missing_cron(client: AsyncClient):
    with patch("app.api.scheduled_audits.register_scheduled_audit"), \
         patch("app.api.scheduled_audits.scheduler"):
        r = await client.post("/api/scheduled-audits/", json={
            "name": "No Cron Audit",
        })
    assert r.status_code == 422


async def test_create_scheduled_audit_unauthenticated(client: AsyncClient):
    r = await client.post(
        "/api/scheduled-audits/",
        json={"name": "Unauth", "cron_expression": _CRON_WEEKLY},
        headers={"Authorization": ""},
    )
    assert r.status_code == 401


# ── Delete ────────────────────────────────────────────────────────────────────

async def test_delete_scheduled_audit_success(client: AsyncClient):
    create_r = await _create_schedule(client, name="Deletable Schedule")
    assert create_r.status_code == 201
    job_id = create_r.json()["id"]

    with patch("app.api.scheduled_audits.unregister_scheduled_audit"):
        r = await client.delete(f"/api/scheduled-audits/{job_id}")
    assert r.status_code == 204


async def test_delete_scheduled_audit_not_found(client: AsyncClient):
    with patch("app.api.scheduled_audits.unregister_scheduled_audit"):
        r = await client.delete("/api/scheduled-audits/no-such-job-id")
    assert r.status_code == 404


async def test_delete_scheduled_audit_wrong_org(client: AsyncClient):
    """A job belonging to another org should not be deletable."""
    # Manually inject a foreign-org schedule into the in-memory store
    from app.api import scheduled_audits
    foreign_id = f"audit_foreignorg_{uuid.uuid4().hex[:8]}"
    scheduled_audits._scheduled_audits[foreign_id] = {
        "id": foreign_id,
        "org_id": str(uuid.uuid4()),  # different org
        "name": "Foreign Schedule",
        "cron_expression": _CRON_DAILY,
        "is_active": True,
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    with patch("app.api.scheduled_audits.unregister_scheduled_audit"):
        r = await client.delete(f"/api/scheduled-audits/{foreign_id}")
    assert r.status_code == 404
    # Cleanup
    scheduled_audits._scheduled_audits.pop(foreign_id, None)
