"""
test_frameworks.py
==================
Tests for /api/frameworks/ (list, get, crosswalk).

FrameworkLoader is mocked to return deterministic fixture data so
tests are independent of the filesystem JSON files.
"""
import pytest
from unittest.mock import MagicMock, patch
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio

# ── Fixture data ──────────────────────────────────────────────────────────────

_NDPA_FIXTURE = {
    "framework": "Nigeria Data Protection Act 2023",
    "version": "2023",
    "issuing_body": "NDPB",
    "controls": [
        {
            "id": "NDPA-1",
            "title": "Lawful Basis",
            "description": "Processing must have a lawful basis.",
            "evidence_requirements": ["Privacy Policy", "Consent Records"],
            "maps_to": ["GDPR-6"],
        },
        {
            "id": "NDPA-2",
            "title": "Data Minimisation",
            "description": "Collect only necessary data.",
            "evidence_requirements": ["Data Inventory"],
            "maps_to": ["GDPR-5"],
        },
    ],
}

_GAID_FIXTURE = {
    "framework": "GAID 2025",
    "version": "2025",
    "issuing_body": "NCC",
    "controls": [
        {
            "id": "GAID-1",
            "title": "AI Transparency",
            "description": "AI systems must be explainable.",
            "evidence_requirements": ["Model Card"],
            "maps_to": ["NDPA-1"],
        },
    ],
}


def _mock_loader(available=("ndpa", "gaid")):
    loader = MagicMock()
    loader.list_available = MagicMock(return_value=list(available))

    def _load(fw_id):
        return {"ndpa": _NDPA_FIXTURE, "gaid": _GAID_FIXTURE}.get(fw_id)

    loader.load = MagicMock(side_effect=_load)

    def _crosswalk(from_fw, to_fw):
        return [{"source": "NDPA-1", "title": "Lawful Basis", "matched": ["GAID-1"]}]

    loader.crosswalk = MagicMock(side_effect=_crosswalk)
    return loader


# ── List ──────────────────────────────────────────────────────────────────────

async def test_list_frameworks_returns_summaries(client: AsyncClient):
    with patch("app.api.frameworks.get_framework_loader", return_value=_mock_loader()):
        r = await client.get("/api/frameworks/")
    assert r.status_code == 200, r.text
    data = r.json()
    assert isinstance(data, list)
    assert len(data) == 2

    ids = [f["id"] for f in data]
    assert "ndpa" in ids
    assert "gaid" in ids

    ndpa = next(f for f in data if f["id"] == "ndpa")
    assert ndpa["control_count"] == 2
    assert ndpa["issuing_body"] == "NDPB"


async def test_list_frameworks_unauthenticated(client: AsyncClient):
    r = await client.get("/api/frameworks/", headers={"Authorization": ""})
    assert r.status_code == 401


async def test_list_frameworks_empty(client: AsyncClient):
    loader = MagicMock()
    loader.list_available = MagicMock(return_value=[])
    with patch("app.api.frameworks.get_framework_loader", return_value=loader):
        r = await client.get("/api/frameworks/")
    assert r.status_code == 200
    assert r.json() == []


# ── Get Detail ────────────────────────────────────────────────────────────────

async def test_get_framework_ndpa(client: AsyncClient):
    with patch("app.api.frameworks.get_framework_loader", return_value=_mock_loader()):
        r = await client.get("/api/frameworks/ndpa")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == "ndpa"
    assert data["name"] == "Nigeria Data Protection Act 2023"
    assert isinstance(data["controls"], list)
    assert len(data["controls"]) == 2

    ctrl = data["controls"][0]
    assert "id" in ctrl
    assert "title" in ctrl
    assert "evidence_requirements" in ctrl
    assert "maps_to" in ctrl


async def test_get_framework_gaid(client: AsyncClient):
    with patch("app.api.frameworks.get_framework_loader", return_value=_mock_loader()):
        r = await client.get("/api/frameworks/gaid")
    assert r.status_code == 200
    assert r.json()["id"] == "gaid"


async def test_get_framework_not_found(client: AsyncClient):
    with patch("app.api.frameworks.get_framework_loader", return_value=_mock_loader()):
        r = await client.get("/api/frameworks/nonexistent")
    assert r.status_code == 404
    assert "not found" in r.json()["detail"].lower()


# ── Crosswalk ─────────────────────────────────────────────────────────────────

async def test_crosswalk_returns_mappings(client: AsyncClient):
    with patch("app.api.frameworks.get_framework_loader", return_value=_mock_loader()):
        r = await client.get("/api/frameworks/crosswalk/map?from_fw=ndpa&to_fw=gaid")
    assert r.status_code == 200
    data = r.json()
    assert data["from"] == "ndpa"
    assert data["to"] == "gaid"
    assert isinstance(data["mappings"], list)
    assert data["count"] == len(data["mappings"])


async def test_crosswalk_unauthenticated(client: AsyncClient):
    r = await client.get(
        "/api/frameworks/crosswalk/map?from_fw=ndpa&to_fw=gaid",
        headers={"Authorization": ""},
    )
    assert r.status_code == 401


async def test_crosswalk_missing_params(client: AsyncClient):
    with patch("app.api.frameworks.get_framework_loader", return_value=_mock_loader()):
        r = await client.get("/api/frameworks/crosswalk/map")
    assert r.status_code == 422
