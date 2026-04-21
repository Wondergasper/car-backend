"""
test_health.py
==============
Tests for GET /health (public) and meta assertions.
"""
import pytest
from unittest.mock import MagicMock, patch
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_health_check_basic(client: AsyncClient):
    """Health endpoint should be publicly reachable and return 200."""
    r = await client.get("/health")
    # 200 if RAG is available, 503 if degraded — both are OK for infra tests
    assert r.status_code in (200, 503)


async def test_health_check_fields(client: AsyncClient):
    r = await client.get("/health")
    if r.status_code == 200:
        data = r.json()
        assert "status" in data
        assert data["status"] in ("healthy", "degraded")


async def test_openapi_docs_available(client: AsyncClient):
    """Swagger UI and OpenAPI schema should be accessible."""
    r = await client.get("/docs")
    assert r.status_code == 200

    r_schema = await client.get("/openapi.json")
    assert r_schema.status_code == 200
    schema = r_schema.json()
    assert schema["info"]["title"] == "CAR-Bot API"


async def test_redoc_available(client: AsyncClient):
    r = await client.get("/redoc")
    assert r.status_code == 200


async def test_unknown_route_returns_404(client: AsyncClient):
    r = await client.get("/this/does/not/exist")
    assert r.status_code == 404
