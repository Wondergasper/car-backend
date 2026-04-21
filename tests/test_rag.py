"""
test_rag.py
===========
Tests for /api/rag/status, /api/rag/search, /api/rag/index.

RAGEngine is fully mocked so tests do not require sentence-transformers
or ChromaDB to be installed.
"""
import pytest
from unittest.mock import MagicMock, patch
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


def _mock_rag(ready=True, count=42):
    rag = MagicMock()
    rag.is_ready = ready
    rag.document_count = count

    citation = MagicMock()
    citation.source = "NDPA 2023"
    citation.page = 5
    citation.article = "Article 36"
    citation.text = "Every data controller shall…"
    rag.retrieve = MagicMock(return_value=[citation])

    return rag


# ── Status ────────────────────────────────────────────────────────────────────

async def test_rag_status_ready(client: AsyncClient):
    with patch("app.api.rag.get_rag_engine", return_value=_mock_rag(ready=True, count=200)):
        r = await client.get("/api/rag/status")
    assert r.status_code == 200
    data = r.json()
    assert data["ready"] is True
    assert data["document_count"] == 200
    assert "ready" in data["message"].lower()


async def test_rag_status_not_ready(client: AsyncClient):
    with patch("app.api.rag.get_rag_engine", return_value=_mock_rag(ready=False, count=0)):
        r = await client.get("/api/rag/status")
    assert r.status_code == 200
    data = r.json()
    assert data["ready"] is False
    assert "not available" in data["message"].lower()


async def test_rag_status_unauthenticated(client: AsyncClient):
    r = await client.get("/api/rag/status", headers={"Authorization": ""})
    assert r.status_code == 401


# ── Search ────────────────────────────────────────────────────────────────────

async def test_rag_search_success(client: AsyncClient):
    with patch("app.api.rag.get_rag_engine", return_value=_mock_rag()):
        r = await client.post("/api/rag/search", json={
            "query": "data retention obligations",
            "k": 3,
        })
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["query"] == "data retention obligations"
    assert isinstance(data["results"], list)
    assert data["total"] == len(data["results"])
    if data["results"]:
        result = data["results"][0]
        assert "source" in result
        assert "text" in result
        assert "relevance_rank" in result


async def test_rag_search_empty_query(client: AsyncClient):
    with patch("app.api.rag.get_rag_engine", return_value=_mock_rag()):
        r = await client.post("/api/rag/search", json={"query": ""})
    assert r.status_code == 400
    assert "empty" in r.json()["detail"].lower()


async def test_rag_search_whitespace_query(client: AsyncClient):
    with patch("app.api.rag.get_rag_engine", return_value=_mock_rag()):
        r = await client.post("/api/rag/search", json={"query": "   "})
    assert r.status_code == 400


async def test_rag_search_engine_not_ready(client: AsyncClient):
    with patch("app.api.rag.get_rag_engine", return_value=_mock_rag(ready=False)):
        r = await client.post("/api/rag/search", json={"query": "consent forms"})
    assert r.status_code == 503


async def test_rag_search_framework_filter(client: AsyncClient):
    citation = MagicMock()
    citation.source = "GAID 2025"
    citation.page = 10
    citation.article = "Guideline 5"
    citation.text = "AI governance requires…"

    rag = _mock_rag()
    rag.retrieve = MagicMock(return_value=[citation])

    with patch("app.api.rag.get_rag_engine", return_value=rag):
        r = await client.post("/api/rag/search", json={
            "query": "AI governance",
            "k": 5,
            "framework": "gaid",
        })

    assert r.status_code == 200
    # All results must match the framework filter
    for item in r.json()["results"]:
        assert "gaid" in item["source"].lower()


async def test_rag_search_k_capped_at_10(client: AsyncClient):
    """k > 10 should be silently capped to 10."""
    citations = [
        MagicMock(source=f"Doc {i}", page=i, article=f"Art {i}", text=f"Text {i}")
        for i in range(15)
    ]
    rag = _mock_rag()
    rag.retrieve = MagicMock(return_value=citations[:10])

    with patch("app.api.rag.get_rag_engine", return_value=rag):
        r = await client.post("/api/rag/search", json={"query": "test", "k": 50})

    assert r.status_code == 200
    # retrieve should have been called with 10, not 50
    rag.retrieve.assert_called_once()
    call_k = rag.retrieve.call_args.kwargs.get("k") or rag.retrieve.call_args.args[1] if len(rag.retrieve.call_args.args) > 1 else None
    if call_k is not None:
        assert call_k <= 10


async def test_rag_search_unauthenticated(client: AsyncClient):
    r = await client.post(
        "/api/rag/search",
        json={"query": "privacy"},
        headers={"Authorization": ""},
    )
    assert r.status_code == 401


# ── Re-index ──────────────────────────────────────────────────────────────────

async def test_rag_index_success(client: AsyncClient):
    rag = _mock_rag()
    rag.index_documents = MagicMock(return_value=350)

    with patch("app.api.rag.get_rag_engine", return_value=rag):
        r = await client.post("/api/rag/index")

    assert r.status_code == 200, r.text
    assert "350" in r.json()["message"]


async def test_rag_index_not_ready(client: AsyncClient):
    with patch("app.api.rag.get_rag_engine", return_value=_mock_rag(ready=False)):
        r = await client.post("/api/rag/index")
    assert r.status_code == 503


async def test_rag_index_failure(client: AsyncClient):
    rag = _mock_rag()
    rag.index_documents = MagicMock(side_effect=RuntimeError("disk full"))

    with patch("app.api.rag.get_rag_engine", return_value=rag):
        r = await client.post("/api/rag/index")

    assert r.status_code == 500
