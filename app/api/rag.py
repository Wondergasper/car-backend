"""
RAG API - Semantic clause search over Nigerian regulatory corpus.
GET  /api/rag/status       - Check RAG engine status
POST /api/rag/search       - Semantic clause search
POST /api/rag/index        - Re-index documents (admin only)
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional

from app.api.dependencies import get_current_user
from app.models.database import User
from app.core.rag_engine import get_rag_engine
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


class SearchRequest(BaseModel):
    query: str
    k: int = 5
    framework: Optional[str] = None


class ClauseResult(BaseModel):
    source: str
    page: int
    article: str
    text: str
    relevance_rank: int


class SearchResponse(BaseModel):
    query: str
    results: List[ClauseResult]
    total: int


class RAGStatus(BaseModel):
    ready: bool
    document_count: int
    message: str


@router.get("/status", response_model=RAGStatus)
async def rag_status(current_user: User = Depends(get_current_user)):
    rag = get_rag_engine()
    count = rag.document_count
    return RAGStatus(
        ready=rag.is_ready,
        document_count=count,
        message=f"RAG engine ready with {count} indexed chunks" if rag.is_ready else "RAG engine not available",
    )


@router.post("/search", response_model=SearchResponse)
async def search_clauses(
    request: SearchRequest,
    current_user: User = Depends(get_current_user),
):
    if not request.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    rag = get_rag_engine()
    if not rag.is_ready:
        raise HTTPException(
            status_code=503,
            detail="RAG engine not available. Install: sentence-transformers chromadb pypdf"
        )

    citations = rag.retrieve(query=request.query, k=min(request.k, 10))

    # Optional framework filter
    if request.framework:
        citations = [c for c in citations if request.framework.lower() in c.source.lower()]

    return SearchResponse(
        query=request.query,
        results=[
            ClauseResult(
                source=c.source,
                page=c.page,
                article=c.article,
                text=c.text,
                relevance_rank=i + 1,
            )
            for i, c in enumerate(citations)
        ],
        total=len(citations),
    )


@router.post("/index")
async def reindex_documents(current_user: User = Depends(get_current_user)):
    rag = get_rag_engine()
    if not rag.is_ready:
        raise HTTPException(status_code=503, detail="RAG engine not available")
    try:
        count = rag.index_documents(force=True)
        return {"message": f"Re-indexed {count} document chunks successfully"}
    except Exception as e:
        logger.error("Re-indexing failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Indexing failed: {str(e)}")
