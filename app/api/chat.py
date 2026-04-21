"""
AI Chat endpoint - powered by RAG engine with regulatory clause citations.
Routes through LLMRouter: Gemini -> Mistral -> Llama3 -> Phi3.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime

from app.db.session import get_db
from app.models.database import User, Audit, Finding, Organization, AuditStatus
from app.api.dependencies import get_current_user
from app.core.config import get_settings
from app.core.rag_engine import get_rag_engine
from app.services.ai_monitor import get_ai_monitor
import logging

logger = logging.getLogger(__name__)
router = APIRouter()
settings = get_settings()


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    message: str
    audit_id: Optional[str] = None
    history: List[ChatMessage] = []
    use_rag: bool = True


class CitationItem(BaseModel):
    source: str
    page: int
    article: str
    text: str


class ChatResponse(BaseModel):
    reply: str
    audit_id: Optional[str] = None
    sources: List[str] = []
    citations: List[CitationItem] = []
    grounded: bool = False
    model_used: str = "gemini"
    ai_safe: bool = True
    risk_score: float = 0.0


async def _build_audit_context(
    org: Organization, audits: list, findings: list, audit_id: Optional[str]
) -> str:
    latest = None
    if audit_id:
        latest = next((a for a in audits if str(a.id) == audit_id), None)
    if not latest and audits:
        latest = audits[0]

    score   = latest.compliance_score if latest else "Unknown"
    total   = latest.findings_count   if latest else 0
    crit    = latest.critical_count   if latest else 0
    high    = latest.high_count       if latest else 0

    finding_summaries = "\n".join(
        f"- [{f.severity.value.upper()}] {f.title}: {f.description[:120]}"
        for f in findings[:15]
    ) or "No findings recorded."

    return (
        f"ORGANIZATION: {org.name}\n"
        f"INDUSTRY: {org.industry or 'Unknown'}\n"
        f"DPO: {org.dpo_name or 'Not configured'}\n\n"
        f"LATEST AUDIT:\n"
        f"- Score: {score}%  |  Total: {total}  |  Critical: {crit}  |  High: {high}\n"
        f"- Date: {latest.created_at.strftime('%d %b %Y') if latest else 'N/A'}\n\n"
        f"TOP FINDINGS:\n{finding_summaries}"
    )


@router.post("/", response_model=ChatResponse)
async def chat_with_audit(
    request: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not settings.GOOGLE_API_KEY and not settings.HUGGINGFACE_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No AI service configured. Set GOOGLE_API_KEY or HUGGINGFACE_TOKEN.",
        )

    # Fetch org and audit data
    org = (await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )).scalar_one()

    audits = (await db.execute(
        select(Audit)
        .where(Audit.org_id == current_user.org_id, Audit.status == AuditStatus.COMPLETED)
        .order_by(Audit.created_at.desc()).limit(5)
    )).scalars().all()

    target_audit_id = request.audit_id or (str(audits[0].id) if audits else None)
    findings = []
    if target_audit_id:
        findings = (await db.execute(
            select(Finding).where(Finding.audit_id == target_audit_id).limit(30)
        )).scalars().all()

    audit_context = await _build_audit_context(org, audits, findings, target_audit_id)
    history = [{"role": m.role, "content": m.content} for m in request.history]

    # RAG: retrieve relevant regulatory clauses
    rag = get_rag_engine()
    try:
        if request.use_rag and rag.is_ready:
            rag_result = await rag.generate_grounded_response(
                query=request.message,
                audit_context=audit_context,
                history=history,
                api_key=settings.GOOGLE_API_KEY,
            )
            reply       = rag_result.answer
            citations   = rag_result.citations
            grounded    = rag_result.grounded
            model_used  = rag_result.model_used
        else:
            # Fallback to direct Gemini call (no RAG)
            from app.core.llm_router import LLMRouter
            router_llm = LLMRouter(api_key=settings.GOOGLE_API_KEY,
                                   hf_token=settings.HUGGINGFACE_TOKEN)
            system_prompt = (
                "You are an expert AI compliance advisor for CAR-Bot, "
                "specialising in NDPA 2023 and GAID 2025.\n\n"
                + audit_context
            )
            reply       = await router_llm.generate(system_prompt, request.message, history)
            citations   = []
            grounded    = False
            model_used  = router_llm.last_model_used
    except Exception as e:
        logger.error("Chat generation failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"AI service error: {str(e)}")

    # AI safety check
    monitor = get_ai_monitor()
    safety  = monitor.check_response(
        query=request.message,
        response=reply,
        citations=[{"source": c.source, "article": c.article} for c in citations],
        model_used=model_used,
    )

    return ChatResponse(
        reply=reply,
        audit_id=target_audit_id,
        sources=[f.title for f in findings[:5]],
        citations=[
            CitationItem(source=c.source, page=c.page, article=c.article, text=c.text)
            for c in citations
        ],
        grounded=grounded,
        model_used=model_used,
        ai_safe=safety.is_safe,
        risk_score=safety.risk_score,
    )
