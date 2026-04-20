"""
AI Chat endpoint — "Chat with Your Audit" powered by Google Gemini.
Users can ask natural-language questions about their compliance posture.
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
import logging

logger = logging.getLogger(__name__)
router = APIRouter()
settings = get_settings()


class ChatMessage(BaseModel):
    role: str  # "user" | "assistant"
    content: str


class ChatRequest(BaseModel):
    message: str
    audit_id: Optional[str] = None  # scope to a specific audit, or use latest
    history: List[ChatMessage] = []


class ChatResponse(BaseModel):
    reply: str
    audit_id: Optional[str] = None
    sources: List[str] = []


async def _build_audit_context_prompt(
    org: Organization,
    audits: list,
    findings: list,
    audit_id: Optional[str],
) -> str:
    """Build a rich system prompt from real audit/finding data."""
    latest_audit = None
    if audit_id:
        for a in audits:
            if str(a.id) == audit_id:
                latest_audit = a
                break
    if not latest_audit and audits:
        latest_audit = audits[0]

    score = latest_audit.compliance_score if latest_audit else "Unknown"
    total_findings = latest_audit.findings_count if latest_audit else 0
    critical = latest_audit.critical_count if latest_audit else 0
    high = latest_audit.high_count if latest_audit else 0

    finding_summaries = "\n".join(
        f"- [{f.severity.value.upper()}] {f.title}: {f.description[:120]}..."
        for f in findings[:15]
    ) or "No findings recorded."

    return f"""You are an expert AI compliance advisor for CAR-Bot, specializing in Nigerian Data Protection Act (NDPA 2023) and GAID 2025.

ORGANIZATION: {org.name}
INDUSTRY: {org.industry or 'Unknown'}
DPO: {org.dpo_name or 'Not configured'} <{org.dpo_email or 'No email'}>

LATEST AUDIT SUMMARY:
- Compliance Score: {score}%
- Total Findings: {total_findings}
- Critical Issues: {critical}
- High Issues: {high}
- Audit Date: {latest_audit.created_at.strftime('%d %b %Y') if latest_audit else 'N/A'}

TOP FINDINGS:
{finding_summaries}

INSTRUCTIONS:
- Answer the user's compliance question using the data above
- Be specific, cite finding titles when relevant
- Recommend actions aligned with NDPA 2023 and GAID 2025
- Be concise — max 3 paragraphs unless the user asks for detail
- If you don't know something, say so rather than hallucinating
"""


@router.post("/", response_model=ChatResponse)
async def chat_with_audit(
    request: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Ask Gemini AI questions about your compliance posture."""
    if not settings.GOOGLE_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI chat is not configured. Set GOOGLE_API_KEY in your environment.",
        )

    # Fetch org & recent audit data
    org_result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = org_result.scalar_one()

    audits_result = await db.execute(
        select(Audit)
        .where(
            Audit.org_id == current_user.org_id,
            Audit.status == AuditStatus.COMPLETED,
        )
        .order_by(Audit.created_at.desc())
        .limit(5)
    )
    audits = audits_result.scalars().all()

    # Get findings from the most relevant audit
    target_audit_id = request.audit_id or (str(audits[0].id) if audits else None)
    findings = []
    if target_audit_id:
        findings_result = await db.execute(
            select(Finding).where(Finding.audit_id == target_audit_id).limit(30)
        )
        findings = findings_result.scalars().all()

    system_prompt = await _build_audit_context_prompt(
        org=org,
        audits=audits,
        findings=findings,
        audit_id=target_audit_id,
    )

    try:
        import google.generativeai as genai
        genai.configure(api_key=settings.GOOGLE_API_KEY)
        model = genai.GenerativeModel("gemini-1.5-flash", system_instruction=system_prompt)

        # Build conversation history
        gemini_history = []
        for msg in request.history[-8:]:  # keep last 8 turns for context window
            gemini_history.append({
                "role": msg.role,
                "parts": [msg.content],
            })

        chat = model.start_chat(history=gemini_history)
        response = await chat.send_message_async(request.message)
        reply = response.text

        return ChatResponse(
            reply=reply,
            audit_id=target_audit_id,
            sources=[f.title for f in findings[:5]],
        )
    except Exception as e:
        logger.error(f"Gemini chat error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI service error: {str(e)}",
        )
