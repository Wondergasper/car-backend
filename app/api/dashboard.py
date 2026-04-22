from fastapi import APIRouter, Depends, Request
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.models.database import User, Audit, Connector, AuditStatus, ConnectorStatus, Document
from app.api.dependencies import get_current_user
from typing import Dict, Any

router = APIRouter()

@router.get("/stats")
async def get_dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get aggregated statistics for the dashboard overview.
    Optimized to return counts and latest scores directly from DB.
    """
    # 1. Total findings (sum across all audits for the org)
    findings_res = await db.execute(
        select(func.sum(Audit.findings_count))
        .where(Audit.org_id == current_user.org_id)
    )
    total_findings = findings_res.scalar() or 0

    # 2. Latest compliance score (from the most recent completed audit)
    score_res = await db.execute(
        select(Audit.compliance_score)
        .where(
            Audit.org_id == current_user.org_id,
            Audit.status == AuditStatus.COMPLETED,
            Audit.compliance_score.isnot(None)
        )
        .order_by(Audit.created_at.desc())
        .limit(1)
    )
    latest_score = score_res.scalar()

    # 3. Active connectors count
    connectors_res = await db.execute(
        select(func.count(Connector.id))
        .where(
            Connector.org_id == current_user.org_id,
            Connector.status == ConnectorStatus.ACTIVE,
            Connector.deleted_at.is_(None)
        )
    )
    active_connectors = connectors_res.scalar() or 0

    # 4. Pending/In-progress audits count
    pending_audits_res = await db.execute(
        select(func.count(Audit.id))
        .where(
            Audit.org_id == current_user.org_id,
            Audit.status.in_([AuditStatus.PENDING, AuditStatus.IN_PROGRESS])
        )
    )
    pending_audits = pending_audits_res.scalar() or 0

    documents = (
        await db.execute(
            select(Document).where(Document.org_id == current_user.org_id).order_by(Document.created_at.desc())
        )
    ).scalars().all()
    analyzed_documents = 0
    high_risk_documents = 0

    for document in documents:
        analysis = (document.content or {}).get("analysis", {}) if isinstance(document.content, dict) else {}
        summary = analysis.get("summary", {})
        if analysis.get("status") == "completed":
            analyzed_documents += 1
        if summary.get("by_risk_level", {}).get("critical", 0) or summary.get("by_risk_level", {}).get("high", 0):
            high_risk_documents += 1

    return {
        "compliance_score": latest_score,
        "active_connectors": active_connectors,
        "total_findings": total_findings,
        "pending_audits": pending_audits,
        "analyzed_documents": analyzed_documents,
        "high_risk_documents": high_risk_documents,
    }
