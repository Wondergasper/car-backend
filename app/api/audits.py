"""
Audits API - org-scoped with detailed tracking.
Triggers the audit processor to run the full pipeline:
connector events → PII scanner → rules engine → findings → score.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from datetime import datetime, timedelta
from app.db.session import get_db
from app.models.database import User, Audit, Finding, Organization, AuditStatus
from app.schemas.schemas import AuditGenerate, AuditResponse, FindingResponse
from app.api.dependencies import get_current_user
from app.services.audit_processor import run_audit

router = APIRouter()


@router.get("/", response_model=List[AuditResponse])
async def list_audits(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Audit)
        .where(Audit.org_id == current_user.org_id)
        .order_by(Audit.created_at.desc())
    )
    audits = result.scalars().all()
    return audits


@router.get("/{audit_id}", response_model=AuditResponse)
async def get_audit(
    audit_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Audit).where(
            Audit.id == audit_id,
            Audit.org_id == current_user.org_id
        )
    )
    audit = result.scalar_one_or_none()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    return audit


@router.get("/{audit_id}/findings", response_model=List[FindingResponse])
async def get_audit_findings(
    audit_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Audit).where(
            Audit.id == audit_id,
            Audit.org_id == current_user.org_id
        )
    )
    audit = result.scalar_one_or_none()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    findings_result = await db.execute(
        select(Finding).where(Finding.audit_id == audit_id)
    )
    return findings_result.scalars().all()


@router.post("/generate", response_model=AuditResponse, status_code=status.HTTP_202_ACCEPTED)
async def generate_audit(
    audit_data: AuditGenerate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Check org limits
    result = await db.execute(select(Organization).where(Organization.id == current_user.org_id))
    org = result.scalar_one()

    result = await db.execute(
        select(Audit).where(
            Audit.org_id == org.id,
            Audit.created_at >= func.now() - timedelta(days=30)
        )
    )
    monthly_audits = len(result.scalars().all())

    if monthly_audits >= org.max_monthly_audits:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Monthly audit limit reached ({org.max_monthly_audits}). Upgrade your plan.",
        )

    # Create new audit
    audit_name = audit_data.name or f"Compliance Audit - {org.name}"
    new_audit = Audit(
        org_id=org.id,
        initiated_by=current_user.id,
        name=audit_name,
        audit_type=audit_data.audit_type,
        scope=audit_data.scope,
        status=AuditStatus.IN_PROGRESS,
        started_at=datetime.utcnow(),
    )
    db.add(new_audit)
    await db.commit()
    await db.refresh(new_audit)

    # Run the audit processor (synchronous for now, Celery later)
    try:
        completed_audit = await run_audit(str(new_audit.id), db)
        # Refresh to get the latest state
        result = await db.execute(
            select(Audit).where(Audit.id == completed_audit.id)
        )
        return result.scalar_one()
    except Exception as e:
        # Audit failed, update status
        result = await db.execute(
            select(Audit).where(Audit.id == new_audit.id)
        )
        failed_audit = result.scalar_one()
        failed_audit.status = AuditStatus.FAILED
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Audit processing failed: {str(e)}",
        )


@router.get("/{audit_id}/download", status_code=status.HTTP_200_OK)
async def download_audit_report(
    audit_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Audit).where(
            Audit.id == audit_id,
            Audit.org_id == current_user.org_id
        )
    )
    audit = result.scalar_one_or_none()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    if not audit.report_storage_key:
        raise HTTPException(status_code=404, detail="Report not yet generated")

    # Get presigned URL from object storage
    from app.services.storage import object_storage
    presigned_url = await object_storage.get_presigned_url(
        audit.report_storage_key,
        expiration=3600
    )
    if not presigned_url:
        raise HTTPException(status_code=500, detail="Failed to generate download URL")

    return {"download_url": presigned_url, "filename": f"CAR-{audit_id[:8]}.pdf"}
