"""
Audits API - org-scoped with detailed tracking.
Triggers the audit processor to run the full pipeline:
connector events → PII scanner → rules engine → findings → score.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request, WebSocket, WebSocketDisconnect
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from datetime import datetime, timedelta, timezone
from app.db.session import get_db
from app.models.database import (
    User, Audit, Finding, Organization, AuditStatus, FindingStatus, FindingSeverity
)
from app.schemas.schemas import AuditGenerate, AuditResponse, FindingResponse
from app.api.dependencies import get_current_user
from app.services.audit_processor import run_audit
import asyncio
import hashlib
import json
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


from app.services.filing_service import file_audit


@router.get("/", response_model=List[AuditResponse])
async def list_audits(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 50,
):
    result = await db.execute(
        select(Audit)
        .where(Audit.org_id == current_user.org_id)
        .order_by(Audit.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    audits = result.scalars().all()
    return audits


@router.get("/generate", include_in_schema=True)
async def generate_audit_wrong_method():
    """Avoid mistaking GET /audits/generate for an audit id."""
    raise HTTPException(
        status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
        detail="Use POST /api/audits/generate with a JSON body to start an audit.",
    )


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


@router.post("/{audit_id}/submit", response_model=AuditResponse)
async def submit_audit_to_ndpc(
    audit_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    try:
        result = await db.execute(
            select(Audit).where(
                Audit.id == audit_id,
                Audit.org_id == current_user.org_id
            )
        )
        audit = result.scalar_one_or_none()
        if not audit:
            raise HTTPException(status_code=404, detail="Audit not found")

        await file_audit(str(audit.id), db)
        await db.refresh(audit)
        return audit
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Filing failed for audit {audit_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Regulatory filing failed")


from app.services.fix_generator import FixGenerationService


# ─── WebSocket: Real-Time Audit Progress ────────────────────────────────────

@router.websocket("/ws/{audit_id}/progress")
async def audit_progress_ws(websocket: WebSocket, audit_id: str, db: AsyncSession = Depends(get_db)):
    """Stream live audit progress to the client."""
    await websocket.accept()
    try:
        while True:
            result = await db.execute(select(Audit).where(Audit.id == audit_id))
            audit = result.scalar_one_or_none()
            if not audit:
                await websocket.send_json({"error": "Audit not found"})
                break

            await websocket.send_json({
                "audit_id": str(audit.id),
                "status": audit.status.value if hasattr(audit.status, "value") else audit.status,
                "progress": float(audit.progress or 0),
                "findings_count": audit.findings_count or 0,
                "compliance_score": audit.compliance_score,
            })

            terminal_statuses = {AuditStatus.COMPLETED, AuditStatus.FAILED, AuditStatus.CANCELLED}
            if audit.status in terminal_statuses:
                break

            await asyncio.sleep(2)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error for audit {audit_id}: {e}")
    finally:
        await websocket.close()


# ─── Bulk Finding Resolve / Accept ──────────────────────────────────────────

class FindingUpdate(AuditResponse.__class__):
    pass

from pydantic import BaseModel as _BaseModel

class FindingStatusUpdate(_BaseModel):
    status: FindingStatus
    resolution_notes: Optional[str] = None

class BulkFindingAction(_BaseModel):
    ids: List[str]
    action: str  # "resolve", "accept", "false_positive"
    resolution_notes: Optional[str] = None


@router.patch("/{audit_id}/findings/{finding_id}", response_model=FindingResponse)
async def update_finding_status(
    audit_id: str,
    finding_id: str,
    data: FindingStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a single finding's status (resolve, accept, mark false positive)."""
    result = await db.execute(
        select(Finding).where(
            Finding.id == finding_id,
            Finding.audit_id == audit_id,
            Finding.org_id == current_user.org_id,
        )
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = data.status
    finding.resolution_notes = data.resolution_notes
    if data.status == FindingStatus.RESOLVED:
        finding.resolved_by = current_user.id
        finding.resolved_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(finding)
    return finding


@router.post("/{audit_id}/findings/batch")
async def bulk_update_findings(
    audit_id: str,
    data: BulkFindingAction,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Bulk update multiple findings at once."""
    action_map = {
        "resolve": FindingStatus.RESOLVED,
        "accept": FindingStatus.ACCEPTED,
        "false_positive": FindingStatus.FALSE_POSITIVE,
        "in_review": FindingStatus.IN_REVIEW,
    }
    if data.action not in action_map:
        raise HTTPException(status_code=400, detail=f"Unknown action '{data.action}'. Use: resolve, accept, false_positive, in_review")

    new_status = action_map[data.action]
    updated = 0

    for finding_id in data.ids:
        result = await db.execute(
            select(Finding).where(
                Finding.id == finding_id,
                Finding.audit_id == audit_id,
                Finding.org_id == current_user.org_id,
            )
        )
        finding = result.scalar_one_or_none()
        if finding:
            finding.status = new_status
            finding.resolution_notes = data.resolution_notes
            if new_status == FindingStatus.RESOLVED:
                finding.resolved_by = current_user.id
                finding.resolved_at = datetime.now(timezone.utc)
            updated += 1

    await db.commit()
    return {"updated": updated, "action": data.action}


# ─── Audit Diff / Changelog ─────────────────────────────────────────────────

@router.get("/{audit_id}/diff")
async def get_audit_diff(
    audit_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Compare this audit with the previous one — surface regressions and improvements."""
    result = await db.execute(
        select(Audit).where(
            Audit.id == audit_id,
            Audit.org_id == current_user.org_id
        )
    )
    current_audit = result.scalar_one_or_none()
    if not current_audit:
        raise HTTPException(status_code=404, detail="Audit not found")
    if current_audit.status != AuditStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Audit must be completed to generate a diff")

    # Get the previously completed audit
    prev_result = await db.execute(
        select(Audit)
        .where(
            Audit.org_id == current_user.org_id,
            Audit.status == AuditStatus.COMPLETED,
            Audit.created_at < current_audit.created_at,
        )
        .order_by(Audit.created_at.desc())
        .limit(1)
    )
    prev_audit = prev_result.scalar_one_or_none()

    if not prev_audit:
        return {
            "message": "No previous audit to compare against",
            "score_delta": None,
            "new_findings": [],
            "resolved_findings": [],
            "regressions": 0,
            "improvements": 0,
        }

    # Get rule_ids from both audits
    cur_findings_res = await db.execute(select(Finding).where(Finding.audit_id == current_audit.id))
    cur_findings = cur_findings_res.scalars().all()

    prev_findings_res = await db.execute(select(Finding).where(Finding.audit_id == prev_audit.id))
    prev_findings = prev_findings_res.scalars().all()

    cur_rule_ids = {f.rule_id for f in cur_findings}
    prev_rule_ids = {f.rule_id for f in prev_findings}

    new_rule_ids = cur_rule_ids - prev_rule_ids
    resolved_rule_ids = prev_rule_ids - cur_rule_ids

    new_findings = [f for f in cur_findings if f.rule_id in new_rule_ids]
    resolved_findings = [f for f in prev_findings if f.rule_id in resolved_rule_ids]

    score_delta = None
    if current_audit.compliance_score is not None and prev_audit.compliance_score is not None:
        score_delta = current_audit.compliance_score - prev_audit.compliance_score

    return {
        "current_audit_id": str(current_audit.id),
        "previous_audit_id": str(prev_audit.id),
        "score_delta": score_delta,
        "current_score": current_audit.compliance_score,
        "previous_score": prev_audit.compliance_score,
        "regressions": len(new_findings),
        "improvements": len(resolved_findings),
        "new_findings": [
            {"rule_id": f.rule_id, "title": f.title, "severity": f.severity.value if hasattr(f.severity, "value") else f.severity}
            for f in new_findings
        ],
        "resolved_findings": [
            {"rule_id": f.rule_id, "title": f.title, "severity": f.severity.value if hasattr(f.severity, "value") else f.severity}
            for f in resolved_findings
        ],
    }


@router.get("/{audit_id}/remediation", status_code=status.HTTP_200_OK)
async def generate_remediation_plans(
    audit_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Ensure audit exists
    result = await db.execute(
        select(Audit).where(
            Audit.id == audit_id,
            Audit.org_id == current_user.org_id
        )
    )
    audit = result.scalar_one_or_none()
    if not audit:
        raise HTTPException(status_code=404, detail="Audit not found")

    # Get findings
    findings_result = await db.execute(
        select(Finding).where(Finding.audit_id == audit_id)
    )
    findings = findings_result.scalars().all()

    if not findings:
        return {"message": "No findings to remediate", "plans": []}

    # Generate fixes using the service (Gemini-powered or template-based)
    fix_service = FixGenerationService()
    
    # Map raw DB findings to ComplianceFinding for the service
    from app.core.rules_engine import ComplianceFinding
    compliance_findings = []
    for f in findings:
        compliance_findings.append(ComplianceFinding(
            rule_id=f.rule_id,
            severity=f.severity,
            title=f.title,
            description=f.description,
            recommendation=f.recommendation,
            evidence=f.evidence or {},
            auto_fixable=f.auto_fixable
        ))

    # Get organization context for better AI generation
    org_result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = org_result.scalar_one()
    org_context = {
        "company_name": org.name,
        "dpo_name": org.dpo_name,
        "dpo_email": org.dpo_email,
        "industry": org.industry
    }

    plans = await fix_service.generate_all_fixes(compliance_findings, org_context)
    return plans


from fastapi import UploadFile, File
import io
import pdfplumber

@router.post("/upload-data", status_code=status.HTTP_200_OK)
async def upload_analysis_data(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Accepts manual file uploads (PDF, JSON) to be used as data sources
    for analysis. Bridging the gap for Hackathon demos.
    """
    try:
        content = await file.read()
        payload_dict = {}

        if file.filename.endswith(".json"):
            payload_dict = json.loads(content)
        elif file.filename.endswith(".pdf"):
            with pdfplumber.open(io.BytesIO(content)) as pdf:
                extracted_text = "\n".join([page.extract_text() or "" for page in pdf.pages])
                payload_dict = {"unstructured_text": extracted_text}
        else:
            # Fallback for csv, txt etc.
            payload_dict = {"raw_content": content.decode("utf-8", errors="ignore")}

        # Create a ConnectorEvent representing this manual upload
        from app.models.database import ConnectorEvent

        payload_json = json.dumps(payload_dict, default=str)
        payload_hash = hashlib.sha256(content).hexdigest()
        new_event = ConnectorEvent(
            org_id=current_user.org_id,
            connector_id=None,
            event_type="manual_file_upload",
            payload_hash=payload_hash,
            payload_size=len(content),
            payload_sample=payload_json,
            processed=False,
        )
        db.add(new_event)
        await db.commit()

        return {
            "status": "success", 
            "message": f"Successfully parsed {file.filename} for analysis. You can now run an audit."
        }
    except Exception as e:
        logger.error(f"File upload failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"File processing failed: {str(e)}")
