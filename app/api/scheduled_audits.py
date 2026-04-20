"""
Scheduled Audits API.
Create and manage cron-based automatic compliance audit schedules.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone
import secrets

from app.db.session import get_db
from app.models.database import User, Organization
from app.api.dependencies import get_current_user
from app.services.scheduler_service import register_scheduled_audit, unregister_scheduled_audit, scheduler

router = APIRouter()

# In-memory registry (replace with DB table for production)
_scheduled_audits: dict = {}


class ScheduledAuditCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    cron_expression: str = Field(
        description="Cron expression: '0 8 * * 1' = every Monday at 8am UTC"
    )
    audit_type: str = "full"


class ScheduledAuditResponse(BaseModel):
    id: str
    name: str
    cron_expression: str
    is_active: bool
    org_id: str
    created_at: str
    next_run: Optional[str] = None


@router.get("/", response_model=List[ScheduledAuditResponse])
async def list_scheduled_audits(
    current_user: User = Depends(get_current_user),
):
    """List all scheduled audit jobs for this organization."""
    org_schedules = [
        {**v, "id": k}
        for k, v in _scheduled_audits.items()
        if v["org_id"] == str(current_user.org_id)
    ]

    result = []
    for s in org_schedules:
        next_run = None
        job = scheduler.get_job(s["id"])
        if job and job.next_run_time:
            next_run = job.next_run_time.isoformat()
        result.append(ScheduledAuditResponse(**s, next_run=next_run))
    return result


@router.post("/", response_model=ScheduledAuditResponse, status_code=status.HTTP_201_CREATED)
async def create_scheduled_audit(
    data: ScheduledAuditCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new scheduled audit with a cron expression."""
    job_id = f"audit_{current_user.org_id}_{secrets.token_urlsafe(6)}"

    try:
        register_scheduled_audit(
            job_id=job_id,
            org_id=str(current_user.org_id),
            initiated_by=str(current_user.id),
            audit_name=data.name,
            cron_expression=data.cron_expression,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    schedule = {
        "id": job_id,
        "org_id": str(current_user.org_id),
        "name": data.name,
        "cron_expression": data.cron_expression,
        "is_active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _scheduled_audits[job_id] = schedule

    job = scheduler.get_job(job_id)
    next_run = job.next_run_time.isoformat() if job and job.next_run_time else None
    return ScheduledAuditResponse(**schedule, next_run=next_run)


@router.delete("/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scheduled_audit(
    job_id: str,
    current_user: User = Depends(get_current_user),
):
    """Cancel and remove a scheduled audit."""
    schedule = _scheduled_audits.get(job_id)
    if not schedule or schedule["org_id"] != str(current_user.org_id):
        raise HTTPException(status_code=404, detail="Scheduled audit not found")

    unregister_scheduled_audit(job_id)
    del _scheduled_audits[job_id]
    return None
