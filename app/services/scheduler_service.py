"""
Scheduled Audits — APScheduler integration.
Registers scheduled audit jobs from the database and runs them at cron times.
"""
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy import select
from datetime import datetime, timezone
import logging

from app.db.session import async_session
from app.models.database import Audit, AuditStatus, AuditType, Organization, User
from app.services.audit_processor import run_audit
from app.services.notification_service import notify_audit_complete

logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler(timezone="UTC")


async def _run_scheduled_audit(
    org_id: str,
    initiated_by: str,
    audit_name: str,
):
    """Execute a scheduled audit run for an organization."""
    async with async_session() as db:
        try:
            # Verify org still exists and get context
            org_result = await db.execute(
                select(Organization).where(Organization.id == org_id)
            )
            org = org_result.scalar_one_or_none()
            if not org:
                logger.warning(f"Scheduled audit: org {org_id} not found — skipping")
                return

            # Create the audit record
            new_audit = Audit(
                org_id=org_id,
                initiated_by=initiated_by,
                name=audit_name,
                audit_type=AuditType.SCHEDULED,
                status=AuditStatus.IN_PROGRESS,
                started_at=datetime.now(timezone.utc),
            )
            db.add(new_audit)
            await db.commit()
            await db.refresh(new_audit)

            logger.info(f"Running scheduled audit {new_audit.id} for org {org.name}")
            completed = await run_audit(str(new_audit.id), db)

            # Send notification if DPO email configured
            if org.dpo_email:
                await notify_audit_complete(
                    dpo_email=org.dpo_email,
                    org_name=org.name,
                    audit_name=audit_name,
                    compliance_score=completed.compliance_score,
                    findings_count=completed.findings_count,
                    critical_count=completed.critical_count,
                    org_id=org_id,
                )

        except Exception as e:
            logger.error(f"Scheduled audit failed for org {org_id}: {e}", exc_info=True)


def register_scheduled_audit(
    job_id: str,
    org_id: str,
    initiated_by: str,
    audit_name: str,
    cron_expression: str,  # e.g., "0 8 * * 1" = every Monday 8am
):
    """Register a new scheduled audit job with APScheduler."""
    parts = cron_expression.strip().split()
    if len(parts) != 5:
        raise ValueError(f"Invalid cron expression: {cron_expression!r}. Expected 5 parts.")

    minute, hour, day, month, day_of_week = parts
    trigger = CronTrigger(
        minute=minute,
        hour=hour,
        day=day,
        month=month,
        day_of_week=day_of_week,
        timezone="UTC",
    )

    scheduler.add_job(
        _run_scheduled_audit,
        trigger=trigger,
        id=job_id,
        replace_existing=True,
        kwargs={
            "org_id": org_id,
            "initiated_by": initiated_by,
            "audit_name": audit_name,
        },
    )
    logger.info(f"Scheduled audit job registered: {job_id} — cron: {cron_expression}")


def unregister_scheduled_audit(job_id: str):
    """Remove a scheduled audit job."""
    try:
        scheduler.remove_job(job_id)
        logger.info(f"Scheduled audit job removed: {job_id}")
    except Exception:
        logger.warning(f"Scheduled job {job_id} not found — nothing to remove")


def start_scheduler():
    """Start the APScheduler event loop (called on app startup)."""
    if not scheduler.running:
        scheduler.start()
        logger.info("APScheduler started for scheduled audits")


def stop_scheduler():
    """Gracefully stop the scheduler (called on app shutdown)."""
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("APScheduler stopped")
