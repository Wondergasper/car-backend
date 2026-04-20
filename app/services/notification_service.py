"""
Notification Service.
Sends email alerts via Resend and fires outgoing webhooks on key events.
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import httpx
import json
import logging
from datetime import datetime, timezone

from app.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


@dataclass
class NotificationEvent:
    event_type: str        # "audit.completed", "finding.critical", etc.
    org_id: str
    payload: Dict[str, Any]


class ResendEmailService:
    """Send transactional emails via Resend API."""

    BASE_URL = "https://api.resend.com/emails"

    def __init__(self):
        self.api_key = settings.RESEND_API_KEY
        self.from_email = settings.RESEND_FROM_EMAIL
        self.enabled = bool(self.api_key)

    async def send(
        self,
        to: str,
        subject: str,
        html: str,
    ) -> bool:
        if not self.enabled:
            logger.info(f"[Resend disabled] Would send email to {to}: {subject}")
            return False
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    self.BASE_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "from": self.from_email,
                        "to": [to],
                        "subject": subject,
                        "html": html,
                    },
                )
                resp.raise_for_status()
                logger.info(f"Email sent to {to}: {subject}")
                return True
        except Exception as e:
            logger.error(f"Failed to send email to {to}: {e}")
            return False

    def build_audit_complete_html(
        self,
        org_name: str,
        audit_name: str,
        compliance_score: Optional[int],
        findings_count: int,
        critical_count: int,
        dashboard_url: str,
    ) -> str:
        score_color = (
            "#22c55e" if (compliance_score or 0) >= 80
            else "#f59e0b" if (compliance_score or 0) >= 60
            else "#ef4444"
        )
        return f"""
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; background: #0f172a; color: #e2e8f0; padding: 32px; border-radius: 12px;">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:24px;">
            <div style="background:linear-gradient(135deg,#06b6d4,#3b82f6);width:40px;height:40px;border-radius:10px;display:flex;align-items:center;justify-content:center;">
              <span style="color:white;font-size:20px">🛡️</span>
            </div>
            <span style="font-size:22px;font-weight:bold;color:white;">CAR-Bot</span>
          </div>
          <h1 style="color:white;font-size:20px;margin-bottom:8px;">Audit Completed: {audit_name}</h1>
          <p style="color:#94a3b8;margin-bottom:24px;">Your compliance audit for <strong style="color:white">{org_name}</strong> has finished.</p>

          <div style="background:#1e293b;border-radius:10px;padding:20px;margin-bottom:24px;">
            <div style="display:flex;justify-content:space-between;margin-bottom:12px;">
              <span style="color:#94a3b8">Compliance Score</span>
              <strong style="color:{score_color};font-size:20px">{compliance_score if compliance_score is not None else 'N/A'}%</strong>
            </div>
            <div style="display:flex;justify-content:space-between;margin-bottom:12px;">
              <span style="color:#94a3b8">Total Findings</span>
              <strong style="color:white">{findings_count}</strong>
            </div>
            <div style="display:flex;justify-content:space-between;">
              <span style="color:#94a3b8">Critical Issues</span>
              <strong style="color:#ef4444">{critical_count}</strong>
            </div>
          </div>

          <a href="{dashboard_url}" style="display:inline-block;background:linear-gradient(135deg,#06b6d4,#3b82f6);color:white;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;">
            View Full Report →
          </a>
          <p style="color:#475569;font-size:12px;margin-top:24px;">This is an automated message from CAR-Bot. Do not reply to this email.</p>
        </div>
        """

    def build_critical_finding_html(
        self,
        org_name: str,
        finding_title: str,
        finding_description: str,
        recommendation: str,
        dashboard_url: str,
    ) -> str:
        return f"""
        <div style="font-family: sans-serif; max-width: 600px; margin: 0 auto; background: #0f172a; color: #e2e8f0; padding: 32px; border-radius: 12px;">
          <div style="background:#7f1d1d;border:1px solid #ef4444;border-radius:8px;padding:16px;margin-bottom:24px;">
            <strong style="color:#ef4444">🚨 CRITICAL FINDING DETECTED</strong>
          </div>
          <h1 style="color:white;font-size:18px;">{finding_title}</h1>
          <p style="color:#94a3b8;">{finding_description}</p>
          <div style="background:#1e293b;border-radius:8px;padding:16px;margin:16px 0;">
            <strong style="color:#06b6d4">Recommendation</strong>
            <p style="color:#e2e8f0;margin-top:8px;">{recommendation}</p>
          </div>
          <a href="{dashboard_url}" style="display:inline-block;background:#ef4444;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;">
            View Finding →
          </a>
        </div>
        """


class WebhookDeliveryService:
    """Deliver outgoing webhook payloads to registered endpoint URLs."""

    async def deliver(
        self,
        url: str,
        secret: Optional[str],
        event: NotificationEvent,
    ) -> bool:
        import hmac
        import hashlib

        payload_bytes = json.dumps({
            "event_type": event.event_type,
            "org_id": event.org_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": event.payload,
        }).encode()

        headers = {
            "Content-Type": "application/json",
            "X-CARBot-Event": event.event_type,
        }
        if secret:
            signature = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
            headers["X-CARBot-Signature"] = f"sha256={signature}"

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(url, content=payload_bytes, headers=headers)
                resp.raise_for_status()
                logger.info(f"Webhook delivered to {url}: {event.event_type}")
                return True
        except Exception as e:
            logger.error(f"Webhook delivery failed to {url}: {e}")
            return False


# Singleton instances
email_service = ResendEmailService()
webhook_service = WebhookDeliveryService()


async def notify_audit_complete(
    dpo_email: str,
    org_name: str,
    audit_name: str,
    compliance_score: Optional[int],
    findings_count: int,
    critical_count: int,
    webhook_urls: List[Dict[str, Any]] = None,
    org_id: str = "",
):
    """Notify DPO by email and fire all registered webhooks when an audit completes."""
    dashboard_url = "https://car-bot.ai/dashboard/reports"

    # Email
    html = email_service.build_audit_complete_html(
        org_name=org_name,
        audit_name=audit_name,
        compliance_score=compliance_score,
        findings_count=findings_count,
        critical_count=critical_count,
        dashboard_url=dashboard_url,
    )
    await email_service.send(
        to=dpo_email,
        subject=f"[CAR-Bot] Audit Complete: {audit_name} — Score {compliance_score}%",
        html=html,
    )

    # Webhooks
    if webhook_urls:
        event = NotificationEvent(
            event_type="audit.completed",
            org_id=org_id,
            payload={
                "audit_name": audit_name,
                "compliance_score": compliance_score,
                "findings_count": findings_count,
                "critical_count": critical_count,
            },
        )
        for hook in webhook_urls:
            await webhook_service.deliver(
                url=hook.get("url"),
                secret=hook.get("secret"),
                event=event,
            )


async def notify_critical_finding(
    dpo_email: str,
    finding_title: str,
    finding_description: str,
    recommendation: str,
    webhook_urls: List[Dict[str, Any]] = None,
    org_id: str = "",
):
    """Alert DPO immediately when a critical finding is detected."""
    dashboard_url = "https://car-bot.ai/dashboard/reports"

    html = email_service.build_critical_finding_html(
        org_name="",
        finding_title=finding_title,
        finding_description=finding_description,
        recommendation=recommendation,
        dashboard_url=dashboard_url,
    )
    await email_service.send(
        to=dpo_email,
        subject=f"[CAR-Bot] 🚨 Critical Finding: {finding_title}",
        html=html,
    )

    if webhook_urls:
        event = NotificationEvent(
            event_type="finding.critical",
            org_id=org_id,
            payload={
                "title": finding_title,
                "description": finding_description,
                "recommendation": recommendation,
            },
        )
        for hook in webhook_urls:
            await webhook_service.deliver(
                url=hook.get("url"),
                secret=hook.get("secret"),
                event=event,
            )
