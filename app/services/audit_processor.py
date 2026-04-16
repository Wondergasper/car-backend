"""
Audit Processor — The Pipeline Core.

Connects: Connector Events → PII Scanner → Rules Engine → Findings → Audit Results

This is the synchronous processor that runs when an audit is triggered.
(Async background processing via Celery will be added later.)
"""
import json
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.rules_engine import RulesEngine, AuditContext, ComplianceFinding
from app.core.pii_scanner import PIIScanner
from app.models.database import (
    ConnectorEvent, Audit, Finding, Connector, ComplianceRule,
    AuditStatus, FindingSeverity, FindingStatus,
)

logger = logging.getLogger(__name__)


class AuditProcessor:
    """
    Processes an audit by:
    1. Collecting all unprocessed connector events
    2. Scanning payloads for PII
    3. Building an AuditContext from the aggregated data
    4. Running the rules engine against the context
    5. Saving findings to the database
    6. Updating the audit status and compliance score
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.pii_scanner = PIIScanner()
        self.rules_engine = RulesEngine()

    async def process_audit(self, audit: Audit) -> Audit:
        """
        Run the full audit pipeline for a given audit record.
        Returns the updated audit with findings and score.
        """
        audit.status = AuditStatus.IN_PROGRESS
        audit.progress = 5.0
        audit.started_at = datetime.utcnow()
        await self.db.commit()

        try:
            # Step 1: Get connector IDs from audit scope
            connector_ids = self._get_connector_ids(audit)
            audit.progress = 10.0
            await self._update_audit(audit)

            # Step 2: Collect unprocessed events from those connectors
            events = await self._collect_events(connector_ids)
            audit.progress = 20.0
            await self._update_audit(audit)

            # Step 3: Build AuditContext from events + connector metadata
            context = await self._build_context(events, connector_ids)
            audit.progress = 40.0
            await self._update_audit(audit)

            # Step 4: Run rules engine
            findings = self.rules_engine.evaluate(context)
            audit.progress = 70.0
            await self._update_audit(audit)

            # Step 5: Save findings to database
            await self._save_findings(audit, findings, context)
            audit.progress = 90.0
            await self._update_audit(audit)

            # Step 6: Calculate compliance score and finalize
            summary = self.rules_engine.generate_summary(findings)
            audit.compliance_score = summary["compliance_score"]
            audit.findings_count = summary["total_findings"]
            audit.critical_count = summary["by_severity"].get("critical", 0)
            audit.high_count = summary["by_severity"].get("high", 0)
            audit.medium_count = summary["by_severity"].get("medium", 0)
            audit.low_count = summary["by_severity"].get("low", 0)
            audit.info_count = summary["by_severity"].get("info", 0)
            audit.status = AuditStatus.COMPLETED
            audit.completed_at = datetime.utcnow()
            audit.progress = 100.0

            await self.db.commit()
            await self.db.refresh(audit)

            logger.info(
                f"Audit {audit.id} completed: score={audit.compliance_score}%, "
                f"findings={audit.findings_count} "
                f"(C:{audit.critical_count} H:{audit.high_count} "
                f"M:{audit.medium_count} L:{audit.low_count})"
            )

            return audit

        except Exception as e:
            logger.error(f"Audit {audit.id} failed: {e}", exc_info=True)
            audit.status = AuditStatus.FAILED
            audit.progress = 0
            await self.db.commit()
            raise

    def _get_connector_ids(self, audit: Audit) -> List[str]:
        """Extract connector IDs from audit scope, or use all org connectors."""
        if audit.scope and "connectors" in audit.scope:
            return audit.scope["connectors"]
        # Default: use all active connectors for the org
        # This is resolved at runtime via DB query
        return []

    async def _collect_events(self, connector_ids: List[str]) -> List[ConnectorEvent]:
        """Collect all unprocessed events from the specified connectors."""
        query = select(ConnectorEvent).where(
            ConnectorEvent.processed == False,
            ConnectorEvent.retry_count < ConnectorEvent.max_retries,
        )
        if connector_ids:
            query = query.where(ConnectorEvent.connector_id.in_(connector_ids))

        result = await self.db.execute(query.order_by(ConnectorEvent.created_at.asc()))
        return list(result.scalars().all())

    async def _build_context(self, events: List[ConnectorEvent], connector_ids: List[str]) -> AuditContext:
        """
        Build an AuditContext from connector events and connector metadata.
        This is where raw events become structured audit input.
        """
        context = AuditContext()

        # Get connector metadata
        if connector_ids:
            result = await self.db.execute(
                select(Connector).where(Connector.id.in_(connector_ids))
            )
            connectors = result.scalars().all()
            for c in connectors:
                context.connectors.append({
                    "id": str(c.id),
                    "name": c.name,
                    "type_id": str(c.connector_type_id),
                    "status": c.status.value if hasattr(c.status, 'value') else str(c.status),
                    "sync_enabled": c.sync_enabled,
                })

        # Process each event: scan payload for PII, extract metadata
        pii_findings = []
        for event in events:
            if event.payload_sample:
                try:
                    payload = json.loads(event.payload_sample)
                    # Scan for PII
                    event_pii = self.pii_scanner.scan_dict(
                        payload,
                        location=f"connector/{event.connector_id}/event/{event.event_type}"
                    )
                    pii_findings.extend(event_pii)

                    # Extract security posture from payload
                    self._extract_security_context(context, payload)
                except json.JSONDecodeError:
                    # Try scanning as raw text
                    text_pii = self.pii_scanner.scan_text(
                        event.payload_sample,
                        location=f"connector/{event.connector_id}/text"
                    )
                    pii_findings.extend(text_pii)

        context.pii_inventory = pii_findings

        # If no events were available, still create a minimal context
        # This allows audits to run even without connector data
        if not events:
            logger.warning(f"No unprocessed events found. Running audit with minimal context.")

        return context

    def _extract_security_context(self, context: AuditContext, payload: Dict[str, Any]):
        """
        Extract security/governance signals from connector payload.
        The payload may contain metadata about the source system's
        security posture, not just raw data.
        """
        # Encryption signals
        if payload.get("encryption"):
            enc = payload["encryption"]
            if isinstance(enc, dict):
                if enc.get("at_rest"):
                    context.encryption_at_rest = True
                if enc.get("in_transit") or enc.get("tls"):
                    context.encryption_in_transit = True
            elif isinstance(enc, str) and enc.lower() in ("aes256", "aes-256", "enabled", "true"):
                context.encryption_at_rest = True

        # Authentication signals
        auth = payload.get("authentication", {})
        if isinstance(auth, dict):
            if auth.get("mfa") or auth.get("multi_factor"):
                context.mfa_enabled = True

        # Access control signals
        if payload.get("access_control") or payload.get("rbac"):
            context.access_control_policy = "detected"
            if payload.get("rbac", {}).get("enabled"):
                context.role_based_access = True

        # Audit logging signals
        if payload.get("audit_logging") or payload.get("audit_trail"):
            context.audit_logging_enabled = True
            context.authorization_audit_trail = True

        # Consent signals
        if payload.get("consent_records"):
            records = payload["consent_records"]
            if isinstance(records, list):
                context.consent_records.extend(records)
            if payload.get("consent_method"):
                context.consent_collection_method = payload["consent_method"]

        # Governance signals
        if payload.get("retention_policy"):
            context.retention_policy = payload["retention_policy"]
        if payload.get("deletion_procedures"):
            context.deletion_procedures = payload["deletion_procedures"]
        if payload.get("purpose_statements"):
            context.purpose_statements = payload["purpose_statements"]
        if payload.get("processing_purposes"):
            context.data_processing_purposes = payload["processing_purposes"]

        # Data subject rights signals
        if payload.get("dsar_procedure"):
            context.dsar_procedure = payload["dsar_procedure"]
        if payload.get("rectification_procedure"):
            context.rectification_procedure = payload["rectification_procedure"]
        if payload.get("erasure_procedure"):
            context.erasure_procedure = payload["erasure_procedure"]

        # Breach management signals
        if payload.get("breach_notification"):
            context.breach_notification_procedure = payload["breach_notification"]
        if payload.get("breach_response_plan"):
            context.breach_response_plan = payload["breach_response_plan"]

        # Data minimization signals
        if payload.get("personal_data_fields"):
            fields = payload["personal_data_fields"]
            if isinstance(fields, list):
                context.personal_data_fields.extend(fields)
        if payload.get("excessive_fields"):
            fields = payload["excessive_fields"]
            if isinstance(fields, list):
                context.excessive_fields.extend(fields)

        # Data age signals
        if payload.get("oldest_record_date"):
            try:
                context.oldest_record_date = datetime.fromisoformat(payload["oldest_record_date"])
            except (ValueError, TypeError):
                pass
        if payload.get("record_age_distribution"):
            context.record_age_distribution = payload["record_age_distribution"]

        # Cross-border signals
        if payload.get("data_locations"):
            locs = payload["data_locations"]
            if isinstance(locs, list):
                context.data_locations.extend(locs)
        if payload.get("cross_border_transfers"):
            transfers = payload["cross_border_transfers"]
            if isinstance(transfers, list):
                context.cross_border_transfers.extend(transfers)
        if payload.get("adequacy_countries"):
            countries = payload["adequacy_countries"]
            if isinstance(countries, list):
                context.adequacy_countries.extend(countries)

        # GAID 2025 signals
        if payload.get("gaid_consent_records"):
            context.gaid_consent_records = payload["gaid_consent_records"]
        if payload.get("gaid_transparency_notice"):
            context.gaid_transparency_notice = payload["gaid_transparency_notice"]
        if payload.get("gaid_data_portability"):
            context.gaid_data_portability = payload["gaid_data_portability"]

    async def _save_findings(
        self,
        audit: Audit,
        findings: List[ComplianceFinding],
        context: AuditContext,
    ):
        """Save compliance findings to the database."""
        for f in findings:
            # Map severity enum to string for DB
            severity_str = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            severity_enum = FindingSeverity(severity_str) if severity_str in [s.value for s in FindingSeverity] else FindingSeverity.HIGH

            finding = Finding(
                audit_id=audit.id,
                org_id=audit.org_id,
                rule_id=f.rule_id,
                severity=severity_enum,
                title=f.title,
                description=f.description,
                recommendation=f.recommendation,
                evidence=f.evidence,
                affected_records=f.affected_records,
                auto_fixable=f.auto_fixable,
                auto_fix_suggestion=f.auto_fix_suggestion,
                status=FindingStatus.OPEN,
            )
            self.db.add(finding)

        # Mark events as processed
        connector_ids = self._get_connector_ids(audit)
        events = await self._collect_events(connector_ids)
        for event in events:
            event.processed = True
            event.processed_at = datetime.utcnow()
            self.db.add(event)

        await self.db.commit()

    async def _update_audit(self, audit: Audit):
        """Update audit progress in the database."""
        await self.db.commit()
        await self.db.refresh(audit)


async def run_audit(audit_id: str, db: AsyncSession) -> Audit:
    """
    Entry point for running an audit.
    Call this from the API or from a background task.
    """
    result = await db.execute(select(Audit).where(Audit.id == audit_id))
    audit = result.scalar_one_or_none()
    if not audit:
        raise ValueError(f"Audit {audit_id} not found")

    processor = AuditProcessor(db)
    return await processor.process_audit(audit)
