"""
PII Inventory Aggregation Service.

Builds a system-wide map of what PII exists, where it lives,
and in what volume across all connected data sources.
This is the "Digital Dragnet" output — a machine-readable inventory.
"""
from typing import List, Dict, Any, Optional
from datetime import datetime
from uuid import UUID

from sqlalchemy import select, func as sa_func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.pii_scanner import PIIScanner, PIIFinding
from app.models.database import ConnectorEvent, Connector


class PIIInventoryBuilder:
    """
    Aggregates PII findings across all connector events for an organization.
    Produces a structured inventory: what PII, where, how much.
    """

    def __init__(self, db: AsyncSession, org_id: UUID):
        self.db = db
        self.org_id = org_id
        self.scanner = PIIScanner()

    async def build_inventory(self) -> Dict[str, Any]:
        """
        Build the complete PII inventory for an organization.
        Returns a structured JSON-serializable dict.
        """
        # Get all connector events for this org
        result = await self.db.execute(
            select(ConnectorEvent).where(
                ConnectorEvent.org_id == self.org_id
            ).order_by(ConnectorEvent.created_at.desc())
        )
        events = result.scalars().all()

        # Aggregate PII findings per event
        all_findings = []
        by_source = {}
        by_category = {}
        by_risk = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        timeline = []

        for event in events:
            if not event.payload_sample:
                continue

            source_key = str(event.connector_id)

            # Scan payload for PII
            try:
                import json
                payload = json.loads(event.payload_sample)
                event_findings = self.scanner.scan_dict(
                    payload,
                    location=f"connector/{event.connector_id}/{event.event_type}"
                )
            except json.JSONDecodeError:
                event_findings = self.scanner.scan_text(
                    event.payload_sample,
                    location=f"connector/{event.connector_id}/raw"
                )

            if not event_findings:
                continue

            all_findings.extend(event_findings)

            # By source
            source_entry = by_source.get(source_key, {
                "connector_id": source_key,
                "event_count": 0,
                "pii_count": 0,
                "categories": {},
                "locations": [],
                "latest_scan": None,
            })
            source_entry["event_count"] += 1
            source_entry["pii_count"] += len(event_findings)
            source_entry["latest_scan"] = event.created_at.isoformat()

            for f in event_findings:
                cat = f.category.value if hasattr(f.category, 'value') else str(f.category)
                source_entry["categories"][cat] = source_entry["categories"].get(cat, 0) + 1
                if f.location not in source_entry["locations"]:
                    source_entry["locations"].append(f.location)

            by_source[source_key] = source_entry

            # By category
            for f in event_findings:
                cat = f.category.value if hasattr(f.category, 'value') else str(f.category)
                by_category[cat] = by_category.get(cat, 0) + 1
                by_risk[f.risk_level] = by_risk.get(f.risk_level, 0) + 1

            # Timeline entry
            timeline.append({
                "timestamp": event.created_at.isoformat(),
                "connector_id": str(event.connector_id),
                "event_type": event.event_type,
                "pii_found": len(event_findings),
            })

        # Build connector name map
        connector_ids = [UUID(k) for k in by_source.keys()]
        if connector_ids:
            conn_result = await self.db.execute(
                select(Connector).where(Connector.id.in_(connector_ids))
            )
            connectors = {str(c.id): c.name for c in conn_result.scalars().all()}
        else:
            connectors = {}

        # Enrich by_source with connector names
        for key, source in by_source.items():
            source["connector_name"] = connectors.get(key, "Unknown")

        summary = self.scanner.get_summary(all_findings)

        return {
            "org_id": str(self.org_id),
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_pii_instances": summary["total_findings"],
                "by_category": summary["by_category"],
                "by_risk_level": summary["by_risk_level"],
                "total_sources_scanned": len(by_source),
            },
            "by_source": by_source,
            "by_category": by_category,
            "by_risk_level": by_risk,
            "timeline": timeline[-100:],  # Last 100 events
            "high_risk_locations": summary.get("high_risk_locations", []),
        }

    async def get_inventory_for_audit(self, connector_ids: Optional[List[str]] = None) -> List[PIIFinding]:
        """
        Get PII findings for a specific audit scope.
        Returns raw PIIFinding objects for the rules engine.
        """
        query = select(ConnectorEvent).where(
            ConnectorEvent.org_id == self.org_id,
            ConnectorEvent.processed == False,
        )
        if connector_ids:
            query = query.where(ConnectorEvent.connector_id.in_(connector_ids))

        result = await self.db.execute(query.order_by(ConnectorEvent.created_at.desc()))
        events = result.scalars().all()

        all_findings = []
        for event in events:
            if not event.payload_sample:
                continue
            try:
                import json
                payload = json.loads(event.payload_sample)
                event_findings = self.scanner.scan_dict(
                    payload,
                    location=f"connector/{event.connector_id}/{event.event_type}"
                )
            except json.JSONDecodeError:
                event_findings = self.scanner.scan_text(
                    event.payload_sample,
                    location=f"connector/{event.connector_id}/raw"
                )
            all_findings.extend(event_findings)

        return all_findings
