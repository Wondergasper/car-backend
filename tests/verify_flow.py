import asyncio
import uuid
import json
from datetime import datetime
from sqlalchemy import select, text
from app.db.session import async_session, engine, Base
from app.models.database import (
    Organization, User, UserRole, ConnectorType, Connector, 
    ConnectorEvent, Audit, AuditStatus, AuditType
)
from app.services.audit_processor import run_audit
from app.services.filing_service import file_audit

async def verify_flow():
    print("--- Verification Started ---")
    
    async with async_session() as session:
        # 1. Setup - Create Org and User
        org_id = uuid.uuid4()
        org = Organization(
            id=org_id,
            name="Test Bank PLC",
            slug=f"test-bank-{str(org_id)[:8]}",
            industry="Banking",
            dpo_name="John Doe",
            dpo_email="john@testbank.com"
        )
        session.add(org)
        
        user_id = uuid.uuid4()
        user = User(
            id=user_id,
            org_id=org_id,
            email=f"tester-{str(user_id)[:8]}@test.com",
            hashed_password="hashed_placeholder",
            full_name="Master Tester",
            role=UserRole.ADMIN
        )
        session.add(user)
        
        # 2. Setup - Connector Type (ensure postgres exists)
        result = await session.execute(select(ConnectorType).where(ConnectorType.slug == "postgresql"))
        conn_type = result.scalar_one_or_none()
        if not conn_type:
            conn_type = ConnectorType(
                slug="postgresql",
                name="PostgreSQL",
                config_schema={},
                required_fields=[],
            )
            session.add(conn_type)
            await session.flush()

        # 3. Create Connector
        connector_id = uuid.uuid4()
        connector = Connector(
            id=connector_id,
            org_id=org_id,
            created_by=user_id,
            name="Core Banking DB",
            connector_type_id=conn_type.id,
            config_encrypted=b"placeholder",
            status="active"
        )
        session.add(connector)
        
        # 4. Add "Bad" Data Events
        # Event 1: Unencrypted PII
        payload1 = {
            "table": "customers",
            "records": [
                {"name": "Alice", "bvn": "22233344455", "nin": "12345678901"}, # Raw BVN/NIN
                {"name": "Bob", "phone": "08012345678"}
            ],
            "encryption": {"at_rest": False} # Explicitly disabled
        }
        event1 = ConnectorEvent(
            connector_id=connector_id,
            org_id=org_id,
            event_type="data_update",
            payload_hash="hash1",
            payload_size=len(json.dumps(payload1)),
            payload_sample=json.dumps(payload1),
            processed=False
        )
        session.add(event1)
        
        # Event 2: Cross-border transfer to non-adequate country
        payload2 = {
            "data_locations": [
                {"service": "AWS S3", "country": "North Korea", "safeguards": False}
            ]
        }
        event2 = ConnectorEvent(
            connector_id=connector_id,
            org_id=org_id,
            event_type="infrastructure_update",
            payload_hash="hash2",
            payload_size=len(json.dumps(payload2)),
            payload_sample=json.dumps(payload2),
            processed=False
        )
        session.add(event2)
        
        await session.commit()
        print(f"Set up Org: {org.name}, Connector: {connector.name}")

        # 5. Run Audit
        audit_id = uuid.uuid4()
        audit = Audit(
            id=audit_id,
            org_id=org_id,
            initiated_by=user_id,
            name="Verify End-to-End Audit",
            audit_type=AuditType.FULL,
            status=AuditStatus.PENDING
        )
        session.add(audit)
        await session.commit()
        
        print(f"Triggering Audit {audit_id}...")
        completed_audit = await run_audit(str(audit_id), session)
        
        print(f"Audit Completed with Score: {completed_audit.compliance_score}%")
        print(f"Findings Count: {completed_audit.findings_count}")
        
        # 6. Generate Report (Placeholder storage key)
        completed_audit.report_storage_key = f"reports/{org_id}/{audit_id}.pdf"
        await session.commit()
        print(f"Report Storage Key Set: {completed_audit.report_storage_key}")

        # 7. Submit to NDPC
        print(f"Submitting to NDPC...")
        submission_result = await file_audit(str(audit_id), session)
        
        print(f"Submission Successful!")
        print(f"Receipt ID: {submission_result['receipt_id']}")
        
        # Verify final state
        await session.refresh(completed_audit)
        print(f"Final Audit Submitted State: {completed_audit.scope.get('submitted_to_ndpc')}")
        
    print("--- Verification Completed Successfully ---")

if __name__ == "__main__":
    asyncio.run(verify_flow())
