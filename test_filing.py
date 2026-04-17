import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import uuid
from datetime import datetime
import asyncio

# Mocking the models before importing the service to avoid DB issues
import sys
from types import ModuleType

# Create dummy modules
app_models = ModuleType('app.models.database')
app_models.Audit = MagicMock()
app_models.AuditStatus = MagicMock()
app_models.AuditStatus.COMPLETED = "completed"
sys.modules['app.models.database'] = app_models

app_storage = ModuleType('app.services.storage')
app_storage.object_storage = MagicMock()
sys.modules['app.services.storage'] = app_storage

# Now import the service logic (or just the class if we can)
from app.services.filing_service import FilingService

class TestFilingService(unittest.TestCase):
    def setUp(self):
        self.db = AsyncMock()
        self.service = FilingService(self.db)

    def test_submit_to_ndpc_success(self):
        # Setup mock audit
        audit_id = str(uuid.uuid4())
        mock_audit = MagicMock()
        mock_audit.id = audit_id
        mock_audit.org_id = uuid.uuid4()
        mock_audit.status = "completed"
        mock_audit.report_storage_key = "reports/test.pdf"
        mock_audit.scope = {}
        mock_audit.compliance_score = 85

        # Mock DB response
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_audit
        self.db.execute.return_value = mock_result

        # Run the async method
        loop = asyncio.get_event_loop()
        result = loop.run_until_complete(self.service.submit_to_ndpc(audit_id))

        # Assertions
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["receipt_id"].startswith("NDPC-CAR-"))
        self.assertTrue(mock_audit.scope["submitted_to_ndpc"])
        self.db.commit.assert_called()
        print(f"Test Passed! Receipt ID: {result['receipt_id']}")

if __name__ == "__main__":
    unittest.main()
