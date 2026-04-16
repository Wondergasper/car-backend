"""
WhatsApp Business API Connector — Monitors WhatsApp Business messages for PII exposure.
Connects to Meta's WhatsApp Cloud API, retrieves recent messages,
and scans for Nigerian personal identifiers being shared in customer conversations.
"""
import json
import logging
import requests
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from app.core.pii_scanner import PIIScanner

logger = logging.getLogger(__name__)


class WhatsAppConnector:
    """
    Connects to WhatsApp Business API (Meta Cloud API),
    retrieves messages, and scans for PII exposure.
    """

    GRAPH_API_BASE = "https://graph.facebook.com/v18.0"

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.access_token = config.get("access_token", "")
        self.phone_number_id = config.get("phone_number_id", "")
        self.business_account_id = config.get("business_account_id", "")
        self.webhook_verify_token = config.get("webhook_verify_token", "")
        self.scanner = PIIScanner()

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

    def connect(self) -> bool:
        """Test connection to WhatsApp Business API."""
        try:
            url = f"{self.GRAPH_API_BASE}/{self.phone_number_id}"
            response = requests.get(url, headers=self._headers(), timeout=10)

            if response.status_code == 200:
                data = response.json()
                logger.info(f"Connected to WhatsApp Business: {data.get('verified_name', 'Unknown')}")
                return True
            else:
                logger.error(f"WhatsApp API error: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            logger.error(f"WhatsApp connection failed: {e}")
            return False

    def get_recent_messages(self, hours: int = 24, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Retrieve recent messages from the WhatsApp Business API.
        Uses the conversations endpoint to get message history.
        """
        messages = []

        try:
            # Get conversations
            url = f"{self.GRAPH_API_BASE}/{self.phone_number_id}/conversations"
            params = {
                "fields": "id,last_contact_timestamp,contact_profile,pricing",
                "limit": limit,
            }

            response = requests.get(url, headers=self._headers(), params=params, timeout=15)

            if response.status_code != 200:
                logger.error(f"Failed to get conversations: {response.text}")
                return messages

            conversations = response.json().get("data", [])

            # Get messages from each conversation
            for conv in conversations:
                conv_id = conv.get("id")
                if not conv_id:
                    continue

                msg_url = f"{self.GRAPH_API_BASE}/{self.phone_number_id}/messages"
                msg_params = {
                    "fields": "id,from,timestamp,type,text",
                    "limit": 50,
                }

                msg_response = requests.get(msg_url, headers=self._headers(), params=msg_params, timeout=15)

                if msg_response.status_code == 200:
                    msg_data = msg_response.json().get("data", [])
                    messages.extend(msg_data)

        except Exception as e:
            logger.error(f"Failed to retrieve messages: {e}")

        logger.info(f"Retrieved {len(messages)} WhatsApp messages")
        return messages

    def extract_text_from_message(self, message: Dict[str, Any]) -> str:
        """Extract text content from a WhatsApp message."""
        msg_type = message.get("type", "")

        if msg_type == "text":
            text_data = message.get("text", {})
            return text_data.get("body", "")
        elif msg_type == "button":
            btn_data = message.get("button", {})
            return btn_data.get("text", "")
        elif msg_type == "interactive":
            interactive = message.get("interactive", {})
            if "text_reply" in interactive:
                return interactive["text_reply"].get("title", "")
        elif msg_type == "template":
            template = message.get("template", {})
            return template.get("name", "")

        return ""

    def scan_messages_for_pii(self, messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Scan all retrieved messages for PII."""
        all_findings = []
        flagged_messages = []

        for msg in messages:
            text = self.extract_text_from_message(msg)
            if not text:
                continue

            # Scan for PII
            findings = self.scanner.scan_text(text, location=f"whatsapp/msg_{msg.get('id', 'unknown')}")

            if findings:
                flagged_messages.append({
                    "message_id": msg.get("id"),
                    "from": msg.get("from"),
                    "timestamp": msg.get("timestamp"),
                    "message_type": msg.get("type"),
                    "text_preview": text[:100] + "..." if len(text) > 100 else text,
                    "pii_count": len(findings),
                    "findings": [
                        {
                            "category": f.category.value if hasattr(f.category, 'value') else str(f.category),
                            "value": f.value,
                            "confidence": f.confidence,
                            "risk_level": f.risk_level,
                        }
                        for f in findings
                    ],
                })
                all_findings.extend([
                    {
                        "category": f.category.value if hasattr(f.category, 'value') else str(f.category),
                        "value": f.value,
                        "location": f.location,
                        "confidence": f.confidence,
                        "risk_level": f.risk_level,
                    }
                    for f in findings
                ])

        return {
            "total_messages_scanned": len(messages),
            "flagged_messages": flagged_messages,
            "pii_findings": all_findings,
            "pii_finding_count": len(all_findings),
        }

    def build_audit_payload(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Build structured audit payload for the rules engine."""
        flagged = scan_results.get("flagged_messages", [])
        findings = scan_results.get("pii_findings", [])

        # Aggregate by category
        pii_by_category = {}
        for f in findings:
            cat = f.get("category", "unknown")
            pii_by_category[cat] = pii_by_category.get(cat, 0) + 1

        return {
            "connector_type": "whatsapp_business",
            "phone_number_id": self.phone_number_id,
            "business_account_id": self.business_account_id,
            "scan_results": {
                "total_messages_scanned": scan_results.get("total_messages_scanned", 0),
                "flagged_messages_count": len(flagged),
                "total_pii_instances": scan_results.get("pii_finding_count", 0),
                "pii_by_category": pii_by_category,
            },
            "flagged_messages_sample": flagged[:10],  # Only include first 10
            "pii_findings": findings,
            "pii_finding_count": len(findings),
            "encryption": {
                "at_rest": False,  # WhatsApp Business API may not encrypt stored messages
                "in_transit": True,  # End-to-end encryption for messages
            },
            "consent_records": [],  # WhatsApp doesn't track consent
            "audit_logging": True,  # Meta provides audit logs
            "scanned_at": datetime.utcnow().isoformat(),
            "status": "completed",
        }

    def run_full_audit(self) -> Dict[str, Any]:
        """
        Run the complete audit pipeline for WhatsApp Business:
        1. Connect to WhatsApp API
        2. Retrieve recent messages
        3. Scan messages for PII
        4. Build structured audit payload
        """
        logger.info(f"Starting WhatsApp Business audit for phone: {self.phone_number_id}")

        # Step 1: Test connection
        if not self.connect():
            return {
                "status": "failed",
                "error": "Could not connect to WhatsApp Business API",
                "connector_type": "whatsapp_business",
                "phone_number_id": self.phone_number_id,
            }

        # Step 2: Get recent messages
        messages = self.get_recent_messages(hours=24, limit=100)

        # Step 3: Scan for PII
        scan_results = self.scan_messages_for_pii(messages)

        # Step 4: Build payload
        payload = self.build_audit_payload(scan_results)

        logger.info(
            f"WhatsApp audit completed: "
            f"{scan_results['total_messages_scanned']} messages scanned, "
            f"{len(scan_results['flagged_messages'])} flagged, "
            f"{scan_results['pii_finding_count']} PII instances"
        )
        return payload

    def setup_webhook(self, webhook_url: str, verify_token: str) -> bool:
        """
        Configure a webhook for real-time message monitoring.
        This is optional — the connector can also poll for messages.
        """
        try:
            url = f"{self.GRAPH_API_BASE}/{self.phone_number_id}/subscribed_apps"
            payload = {
                "webhook_url": webhook_url,
                "webhook_verify_token": verify_token,
                "subscribed_fields": ["messages", "message_deliveries", "message_reads"],
            }

            response = requests.post(url, headers=self._headers(), json=payload, timeout=15)

            if response.status_code == 200:
                logger.info(f"Webhook configured for WhatsApp: {webhook_url}")
                return True
            else:
                logger.error(f"Webhook setup failed: {response.text}")
                return False

        except Exception as e:
            logger.error(f"Webhook setup error: {e}")
            return False
