import hashlib
import io
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

import pdfplumber

from app.core.pii_scanner import PIIFinding, PIIScanner


def extract_document_payload(filename: str, content: bytes) -> Dict[str, Any]:
    lower_name = filename.lower()

    if lower_name.endswith(".json"):
        return json.loads(content.decode("utf-8"))

    if lower_name.endswith(".pdf"):
        with pdfplumber.open(io.BytesIO(content)) as pdf:
            extracted_text = "\n".join(page.extract_text() or "" for page in pdf.pages)
        return {"unstructured_text": extracted_text}

    return {"raw_content": content.decode("utf-8", errors="ignore")}


def build_document_analysis(
    filename: str,
    payload: Dict[str, Any],
    content: bytes,
    location_prefix: str,
) -> Dict[str, Any]:
    scanner = PIIScanner()
    findings = _scan_payload(scanner, payload, location_prefix)
    summary = scanner.get_summary(findings)
    preview = _build_preview(payload)
    recommendations = _build_recommendations(summary, findings)

    return {
        "status": "completed",
        "mode": "instant",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "file_name": filename,
        "payload_hash": hashlib.sha256(content).hexdigest(),
        "summary": {
            "headline": _build_headline(summary),
            "document_preview": preview[:600],
            "total_findings": summary["total_findings"],
            "by_category": summary["by_category"],
            "by_risk_level": summary["by_risk_level"],
            "high_risk_locations": summary["high_risk_locations"][:10],
            "top_findings": _serialize_findings(findings[:10]),
            "recommendations": recommendations,
        },
    }


def _scan_payload(
    scanner: PIIScanner, payload: Dict[str, Any], location_prefix: str
) -> List[PIIFinding]:
    if "unstructured_text" in payload and isinstance(payload["unstructured_text"], str):
        return scanner.scan_text(payload["unstructured_text"], location=location_prefix)

    if "raw_content" in payload and isinstance(payload["raw_content"], str):
        return scanner.scan_text(payload["raw_content"], location=location_prefix)

    findings: List[PIIFinding] = []

    def visit(value: Any, location: str) -> None:
        if isinstance(value, str):
            findings.extend(scanner.scan_text(value, location=location))
            return

        if isinstance(value, dict):
            for key, nested in value.items():
                visit(nested, f"{location}/{key}")
            return

        if isinstance(value, list):
            for index, nested in enumerate(value):
                visit(nested, f"{location}[{index}]")

    visit(payload, location_prefix)
    return findings


def _build_preview(payload: Dict[str, Any]) -> str:
    if "unstructured_text" in payload:
        return str(payload["unstructured_text"]).strip()

    if "raw_content" in payload:
        return str(payload["raw_content"]).strip()

    return json.dumps(payload, default=str)


def _build_headline(summary: Dict[str, Any]) -> str:
    total = summary["total_findings"]
    critical = summary["by_risk_level"].get("critical", 0)
    high = summary["by_risk_level"].get("high", 0)

    if total == 0:
        return "No obvious PII was detected in the uploaded document."
    if critical > 0:
        return f"Critical identifiers were detected in this document ({critical} critical findings)."
    if high > 0:
        return f"Sensitive data indicators were found in this document ({high} high-risk findings)."
    return f"Potential personal data was detected in this document ({total} findings)."


def _serialize_findings(findings: List[PIIFinding]) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    for finding in findings:
        items.append(
            {
                "category": finding.category.value,
                "value": finding.value,
                "location": finding.location,
                "risk_level": finding.risk_level,
                "description": finding.description,
                "confidence": finding.confidence,
            }
        )
    return items


def _build_recommendations(
    summary: Dict[str, Any], findings: List[PIIFinding]
) -> List[str]:
    recommendations: List[str] = []

    if summary["total_findings"] == 0:
        recommendations.append("Run a full audit if you want this upload checked against compliance rules as well.")
        return recommendations

    if summary["by_risk_level"].get("critical", 0) > 0:
        recommendations.append("Review and redact critical identity numbers before wider sharing or retention.")

    if summary["by_category"].get("email", 0) > 0 or summary["by_category"].get("phone", 0) > 0:
        recommendations.append("Confirm you have a lawful basis and access controls for contact data in this document.")

    if any(f.location.endswith("raw") or "unstructured" in f.location for f in findings):
        recommendations.append("Consider converting this document into structured records before downstream processing.")

    recommendations.append("Start a full audit to evaluate this upload against NDPA and GAID control requirements.")
    return recommendations[:4]
