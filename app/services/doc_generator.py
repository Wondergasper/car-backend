"""
Document Generator - Creates compliance documents with AI fix suggestions.
Uses Jinja2 templates and generates structured content.
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
import json


@dataclass
class DocumentTemplate:
    template_id: str
    name: str
    description: str
    content_structure: Dict[str, Any]
    variables: List[str]


class DocumentGenerator:
    """
    Generates compliance documents (CAR reports, privacy policies, etc.)
    with AI-assisted fix suggestions.
    """
    
    # Predefined templates
    TEMPLATES = {
        "car_report": DocumentTemplate(
            template_id="car_report",
            name="Compliance Audit Report (CAR)",
            description="Official NDPC compliance report",
            content_structure={
                "title": "Compliance Audit Report",
                "sections": [
                    "executive_summary",
                    "compliance_score",
                    "findings_summary",
                    "detailed_findings",
                    "recommendations",
                    "appendix",
                ],
            },
            variables=["company_name", "audit_date", "score", "findings"],
        ),
        "privacy_policy": DocumentTemplate(
            template_id="privacy_policy",
            name="Privacy Policy Template",
            description="NDPA 2023 compliant privacy policy",
            content_structure={
                "title": "Privacy Policy",
                "sections": [
                    "introduction",
                    "data_collected",
                    "purpose_of_processing",
                    "data_subject_rights",
                    "contact_information",
                ],
            },
            variables=["company_name", "dpo_contact", "data_categories"],
        ),
        "ropa_record": DocumentTemplate(
            template_id="ropa_record",
            name="Record of Processing Activities (ROPA)",
            description="NDPA 2023 Article 29 compliance",
            content_structure={
                "title": "Record of Processing Activities",
                "sections": [
                    "controller_info",
                    "processing_purposes",
                    "data_categories",
                    "recipients",
                    "retention_periods",
                    "security_measures",
                ],
            },
            variables=["company_name", "processing_activities"],
        ),
    }
    
    def __init__(self):
        self.templates = self.TEMPLATES
    
    def generate_document(
        self,
        template_id: str,
        variables: Dict[str, Any],
        ai_suggestions: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Generate a document from template.
        
        Args:
            template_id: Template to use
            variables: Variables to fill into template
            ai_suggestions: AI-generated fix suggestions
            
        Returns:
            Structured document content (JSON)
        """
        template = self.templates.get(template_id)
        if not template:
            raise ValueError(f"Template '{template_id}' not found")
        
        # Build document structure
        document = {
            "template_id": template_id,
            "generated_at": datetime.utcnow().isoformat(),
            "variables": variables,
            "content": self._build_content(template, variables, ai_suggestions),
            "ai_suggestions": ai_suggestions or [],
        }
        
        return document
    
    def _build_content(
        self,
        template: DocumentTemplate,
        variables: Dict[str, Any],
        ai_suggestions: Optional[List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """Build document content from template."""
        content = {}
        
        if template.template_id == "car_report":
            content = self._build_car_report(variables, ai_suggestions)
        elif template.template_id == "privacy_policy":
            content = self._build_privacy_policy(variables)
        elif template.template_id == "ropa_record":
            content = self._build_ropa_record(variables)
        
        return content
    
    def _build_car_report(
        self,
        variables: Dict[str, Any],
        ai_suggestions: Optional[List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """Build CAR report content."""
        findings = variables.get("findings", [])
        score = variables.get("score", 0)
        
        # Generate severity breakdown
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            severity = finding.get("severity", "low")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        content = {
            "executive_summary": {
                "title": "Executive Summary",
                "content": (
                    f"This report presents the findings of the compliance audit "
                    f"conducted for {variables.get('company_name', 'the Organization')} "
                    f"against the Nigeria Data Protection Act 2023 (NDPA 2023). "
                    f"The audit was performed on {variables.get('audit_date', datetime.utcnow().strftime('%B %d, %Y'))}."
                ),
            },
            "compliance_score": {
                "title": "Compliance Score",
                "score": score,
                "grade": self._score_to_grade(score),
                "interpretation": self._score_interpretation(score),
            },
            "findings_summary": {
                "title": "Findings Summary",
                "total": len(findings),
                "by_severity": severity_counts,
            },
            "detailed_findings": {
                "title": "Detailed Findings",
                "findings": findings,
            },
            "recommendations": {
                "title": "Recommendations",
                "ai_suggestions": ai_suggestions or [],
            },
            "appendix": {
                "title": "Appendix",
                "applicable_rules": "NDPA 2023 Articles 25-47",
                "audit_methodology": "Automated compliance scanning with manual review",
            },
        }
        
        return content
    
    def _build_privacy_policy(self, variables: Dict[str, Any]) -> Dict[str, Any]:
        """Build privacy policy content."""
        return {
            "introduction": {
                "title": "Introduction",
                "content": (
                    f"{variables.get('company_name', 'We')} is committed to protecting "
                    f"the personal data of our users in accordance with the Nigeria "
                    f"Data Protection Act 2023 (NDPA 2023)."
                ),
            },
            "data_collected": {
                "title": "Data We Collect",
                "categories": variables.get("data_categories", []),
            },
            "purpose_of_processing": {
                "title": "Purpose of Processing",
                "purposes": variables.get("purposes", []),
            },
            "data_subject_rights": {
                "title": "Your Rights",
                "rights": [
                    "Right to access your personal data",
                    "Right to rectification of inaccurate data",
                    "Right to erasure (right to be forgotten)",
                    "Right to restrict processing",
                    "Right to data portability",
                    "Right to object to processing",
                ],
            },
            "contact_information": {
                "title": "Contact Us",
                "dpo_contact": variables.get("dpo_contact", "Not provided"),
            },
        }
    
    def _build_ropa_record(self, variables: Dict[str, Any]) -> Dict[str, Any]:
        """Build ROPA record content."""
        return {
            "controller_info": {
                "title": "Controller Information",
                "name": variables.get("company_name", ""),
            },
            "processing_purposes": {
                "title": "Purposes of Processing",
                "purposes": variables.get("processing_activities", []),
            },
            "data_categories": {
                "title": "Categories of Personal Data",
                "categories": [],
            },
            "recipients": {
                "title": "Recipients of Data",
                "recipients": [],
            },
            "retention_periods": {
                "title": "Data Retention Periods",
                "periods": [],
            },
            "security_measures": {
                "title": "Security Measures",
                "measures": [],
            },
        }
    
    def _score_to_grade(self, score: int) -> str:
        """Convert score to grade letter."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    def _score_interpretation(self, score: int) -> str:
        """Interpret the compliance score."""
        if score >= 90:
            return "Excellent compliance. Minimal improvements needed."
        elif score >= 80:
            return "Good compliance. Some areas for improvement identified."
        elif score >= 70:
            return "Moderate compliance. Several areas require attention."
        elif score >= 60:
            return "Below average compliance. Significant improvements needed."
        else:
            return "Poor compliance. Immediate action required to avoid regulatory risk."


# Example usage
if __name__ == "__main__":
    generator = DocumentGenerator()
    
    # Generate a CAR report
    document = generator.generate_document(
        template_id="car_report",
        variables={
            "company_name": "Sample Bank Ltd.",
            "audit_date": "April 15, 2026",
            "score": 87,
            "findings": [
                {
                    "rule_id": "NDPA-2023-Art25",
                    "severity": "critical",
                    "title": "Missing Consent Records",
                    "description": "No consent management system detected",
                    "recommendation": "Implement a consent management system",
                },
            ],
        },
        ai_suggestions=[
            {
                "finding": "NDPA-2023-Art25",
                "suggestion": "Deploy a consent management platform (CMP) that integrates with your web applications.",
                "priority": "high",
            },
        ],
    )
    
    print(json.dumps(document, indent=2))
