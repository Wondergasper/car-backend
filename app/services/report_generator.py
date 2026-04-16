# Report Generator Service
# Generates CAR PDF reports based on audit findings

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
from datetime import datetime
from typing import List, Dict, Any
import os
from app.services.doc_generator import DocumentGenerator


class CARPDFGenerator:
    """Generates Compliance Audit Report (CAR) PDF from structured content."""

    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._create_custom_styles()

    def _create_custom_styles(self):
        self.styles.add(ParagraphStyle(
            name="ReportTitle",
            parent=self.styles["Title"],
            fontSize=24,
            spaceAfter=10,
            textColor=HexColor("#1e40af"),
        ))
        self.styles.add(ParagraphStyle(
            name="SectionHeader",
            parent=self.styles["Heading1"],
            fontSize=16,
            spaceBefore=20,
            spaceAfter=10,
            textColor=HexColor("#1e3a8a"),
        ))
        self.styles.add(ParagraphStyle(
            name="SubSectionHeader",
            parent=self.styles["Heading2"],
            fontSize=12,
            spaceBefore=10,
            spaceAfter=5,
            textColor=HexColor("#3b82f6"),
        ))
        self.styles.add(ParagraphStyle(
            name="BodyText2",
            parent=self.styles["BodyText"],
            fontSize=10,
            spaceAfter=6,
        ))

    def generate_from_document(self, document: Dict[str, Any], output_path: str) -> str:
        """
        Generate PDF from a structured document (from DocumentGenerator).
        """
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72,
        )

        story = []
        content = document.get("content", {})
        variables = document.get("variables", {})
        
        # Title Page
        story.append(Paragraph(content.get("executive_summary", {}).get("title", "Compliance Audit Report"), self.styles["ReportTitle"]))
        story.append(Spacer(1, 20))
        story.append(Paragraph(f"<b>Company:</b> {variables.get('company_name', 'N/A')}", self.styles["Normal"]))
        story.append(Paragraph(f"<b>Audit Date:</b> {variables.get('audit_date', 'N/A')}", self.styles["Normal"]))
        story.append(Spacer(1, 30))

        # Compliance Score
        score_section = content.get("compliance_score", {})
        score = score_section.get("score", 0)
        grade = score_section.get("grade", "N/A")
        
        story.append(Paragraph("Compliance Score", self.styles["SectionHeader"]))
        story.append(Paragraph(
            f'<b>Score:</b> {score}% <b>Grade:</b> {grade}',
            self.styles["Normal"],
        ))
        story.append(Paragraph(score_section.get("interpretation", ""), self.styles["Normal"]))
        story.append(Spacer(1, 20))

        # Findings Summary
        findings_section = content.get("findings_summary", {})
        story.append(Paragraph("Findings Summary", self.styles["SectionHeader"]))
        
        by_severity = findings_section.get("by_severity", {})
        summary_data = [
            ["Severity", "Count"],
            ["Critical", str(by_severity.get("critical", 0))],
            ["High", str(by_severity.get("high", 0))],
            ["Medium", str(by_severity.get("medium", 0))],
            ["Low", str(by_severity.get("low", 0))],
            ["Total", str(findings_section.get("total", 0))],
        ]
        
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1e40af")),
            ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#ffffff")),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 12),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -2), HexColor("#f3f4f6")),
            ("GRID", (0, 0), (-1, -1), 1, HexColor("#d1d5db")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#ffffff"), HexColor("#f9fafb")]),
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))

        # Detailed Findings
        detailed = content.get("detailed_findings", {})
        findings = detailed.get("findings", [])
        
        if findings:
            story.append(Paragraph("Detailed Findings", self.styles["SectionHeader"]))
            
            for i, finding in enumerate(findings, 1):
                story.append(Paragraph(f"Finding #{i}: {finding.get('title', 'N/A')}", self.styles["SubSectionHeader"]))
                story.append(Paragraph(f"<b>Rule:</b> {finding.get('rule_id', 'N/A')}", self.styles["BodyText2"]))
                story.append(Paragraph(f"<b>Severity:</b> {finding.get('severity', 'N/A').title()}", self.styles["BodyText2"]))
                story.append(Paragraph(f"<b>Description:</b> {finding.get('description', '')}", self.styles["BodyText2"]))
                story.append(Paragraph(f"<b>Recommendation:</b> {finding.get('recommendation', '')}", self.styles["BodyText2"]))
                story.append(Spacer(1, 10))

        # AI Suggestions
        ai_section = content.get("recommendations", {})
        ai_suggestions = ai_section.get("ai_suggestions", [])
        
        if ai_suggestions:
            story.append(Paragraph("AI-Generated Fix Suggestions", self.styles["SectionHeader"]))
            
            for i, suggestion in enumerate(ai_suggestions, 1):
                story.append(Paragraph(f"Suggestion #{i}", self.styles["SubSectionHeader"]))
                story.append(Paragraph(f"<b>Finding:</b> {suggestion.get('finding', 'N/A')}", self.styles["BodyText2"]))
                story.append(Paragraph(f"<b>Suggestion:</b> {suggestion.get('suggestion', '')}", self.styles["BodyText2"]))
                story.append(Paragraph(f"<b>Priority:</b> {suggestion.get('priority', 'N/A')}", self.styles["BodyText2"]))
                story.append(Spacer(1, 10))

        # Footer
        story.append(Spacer(1, 30))
        story.append(Paragraph(
            f"Report generated by CAR-Bot on {datetime.now().strftime('%B %d, %Y')}",
            self.styles["Normal"],
        ))
        story.append(Paragraph(
            "This report is confidential and intended solely for the use of the named recipient.",
            self.styles["Normal"],
        ))

        # Build PDF
        doc.build(story)
        return output_path


# Backwards compatibility
CARReportGenerator = CARPDFGenerator

