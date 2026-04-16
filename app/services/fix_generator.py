"""
AI Fix Generation Service.

For every compliance finding, generates a pre-drafted remediation document.
This is the "Remediation Studio" backend — the differentiator from simple audit tools.
Clients don't just get a problem list, they get a solution package.
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime

from app.core.rules_engine import ComplianceFinding


@dataclass
class RemediationDocument:
    finding_rule_id: str
    finding_title: str
    finding_description: str
    finding_severity: str
    remediation_type: str
    document_title: str
    document_content: str
    implementation_steps: List[str]
    estimated_effort: str  # "quick", "moderate", "extensive"
    template_used: str
    generated_at: str


# Remediation templates for each rule
REMEDIATION_TEMPLATES = {
    "consent_management": {
        "document_title": "Consent Management Framework",
        "remediation_type": "Policy + Implementation",
        "estimated_effort": "moderate",
        "implementation_steps": [
            "Deploy a Consent Management Platform (CMP) such as OneTrust, Cookiebot, or Usercentrics",
            "Configure consent forms for each data collection point (web forms, mobile apps, paper forms)",
            "Implement explicit consent checkboxes with clear purpose descriptions",
            "Set up consent logging: timestamp, IP address, consent scope, user identifier",
            "Create a consent withdrawal mechanism (easy opt-out process)",
            "Document consent records in a secure, auditable database",
            "Train staff on consent collection procedures",
            "Test the end-to-end consent flow with sample data subjects",
        ],
        "document_content": """
CONSENT MANAGEMENT FRAMEWORK

1. PURPOSE
This framework establishes how {company_name} obtains, records, and manages
consent from data subjects before collecting or processing their personal data,
in compliance with NDPA 2023 Article 25.

2. SCOPE
Applies to all channels where personal data is collected:
- Website and mobile applications
- Paper forms and contracts
- In-person data collection
- Third-party data sources

3. CONSENT REQUIREMENTS
All consent must be:
- Freely given (no coercion or negative consequences for refusal)
- Specific (clear purpose stated for each consent)
- Informed (data subject understands what they're consenting to)
- Unambiguous (affirmative action — no pre-ticked boxes)
- Documented (timestamp, method, scope recorded)

4. CONSENT COLLECTION METHOD
Consent shall be obtained through:
{consent_method}

5. CONSENT RECORDS
For each consent, the following must be recorded:
- Data subject identifier (name, account ID, etc.)
- Date and time of consent
- Method of consent (online form, paper, verbal)
- Specific purpose(s) consented to
- Version of privacy notice presented
- IP address (for digital consent)

6. CONSENT WITHDRAWAL
Data subjects may withdraw consent at any time through:
- Account settings (for registered users)
- Email request to DPO at {dpo_email}
- Written request to company address

Upon withdrawal, processing based on that consent must stop immediately.

7. REVIEW AND AUDIT
Consent records shall be audited quarterly to ensure:
- Completeness (all data subjects have valid consent)
- Accuracy (consent scope matches actual processing)
- Freshness (consent has not expired or been withdrawn)
""",
    },
    "data_minimization": {
        "document_title": "Data Minimization Assessment",
        "remediation_type": "Assessment + Policy",
        "estimated_effort": "moderate",
        "implementation_steps": [
            "Inventory all personal data fields currently collected",
            "For each field, document: purpose, legal basis, necessity",
            "Identify fields without a documented lawful basis",
            "Remove unnecessary fields from collection forms",
            "Implement field-level access controls to limit internal exposure",
            "Set up automated monitoring for new fields added to systems",
            "Document the data minimization policy and communicate to all teams",
        ],
        "document_content": """
DATA MINIMIZATION ASSESSMENT AND POLICY

1. PURPOSE
This document ensures that {company_name} collects only personal data that
is adequate, relevant, and limited to what is necessary for the stated
processing purposes, in compliance with NDPA 2023 Article 27.

2. CURRENT STATE
Total personal data fields collected: {field_count}
Fields assessed as excessive: {excessive_fields}

3. DATA FIELD INVENTORY
Each personal data field has been assessed against:
- Is it necessary for the stated purpose?
- Is there a lawful basis for collection?
- Can the purpose be achieved with less data?
- Can the data be anonymized or pseudonymized?

4. REMEDIATION PLAN
The following fields will be removed or made optional:
{removal_list}

5. ONGOING COMPLIANCE
- New fields require approval from the DPO before collection
- Quarterly review of all collected fields
- Automated alerts when new fields are added to databases
""",
    },
    "access_control": {
        "document_title": "Access Control Policy (RBAC)",
        "remediation_type": "Policy + Implementation",
        "estimated_effort": "moderate",
        "implementation_steps": [
            "Define user roles: Admin, Analyst, Viewer, Data Subject",
            "Map each role to specific data permissions (read, write, delete)",
            "Implement role-based access at database level (GRANT/REVOKE)",
            "Implement role-based access at application level (middleware)",
            "Set up access request workflow with approval process",
            "Enable access logging for all data access events",
            "Schedule quarterly access reviews",
            "Document and communicate the policy to all staff",
        ],
        "document_content": """
ACCESS CONTROL POLICY — ROLE-BASED ACCESS CONTROL (RBAC)

1. PURPOSE
This policy restricts access to personal data based on job function and
the principle of least privilege, in compliance with NDPA 2023 Article 31.

2. ROLES DEFINED
- Admin: Full access to all systems and data (limited to IT team)
- Analyst: Read access to personal data for analysis purposes
- Viewer: Read-only access to aggregated, anonymized data
- DPO: Full access for compliance monitoring and audit purposes

3. ACCESS PROVISIONING
- Access is granted based on job role and business need
- All access requests must be approved by the data owner
- Temporary access is time-limited and automatically revoked
- Access is reviewed quarterly and adjusted as needed

4. ACCESS MONITORING
- All access attempts (successful and failed) are logged
- Alerts are triggered for unusual access patterns
- Access logs are retained for 12 months minimum

5. VIOLATIONS
Unauthorized access is a policy violation subject to disciplinary action.
""",
    },
    "encryption_at_rest": {
        "document_title": "Data Encryption at Rest Implementation Guide",
        "remediation_type": "Technical Implementation",
        "estimated_effort": "extensive",
        "implementation_steps": [
            "Enable Transparent Data Encryption (TDE) on all database servers",
            "Enable server-side encryption on all file storage (S3, Azure Blob, etc.)",
            "Enable encryption on all backup files and media",
            "Implement application-level encryption for highly sensitive fields (BVN, NIN)",
            "Rotate encryption keys according to organizational policy",
            "Document encryption standards and key management procedures",
            "Test encryption by attempting to read encrypted data without keys",
        ],
        "document_content": """
DATA ENCRYPTION AT REST — IMPLEMENTATION GUIDE

1. PURPOSE
This guide ensures all personal data stored by {company_name} is encrypted
using industry-standard encryption (AES-256), per NDPA 2023 Article 38.

2. ENCRYPTION STANDARDS
- Algorithm: AES-256 (Advanced Encryption Standard)
- Key Management: NIST SP 800-57 compliant
- Key Rotation: Annual rotation, or immediately upon compromise

3. DATABASE ENCRYPTION
- PostgreSQL: Enable pgcrypto module or use pg_tde
- MySQL: Enable InnoDB tablespace encryption
- MSSQL: Enable Transparent Data Encryption (TDE)
- MongoDB: Enable Encrypted Storage (WiredTiger)

4. FILE STORAGE ENCRYPTION
- AWS S3: Enable SSE-S3 or SSE-KMS
- Azure Blob: Enable Azure Storage Service Encryption
- On-premise: Use BitLocker (Windows) or LUKS (Linux)

5. BACKUP ENCRYPTION
- All backup files must be encrypted before storage
- Backup encryption keys must be stored separately from backups
- Test backup restoration regularly to verify key availability
""",
    },
    "mfa": {
        "document_title": "Multi-Factor Authentication Policy",
        "remediation_type": "Policy + Implementation",
        "estimated_effort": "quick",
        "implementation_steps": [
            "Enable MFA on all systems that process personal data",
            "Choose MFA method: TOTP (Google Authenticator), SMS, or hardware keys",
            "Enroll all staff with system access",
            "Set up backup access methods for lost devices",
            "Document the MFA policy and communicate to all staff",
            "Test MFA by attempting login without second factor",
        ],
        "document_content": """
MULTI-FACTOR AUTHENTICATION (MFA) POLICY

1. PURPOSE
This policy ensures strong authentication on all systems processing
personal data, per NDPA 2023 Article 32.

2. REQUIREMENTS
All staff with access to systems containing personal data must use MFA.

3. ACCEPTABLE MFA METHODS
- TOTP (Time-based One-Time Password): Google Authenticator, Authy, Microsoft Authenticator
- Hardware Security Keys: YubiKey, Google Titan
- SMS-based OTP (secondary option, not preferred due to SIM-swap risks)

4. ENROLLMENT
- All new staff must enroll in MFA before receiving system access
- Existing staff must enroll within 30 days of this policy taking effect
- Lost device recovery procedure: contact IT for backup access code

5. EXEMPTIONS
No exemptions without written approval from the CISO and DPO.
""",
    },
    "breach_notification": {
        "document_title": "Data Breach Response Plan",
        "remediation_type": "Policy + Procedure",
        "estimated_effort": "moderate",
        "implementation_steps": [
            "Create a breach response playbook with severity classification",
            "Assign breach response roles (Incident Commander, Legal, Communications, IT)",
            "Set up breach detection monitoring (log analysis, anomaly detection)",
            "Create NDPC notification template (72-hour requirement)",
            "Create data subject notification template",
            "Run a tabletop breach exercise within 60 days",
            "Document breach response procedures and train all staff",
        ],
        "document_content": """
DATA BREACH RESPONSE PLAN

1. PURPOSE
This plan ensures {company_name} can detect, respond to, and report
data breaches within the NDPA 2023 Article 42 requirement of 72 hours.

2. BREACH DEFINITION
A breach is any unauthorized access, loss, destruction, or disclosure
of personal data.

3. BREACH SEVERITY CLASSIFICATION
- Critical: Sensitive data (BVN, NIN, financial) exposed, or >1000 records
- High: Personal data exposed, <1000 records
- Medium: Limited exposure, minimal risk to data subjects
- Low: No personal data affected, policy violation only

4. RESPONSE TEAM
- Incident Commander: {incident_commander}
- IT Lead: {it_lead}
- Legal Counsel: {legal_counsel}
- DPO: {dpo_name} ({dpo_email})
- Communications Lead: {comms_lead}

5. 72-HOUR NOTIFICATION TIMELINE
Hour 0-4: Detect and classify the breach
Hour 4-8: Notify response team, begin containment
Hour 8-24: Assess impact, prepare NDPC notification
Hour 24-48: Submit NDPC notification, prepare data subject notices
Hour 48-72: Notify affected data subjects, publish public statement if needed

6. NDPC NOTIFICATION MUST INCLUDE:
- Nature of the breach
- Categories and approximate number of data subjects affected
- Likely consequences of the breach
- Measures taken or proposed to address the breach
- Contact details of the DPO
""",
    },
    "audit_logging": {
        "document_title": "Audit Logging Implementation Guide",
        "remediation_type": "Technical Implementation",
        "estimated_effort": "moderate",
        "implementation_steps": [
            "Enable database audit logging (pgAudit for PostgreSQL, etc.)",
            "Enable application-level event logging for all CRUD operations",
            "Configure log retention for minimum 12 months",
            "Set up log monitoring and alerting for suspicious patterns",
            "Ensure logs are tamper-evident (append-only, hash-chained)",
            "Document the audit logging standard and communicate to IT team",
        ],
        "document_content": """
AUDIT LOGGING IMPLEMENTATION GUIDE

1. PURPOSE
This guide establishes comprehensive audit logging for all access to
and processing of personal data, per NDPA 2023 Article 40.

2. WHAT TO LOG
- Who accessed personal data (user ID)
- When (timestamp with timezone)
- From where (IP address, device)
- What action was taken (read, create, update, delete)
- Which records were affected (record IDs)
- The result (success, failure, denied)

3. WHERE TO STORE LOGS
- Centralized log management system (ELK Stack, Splunk, CloudWatch)
- Logs must be append-only and tamper-evident
- Logs must be encrypted at rest
- Access to logs restricted to IT security team

4. LOG RETENTION
- Minimum 12 months retention
- Archived logs stored for 3 years minimum
- Logs must be searchable and exportable for audits

5. MONITORING AND ALERTING
- Alert on: unusual access patterns, bulk data exports, access after hours
- Review logs weekly for anomalies
- Quarterly comprehensive log audit
""",
    },
    "dsar": {
        "document_title": "Data Subject Access Request (DSAR) Procedure",
        "remediation_type": "Procedure + Template",
        "estimated_effort": "moderate",
        "implementation_steps": [
            "Create a DSAR intake channel (dedicated email, web form, or portal)",
            "Implement identity verification process for requesters",
            "Build data extraction procedures for each system holding personal data",
            "Create a response template with all required information",
            "Set up tracking system for 30-day SLA compliance",
            "Train staff on DSAR handling procedures",
            "Test the DSAR process with a simulated request",
        ],
        "document_content": """
DATA SUBJECT ACCESS REQUEST (DSAR) PROCEDURE

1. PURPOSE
This procedure enables data subjects to access their personal data
held by {company_name}, per NDPA 2023 Article 45.

2. INTAKE CHANNELS
Data subjects may submit DSARs through:
- Email: {dpo_email}
- Web form: {dsar_form_url}
- Written request to: {company_address}

3. IDENTITY VERIFICATION
Before processing a DSAR, verify the requester's identity:
- For registered users: verify through account credentials
- For non-registered requesters: request government-issued ID
- For representatives: request authorization letter from data subject

4. 30-DAY RESPONSE SLA
- Day 0: Receive and acknowledge the request
- Day 1-5: Verify identity and scope the request
- Day 5-20: Extract data from all relevant systems
- Day 20-25: Review and redact (third-party data, privileged information)
- Day 25-30: Deliver response to data subject

5. RESPONSE CONTENT
The response must include:
- Confirmation that their data is being processed
- The purposes of processing
- Categories of personal data held
- Recipients or categories of recipients
- Retention period or criteria for determining it
- Their rights (rectification, erasure, restriction, portability)
- The source of the data (if not collected directly)
- Existence of automated decision-making (if applicable)

6. TRACKING
All DSARs must be logged with:
- Request date, requester identity, verification method
- Systems searched, records found
- Response date, delivery method
- Any extensions requested and reasons
""",
    },
    "data_retention": {
        "document_title": "Data Retention Schedule",
        "remediation_type": "Policy + Implementation",
        "estimated_effort": "moderate",
        "implementation_steps": [
            "Map all data categories to specific retention periods",
            "Document the legal basis for each retention period",
            "Implement automated deletion jobs for expired data",
            "Set up alerts when data approaches retention expiry",
            "Create exception process for data under legal hold",
            "Document the retention policy and communicate to all teams",
            "Test deletion by verifying data is irretrievable after deletion",
        ],
        "document_content": """
DATA RETENTION SCHEDULE AND POLICY

1. PURPOSE
This schedule defines how long {company_name} retains each category
of personal data, per NDPA 2023 Article 35.

2. RETENTION PERIODS
- Customer account data: 5 years after last interaction or account closure
- Employee records: 7 years after employment ends
- Financial records: 7 years (per tax law requirements)
- Marketing consent records: 3 years after consent withdrawal
- Audit logs: 3 years minimum
- Breach investigation records: 5 years after resolution

3. DELETION PROCEDURES
When data reaches its retention expiry:
- Automated deletion job runs on schedule (weekly)
- Deletion is cryptographic (secure erase, not just flag)
- Deletion is logged with timestamp and record count
- Deletion is verified by attempting to recover deleted data

4. EXCEPTIONS
Data may be retained beyond normal periods if:
- Under legal hold (court order, regulatory investigation)
- Required for ongoing legal proceedings
- Data subject has requested restriction of processing

5. REVIEW
This retention schedule is reviewed annually and updated as needed.
""",
    },
    "cross_border": {
        "document_title": "Cross-Border Data Transfer Assessment",
        "remediation_type": "Assessment + Remediation",
        "estimated_effort": "extensive",
        "implementation_steps": [
            "Map all data storage locations (databases, cloud regions, backups)",
            "Identify transfers to countries without adequacy status",
            "Implement Standard Contractual Clauses (SCCs) with each processor",
            "Document explicit consent for cross-border transfers in privacy notice",
            "Consider migrating data to Nigeria or adequacy countries",
            "Create a cross-border transfer register with safeguards documented",
            "Review SCCs annually and update as regulations change",
        ],
        "document_content": """
CROSS-BORDER DATA TRANSFER ASSESSMENT

1. PURPOSE
This assessment ensures personal data transfers outside Nigeria comply
with NDPA 2023 Article 48 requirements for adequate protection or safeguards.

2. CURRENT DATA LOCATIONS
{data_locations}

3. TRANSFERS WITHOUT ADEQUACY
The following transfers are to countries without recognized adequacy status
and without documented safeguards:
{non_adequate_locations}

4. REMEDIATION OPTIONS
Option A — Migrate Data: Move data storage to Nigeria or an adequacy country
Option B — SCCs: Implement Standard Contractual Clauses with each processor
Option C — Consent: Obtain explicit consent from data subjects for the transfer
Option D — BCRs: Apply Binding Corporate Rules (for multinational organizations)

5. RECOMMENDED ACTION
{recommended_action}

6. ONGOING COMPLIANCE
- Maintain a register of all cross-border transfers
- Review adequacy status of countries annually
- Update SCCs when new templates are issued
- Document consent updates in privacy notice
""",
    },
    "purpose_limitation": {
        "document_title": "Purpose Limitation Register",
        "remediation_type": "Documentation",
        "estimated_effort": "quick",
        "implementation_steps": [
            "Create a processing register documenting each processing purpose",
            "For each purpose, document: data categories, legal basis, retention period",
            "Publish processing purposes in the privacy notice",
            "Review quarterly to ensure no purpose creep",
            "Train staff on purpose limitation requirements",
        ],
        "document_content": """
PURPOSE LIMITATION REGISTER

1. PURPOSE
This register documents each specific purpose for which {company_name}
processes personal data, per NDPA 2023 Article 28.

2. PROCESSING PURPOSES
{purpose_list}

3. FOR EACH PURPOSE WE DOCUMENT:
- The specific and explicit purpose
- The categories of personal data involved
- The legal basis for processing
- The retention period
- Who has access to the data
- Whether data is transferred to third parties

4. NO PURPOSE CREEP
Personal data collected for one purpose must not be processed for a
different, incompatible purpose without obtaining new consent.
""",
    },
    "authorization_audit": {
        "document_title": "Authorization Audit Trail Policy",
        "remediation_type": "Policy",
        "estimated_effort": "quick",
        "implementation_steps": [
            "Enable logging of all authorization decisions (grant/deny)",
            "Log the user, resource, action, and decision for each authorization event",
            "Store logs in a tamper-evident system",
            "Review authorization logs monthly for anomalies",
        ],
        "document_content": """
AUTHORIZATION AUDIT TRAIL POLICY

1. PURPOSE
This policy ensures all authorization decisions are logged for accountability,
per NDPA 2023 Article 33.

2. WHAT IS LOGGED
- User requesting access
- Resource being accessed
- Action requested (read, write, delete, admin)
- Decision (granted, denied)
- Timestamp and IP address
- Policy or role that determined the decision

3. LOG STORAGE
- Logs stored in append-only, tamper-evident system
- Retained for minimum 12 months
- Access restricted to IT security team
""",
    },
    "deletion_procedures": {
        "document_title": "Secure Data Deletion Procedures",
        "remediation_type": "Procedure",
        "estimated_effort": "moderate",
        "implementation_steps": [
            "Define secure deletion standards (cryptographic erase, physical destruction)",
            "Implement deletion procedures for each data store",
            "Create deletion request workflow with approval process",
            "Log all deletions with timestamp and record count",
            "Test deletion effectiveness by attempting data recovery",
        ],
        "document_content": """
SECURE DATA DELETION PROCEDURES

1. PURPOSE
This document defines how {company_name} securely deletes personal data
when it is no longer needed, per NDPA 2023 Article 36.

2. DELETION METHODS
- Database records: Cryptographic erase or overwrite
- Files: Secure delete (multiple overwrite passes)
- Backups: Crypto-shredding (delete encryption keys)
- Physical media: Physical destruction or certified sanitization

3. DELETION WORKFLOW
1. Receive deletion request (automated or manual)
2. Verify the request is authorized
3. Execute deletion across all relevant systems
4. Verify deletion was successful
5. Log the deletion with evidence
6. Notify requester of completion
""",
    },
    "rectification": {
        "document_title": "Data Rectification Procedure",
        "remediation_type": "Procedure",
        "estimated_effort": "quick",
        "implementation_steps": [
            "Create a rectification request intake process",
            "Implement identity verification for rectification requests",
            "Build procedures to update data in each relevant system",
            "Set up notification to third parties if data was shared",
            "Document and communicate the procedure",
        ],
        "document_content": """
DATA RECTIFICATION PROCEDURE

1. PURPOSE
This procedure allows data subjects to request correction of inaccurate
personal data, per NDPA 2023 Article 46.

2. INTAKE
Data subjects may request rectification through:
- Email: {dpo_email}
- Web form: {rectification_form_url}

3. PROCESSING TIMELINE
- Acknowledge request within 2 business days
- Verify identity and assess the request within 5 business days
- Execute rectification within 15 business days
- Notify data subject of completion

4. THIRD-PARTY NOTIFICATION
If rectified data was shared with third parties, notify them of the correction.
""",
    },
    "erasure": {
        "document_title": "Data Erasure (Right to be Forgotten) Procedure",
        "remediation_type": "Procedure",
        "estimated_effort": "moderate",
        "implementation_steps": [
            "Create an erasure request intake process",
            "Implement identity verification for erasure requests",
            "Map all data locations for each data subject",
            "Build deletion procedures across all systems",
            "Create exception criteria (legal holds, legitimate interests)",
            "Test erasure by attempting data recovery",
        ],
        "document_content": """
DATA ERASURE PROCEDURE (RIGHT TO BE FORGOTTEN)

1. PURPOSE
This procedure enables data subjects to request deletion of their personal data,
per NDPA 2023 Article 47.

2. INTAKE AND VERIFICATION
Same process as DSAR — see DSAR procedure document.

3. DATA MAPPING
For each erasure request, identify all locations where the data subject's
personal data exists:
- Primary databases
- Backup systems
- Logs (anonymize if deletion not feasible)
- Third-party processors (notify them)
- Email and document archives

4. DELETION EXECUTION
Execute deletion across all identified systems using secure deletion methods
(see Secure Data Deletion Procedures document).

5. EXCEPTIONS
Erasure may be denied if:
- Data is needed for legal claims
- Data is subject to a legal hold
- Data is needed for public health or research
- Data is needed for exercising the right to freedom of expression

6. CONFIRMATION
Notify the data subject of:
- Completion of erasure
- Any exceptions applied and reasons
- Right to complain to NDPC if dissatisfied
""",
    },
    "gaid_consent": {
        "document_title": "GAID 2025 Enhanced Consent Framework",
        "remediation_type": "Policy + Implementation",
        "estimated_effort": "moderate",
        "implementation_steps": [
            "Upgrade consent management to granular, auditable standards",
            "Implement per-purpose consent (not blanket consent)",
            "Log consent with timestamp, IP, scope, and version",
            "Create easy withdrawal mechanism for each consent scope",
            "Audit consent records quarterly",
        ],
        "document_content": """
GAID 2025 ENHANCED CONSENT FRAMEWORK

This framework extends the base consent management framework to meet
GAID 2025 Section 4 requirements for granular, auditable consent records.

Key additions beyond NDPA 2023 baseline:
- Granular consent: separate consent for each processing purpose
- Audit trail: immutable record of consent lifecycle
- Withdrawal: one-click withdrawal for each consent scope
- Versioning: track consent against the specific privacy notice version
""",
    },
    "gaid_transparency": {
        "document_title": "GAID 2025 Transparency Notice",
        "remediation_type": "Documentation",
        "estimated_effort": "quick",
        "implementation_steps": [
            "Update privacy notice to GAID 2025 standards",
            "Include all required information in accessible language",
            "Publish in multiple formats (web, PDF, print)",
            "Review annually",
        ],
        "document_content": """
GAID 2025 TRANSPARENCY NOTICE TEMPLATE

This template provides a GAID 2025 Section 6-compliant privacy notice
including: data categories, processing purposes, retention periods,
data subject rights, DPO contact, and third-party sharing information.
""",
    },
    "gaid_portability": {
        "document_title": "Data Portability Implementation Guide",
        "remediation_type": "Technical Implementation",
        "estimated_effort": "moderate",
        "implementation_steps": [
            "Build a data export endpoint for each data subject",
            "Export in structured, machine-readable format (JSON/CSV)",
            "Include all personal data plus processing metadata",
            "Set up automated delivery (email with encrypted attachment)",
            "Test export completeness and accuracy",
        ],
        "document_content": """
DATA PORTABILITY IMPLEMENTATION GUIDE

This guide implements GAID 2025 Section 8 requirements for data portability,
enabling data subjects to receive their data in a structured, machine-readable format.

Export format: JSON or CSV
Delivery: Encrypted email attachment or secure download link
Timeline: Within 30 days of request
""",
    },
}


class FixGenerationService:
    """
    Generates remediation documents for compliance findings.
    For each finding, produces a pre-drafted fix document that
    clients can review, modify, and approve.
    """

    def __init__(self):
        self.templates = REMEDIATION_TEMPLATES

    def generate_fix(self, finding: ComplianceFinding, org_context: Dict[str, Any] = None) -> RemediationDocument:
        """
        Generate a remediation document for a single finding.
        """
        template_key = finding.remediation_template or "generic"
        template = self.templates.get(template_key)

        if not template:
            return self._generate_generic_fix(finding)

        # Fill template variables
        content = template["document_content"]
        content = self._fill_variables(content, org_context or {})

        # Add finding-specific details
        content = content.replace("{finding_description}", finding.description)
        content = content.replace("{finding_rule_id}", finding.rule_id)

        # Add evidence-based recommendations
        if finding.evidence:
            content += "\n\nEVIDENCE AND DETAILS:\n"
            content += json.dumps(finding.evidence, indent=2, default=str)

        return RemediationDocument(
            finding_rule_id=finding.rule_id,
            finding_title=finding.title,
            finding_description=finding.description,
            finding_severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
            remediation_type=template.get("remediation_type", "General"),
            document_title=template["document_title"],
            document_content=content,
            implementation_steps=template.get("implementation_steps", []),
            estimated_effort=template.get("estimated_effort", "moderate"),
            template_used=template_key,
            generated_at=datetime.utcnow().isoformat(),
        )

    def generate_all_fixes(
        self,
        findings: List[ComplianceFinding],
        org_context: Dict[str, Any] = None,
    ) -> List[RemediationDocument]:
        """Generate remediation documents for all findings."""
        return [self.generate_fix(f, org_context) for f in findings]

    def _generate_generic_fix(self, finding: ComplianceFinding) -> RemediationDocument:
        """Generate a generic fix document when no specific template exists."""
        return RemediationDocument(
            finding_rule_id=finding.rule_id,
            finding_title=finding.title,
            finding_description=finding.description,
            finding_severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
            remediation_type="General Remediation",
            document_title=f"Remediation Plan for {finding.title}",
            document_content=f"""
REMEDIATION PLAN: {finding.title}

RULE: {finding.rule_id}

FINDING:
{finding.description}

RECOMMENDATION:
{finding.recommendation}

IMPLEMENTATION STEPS:
1. Review the finding and assess impact
2. Develop a remediation plan specific to your systems
3. Implement the fix
4. Test the fix to verify compliance
5. Document the remediation for audit purposes
6. Schedule a follow-up review
""",
            implementation_steps=[
                "Review the finding and assess impact",
                "Develop a remediation plan",
                "Implement the fix",
                "Test the fix",
                "Document the remediation",
                "Schedule follow-up review",
            ],
            estimated_effort="moderate",
            template_used="generic",
            generated_at=datetime.utcnow().isoformat(),
        )

    def _fill_variables(self, content: str, context: Dict[str, Any]) -> str:
        """Fill template variables with organization context."""
        variables = {
            "{company_name}": context.get("company_name", "[Company Name]"),
            "{dpo_name}": context.get("dpo_name", "[DPO Name]"),
            "{dpo_email}": context.get("dpo_email", "[DPO Email]"),
            "{company_address}": context.get("company_address", "[Company Address]"),
            "{incident_commander}": context.get("incident_commander", "[Name]"),
            "{it_lead}": context.get("it_lead", "[Name]"),
            "{legal_counsel}": context.get("legal_counsel", "[Name]"),
            "{comms_lead}": context.get("comms_lead", "[Name]"),
            "{consent_method}": context.get("consent_method", "[Describe consent collection method]"),
            "{dsar_form_url}": context.get("dsar_form_url", "[URL]"),
            "{rectification_form_url}": context.get("rectification_form_url", "[URL]"),
            "{field_count}": str(context.get("field_count", "[count]")),
            "{excessive_fields}": ", ".join(context.get("excessive_fields", [])) or "[fields]",
            "{removal_list}": "\n".join(f"- {f}" for f in context.get("excessive_fields", [])) or "[list fields to remove]",
            "{data_locations}": json.dumps(context.get("data_locations", []), indent=2) or "[list data locations]",
            "{non_adequate_locations}": json.dumps(context.get("non_adequate_locations", []), indent=2) or "[list non-adequate locations]",
            "{recommended_action}": context.get("recommended_action", "[describe recommended action]"),
            "{purpose_list}": "\n".join(f"- {p}" for p in context.get("processing_purposes", [])) or "[list purposes]",
        }

        for var, value in variables.items():
            content = content.replace(var, value)

        return content
