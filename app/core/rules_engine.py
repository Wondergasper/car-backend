"""
Rules Engine - NDPA 2023 + GAID 2025 Compliance Evaluation.

Evaluates real connector data against compliance rules.
Each check inspects actual evidence from scanned data sources,
not placeholder dicts. Produces structured findings with evidence.
"""
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from app.core.pii_scanner import PIIScanner, PIIFinding


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ComplianceFinding:
    rule_id: str
    article: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    remediation_template: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    affected_records: int = 0
    auto_fixable: bool = False
    auto_fix_suggestion: str = ""
    connector_id: Optional[str] = None
    category: str = ""


class AuditContext:
    """
    Holds all data gathered from connectors for a single audit run.
    This is the input to the rules engine — built by the event processor
    from connector events, PII scans, and system metadata.
    """
    def __init__(self):
        # PII inventory: what PII exists, where, in what volume
        self.pii_inventory: List[PIIFinding] = []

        # Connector metadata
        self.connectors: List[Dict[str, Any]] = []

        # Data inventory from connectors
        self.data_sources: List[Dict[str, Any]] = []

        # Schema metadata
        self.schemas: Dict[str, Any] = {}  # table_name -> {columns, types, row_count}

        # Security posture
        self.encryption_at_rest: bool = False
        self.encryption_in_transit: bool = False
        self.mfa_enabled: bool = False
        self.access_control_policy: Optional[str] = None
        self.audit_logging_enabled: bool = False

        # Consent management
        self.consent_records: List[Dict[str, Any]] = []
        self.consent_collection_method: Optional[str] = None

        # Data governance
        self.retention_policy: Optional[Dict[str, Any]] = None
        self.deletion_procedures: Optional[Dict[str, Any]] = None
        self.purpose_statements: List[str] = []
        self.data_processing_purposes: List[str] = []

        # Data subject rights
        self.dsar_procedure: Optional[Dict[str, Any]] = None
        self.rectification_procedure: Optional[Dict[str, Any]] = None
        self.erasure_procedure: Optional[Dict[str, Any]] = None

        # Breach management
        self.breach_notification_procedure: Optional[Dict[str, Any]] = None
        self.breach_response_plan: Optional[Dict[str, Any]] = None

        # Cross-border data transfer
        self.data_locations: List[Dict[str, Any]] = []  # where data is stored
        self.cross_border_transfers: List[Dict[str, Any]] = []
        self.adequacy_countries: List[str] = []  # countries with adequacy status

        # Authorization
        self.authorization_audit_trail: bool = False
        self.role_based_access: bool = False
        self.access_review_frequency: Optional[str] = None

        # Data minimization
        self.personal_data_fields: List[str] = []
        self.excessive_fields: List[str] = []

        # Data age
        self.oldest_record_date: Optional[datetime] = None
        self.record_age_distribution: Dict[str, int] = {}

        # GAID 2025 specific
        self.gaid_consent_records: List[Dict[str, Any]] = []
        self.gaid_transparency_notice: bool = False
        self.gaid_data_portability: bool = False


class RulesEngine:
    """
    Evaluates an AuditContext against NDPA 2023 + GAID 2025 rules.
    Returns a list of ComplianceFinding objects with evidence.
    """

    # Thresholds for accurate detection
    CONSENT_RECORD_THRESHOLD = 1  # Must have at least 1 consent record
    MAX_PERSONAL_DATA_FIELDS = 15  # Beyond this is likely excessive
    MAX_RECORD_AGE_DAYS = 365 * 3  # 3 years - flag old data
    HIGH_PII_CONFIDENCE_THRESHOLD = 0.8

    def __init__(self):
        self.findings: List[ComplianceFinding] = []
        self.context: Optional[AuditContext] = None

    def evaluate(self, context: AuditContext) -> List[ComplianceFinding]:
        """Run all compliance checks against a populated AuditContext."""
        self.context = context
        self.findings = []

        # === NDPA 2023: Data Privacy ===
        self._check_consent_management()
        self._check_data_minimization()
        self._check_purpose_limitation()

        # === NDPA 2023: Access Control ===
        self._check_access_controls()
        self._check_authentication()
        self._check_authorization()

        # === NDPA 2023: Data Retention ===
        self._check_data_retention()
        self._check_deletion_procedures()

        # === NDPA 2023: Security ===
        self._check_encryption_at_rest()
        self._check_encryption_in_transit()
        self._check_audit_logging()
        self._check_breach_notification()

        # === NDPA 2023: Data Subject Rights ===
        self._check_data_subject_access()
        self._check_rectification()
        self._check_erasure()

        # === NDPA 2023: PII Exposure (from scanner) ===
        self._check_pii_exposure()
        self._check_unmasked_pii_in_logs()

        # === Cross-Border (highest-value rule) ===
        self._check_cross_border_transfers()

        # === GAID 2025 ===
        self._check_gaid_consent()
        self._check_gaid_transparency()
        self._check_gaid_data_portability()

        return self.findings

    def _add_finding(
        self,
        rule_id: str,
        article: str,
        title: str,
        severity: Severity,
        description: str,
        recommendation: str,
        remediation_template: str = "",
        evidence: Dict[str, Any] = None,
        affected_records: int = 0,
        auto_fixable: bool = False,
        auto_fix_suggestion: str = "",
        connector_id: Optional[str] = None,
        category: str = "",
    ):
        self.findings.append(ComplianceFinding(
            rule_id=rule_id,
            article=article,
            title=title,
            severity=severity,
            description=description,
            recommendation=recommendation,
            remediation_template=remediation_template,
            evidence=evidence or {},
            affected_records=affected_records,
            auto_fixable=auto_fixable,
            auto_fix_suggestion=auto_fix_suggestion,
            connector_id=connector_id,
            category=category,
        ))

    # ==================== NDPA 2023: Data Privacy ====================

    def _check_consent_management(self):
        """
        NDPA 2023 Article 25 - Consent must be explicit, informed, recorded.
        Checks: consent records exist AND collection method is documented.
        """
        if not self.context.consent_records:
            self._add_finding(
                rule_id="NDPA-2023-Art25",
                article="Article 25",
                title="No Consent Records Found",
                severity=Severity.CRITICAL,
                description=(
                    "No consent records were detected in any connected data source. "
                    "NDPA 2023 requires explicit, informed consent before processing personal data."
                ),
                recommendation=(
                    "Implement a consent management system (CMP) that records: "
                    "(1) what consent was obtained, (2) when, (3) from whom, "
                    "(4) the specific purpose, and (5) the method of consent."
                ),
                remediation_template="consent_management",
                auto_fixable=True,
                auto_fix_suggestion=(
                    "Deploy a consent management platform (e.g., OneTrust, Cookiebot) "
                    "integrated with your web and mobile applications. Log all consent "
                    "events with timestamps and IP addresses."
                ),
                category="data_privacy",
            )
        elif not self.context.consent_collection_method:
            self._add_finding(
                rule_id="NDPA-2023-Art25",
                article="Article 25",
                title="Consent Collection Method Not Documented",
                severity=Severity.HIGH,
                description=(
                    f"Found {len(self.context.consent_records)} consent record(s), "
                    "but the method of consent collection is not documented. "
                    "NDPA 2023 requires consent to be explicit and verifiable."
                ),
                recommendation="Document how consent was obtained for each data subject category.",
                category="data_privacy",
            )

    def _check_data_minimization(self):
        """
        NDPA 2023 Article 27 - Data must be adequate, relevant, limited.
        Checks: number of personal data fields per record exceeds threshold.
        """
        if self.context.personal_data_fields:
            field_count = len(self.context.personal_data_fields)
            if field_count > self.MAX_PERSONAL_DATA_FIELDS:
                excessive = self.context.excessive_fields or self.context.personal_data_fields[self.MAX_PERSONAL_DATA_FIELDS:]
                self._add_finding(
                    rule_id="NDPA-2023-Art27",
                    article="Article 27",
                    title=f"Excessive Personal Data Fields ({field_count} collected)",
                    severity=Severity.HIGH,
                    description=(
                        f"Your systems collect {field_count} personal data fields per record, "
                        f"which exceeds the recommended threshold of {self.MAX_PERSONAL_DATA_FIELDS}. "
                        f"Potentially excessive fields: {', '.join(excessive[:5])}."
                    ),
                    recommendation=(
                        "Review each personal data field and document the lawful basis "
                        "for collecting it. Remove fields that are not necessary for "
                        "the stated processing purpose."
                    ),
                    remediation_template="data_minimization",
                    evidence={"field_count": field_count, "excessive_fields": [f for f in excessive[:10]]},
                    auto_fixable=True,
                    auto_fix_suggestion=(
                        "Conduct a data field audit. For each field, document: "
                        "(1) why it's collected, (2) what purpose it serves, "
                        "(3) whether it can be anonymized or removed. "
                        "Remove fields without a documented lawful basis."
                    ),
                    category="data_privacy",
                )

    def _check_purpose_limitation(self):
        """
        NDPA 2023 Article 28 - Data collected for specified, legitimate purposes.
        Checks: purpose statements exist and map to actual processing.
        """
        if not self.context.purpose_statements and not self.context.data_processing_purposes:
            self._add_finding(
                rule_id="NDPA-2023-Art28",
                article="Article 28",
                title="No Purpose Limitation Documentation",
                severity=Severity.HIGH,
                description=(
                    "No documented purposes for data processing were found. "
                    "NDPA 2023 requires that personal data be collected for "
                    "specified, explicit, and legitimate purposes."
                ),
                recommendation=(
                    "Document each purpose for which personal data is processed. "
                    "Ensure purposes are specific and communicated to data subjects "
                    "at the point of data collection."
                ),
                remediation_template="purpose_limitation",
                auto_fixable=True,
                auto_fix_suggestion=(
                    "Create a processing register documenting: (1) each processing purpose, "
                    "(2) the legal basis, (3) data categories involved, (4) retention period. "
                    "Publish these purposes in your privacy notice."
                ),
                category="data_privacy",
            )

    # ==================== NDPA 2023: Access Control ====================

    def _check_access_controls(self):
        """NDPA 2023 Article 31 - Appropriate access controls required."""
        if not self.context.access_control_policy and not self.context.role_based_access:
            self._add_finding(
                rule_id="NDPA-2023-Art31",
                article="Article 31",
                title="No Access Control Policy Detected",
                severity=Severity.CRITICAL,
                description=(
                    "No access control policy or role-based access system was detected. "
                    "Personal data access must be restricted based on job function."
                ),
                recommendation=(
                    "Implement role-based access control (RBAC) with least-privilege principles. "
                    "Document access control policies and review them quarterly."
                ),
                remediation_template="access_control",
                auto_fixable=True,
                auto_fix_suggestion=(
                    "Implement RBAC: (1) Define roles (admin, analyst, viewer, etc.), "
                    "(2) Map each role to specific data permissions, "
                    "(3) Enforce at database and application level, "
                    "(4) Log all access attempts."
                ),
                category="access_control",
            )

    def _check_authentication(self):
        """NDPA 2023 Article 32 - Strong authentication required."""
        if not self.context.mfa_enabled:
            self._add_finding(
                rule_id="NDPA-2023-Art32",
                article="Article 32",
                title="Multi-Factor Authentication Not Enabled",
                severity=Severity.HIGH,
                description=(
                    "Multi-factor authentication (MFA) is not enabled on systems "
                    "that process personal data. NDPA 2023 requires strong authentication."
                ),
                recommendation="Enable MFA on all systems accessing personal data.",
                remediation_template="mfa",
                auto_fixable=False,
                auto_fix_suggestion=(
                    "Enable MFA using TOTP (Google Authenticator, Authy) or "
                    "hardware security keys (YubiKey) for all staff with data access."
                ),
                category="access_control",
            )

    def _check_authorization(self):
        """NDPA 2023 Article 33 - Authorization audit trail required."""
        if not self.context.authorization_audit_trail:
            self._add_finding(
                rule_id="NDPA-2023-Art33",
                article="Article 33",
                title="No Authorization Audit Trail",
                severity=Severity.MEDIUM,
                description=(
                    "No authorization audit trail was detected. All access grants "
                    "and denials must be logged for accountability."
                ),
                recommendation="Enable detailed logging of all authorization decisions.",
                category="access_control",
            )

    # ==================== NDPA 2023: Data Retention ====================

    def _check_data_retention(self):
        """
        NDPA 2023 Article 35 - Data must not be kept longer than necessary.
        Checks: retention policy exists AND old records are flagged.
        """
        if not self.context.retention_policy:
            self._add_finding(
                rule_id="NDPA-2023-Art35",
                article="Article 35",
                title="No Data Retention Policy",
                severity=Severity.HIGH,
                description=(
                    "No data retention policy was found. Personal data must not "
                    "be kept longer than necessary for its processing purpose."
                ),
                recommendation=(
                    "Establish documented retention periods for each data category. "
                    "Implement automated deletion or anonymization when periods expire."
                ),
                remediation_template="data_retention",
                auto_fixable=True,
                auto_fix_suggestion=(
                    "Create a retention schedule: (1) Map each data category to a "
                    "retention period (e.g., customer data: 5 years after last interaction), "
                    "(2) Implement automated deletion jobs, (3) Document exceptions."
                ),
                category="retention",
            )

        # Check for old records even if policy exists
        if self.context.oldest_record_date:
            age_days = (datetime.utcnow() - self.context.oldest_record_date).days
            if age_days > self.MAX_RECORD_AGE_DAYS:
                self._add_finding(
                    rule_id="NDPA-2023-Art35-Old",
                    article="Article 35",
                    title=f"Records Older Than {self.MAX_RECORD_AGE_DAYS // 365} Years Detected",
                    severity=Severity.HIGH,
                    description=(
                        f"The oldest records in your system are {age_days} days old "
                        f"({age_days // 365} years). This exceeds the recommended "
                        f"maximum retention period of {self.MAX_RECORD_AGE_DAYS // 365} years."
                    ),
                    recommendation="Review and delete or anonymize records beyond their retention period.",
                    evidence={"oldest_record_days": age_days},
                    affected_records=self.context.record_age_distribution.get("over_3_years", 0),
                    auto_fixable=True,
                    auto_fix_suggestion=(
                        "Run a data age analysis query. Delete or anonymize records "
                        "beyond their documented retention period. Keep only aggregated, "
                        "anonymized statistics."
                    ),
                    category="retention",
                )

    def _check_deletion_procedures(self):
        """NDPA 2023 Article 36 - Secure deletion procedures required."""
        if not self.context.deletion_procedures:
            self._add_finding(
                rule_id="NDPA-2023-Art36",
                article="Article 36",
                title="No Secure Deletion Procedures",
                severity=Severity.MEDIUM,
                description=(
                    "No secure deletion procedures were detected. Personal data "
                    "must be irretrievably destroyed when no longer needed."
                ),
                recommendation="Implement secure deletion (cryptographic erase or physical destruction).",
                remediation_template="deletion_procedures",
                category="retention",
            )

    # ==================== NDPA 2023: Security ====================

    def _check_encryption_at_rest(self):
        """NDPA 2023 Article 38 - Data at rest must be encrypted."""
        if not self.context.encryption_at_rest:
            self._add_finding(
                rule_id="NDPA-2023-Art38-Rest",
                article="Article 38",
                title="Data at Rest Encryption Not Enabled",
                severity=Severity.CRITICAL,
                description=(
                    "Data at rest encryption was not detected. All personal data "
                    "stored in databases, files, and backups must be encrypted "
                    "using AES-256 or equivalent."
                ),
                recommendation="Enable TDE (Transparent Data Encryption) or application-level encryption.",
                remediation_template="encryption_at_rest",
                auto_fixable=False,
                auto_fix_suggestion=(
                    "Enable AES-256 encryption at the database level (e.g., PostgreSQL "
                    "pgcrypto, AWS RDS encryption). For file storage, use server-side "
                    "encryption (SSE-S3 or SSE-KMS)."
                ),
                category="security",
            )

    def _check_encryption_in_transit(self):
        """NDPA 2023 Article 38 - Data in transit must be encrypted."""
        if not self.context.encryption_in_transit:
            self._add_finding(
                rule_id="NDPA-2023-Art38-Transit",
                article="Article 38",
                title="Data in Transit Encryption Not Enabled",
                severity=Severity.CRITICAL,
                description=(
                    "TLS/SSL encryption for data in transit was not detected. "
                    "All personal data transmitted over networks must use TLS 1.2+."
                ),
                recommendation="Enable HTTPS/TLS 1.2+ for all data transmission.",
                remediation_template="encryption_in_transit",
                auto_fixable=False,
                category="security",
            )

    def _check_audit_logging(self):
        """NDPA 2023 Article 40 - Comprehensive audit logging required."""
        if not self.context.audit_logging_enabled:
            self._add_finding(
                rule_id="NDPA-2023-Art40",
                article="Article 40",
                title="Audit Logging Not Enabled",
                severity=Severity.HIGH,
                description=(
                    "Comprehensive audit logging for personal data access and "
                    "processing was not detected. NDPA 2023 requires detailed audit logs."
                ),
                recommendation="Enable audit logging for all CRUD operations on personal data.",
                remediation_template="audit_logging",
                auto_fixable=True,
                auto_fix_suggestion=(
                    "Implement database audit logging or application-level event logging. "
                    "Log: who accessed what data, when, from where, and what action was taken. "
                    "Retain logs for at least 12 months."
                ),
                category="security",
            )

    def _check_breach_notification(self):
        """NDPA 2023 Article 42 - Breach notification within 72 hours."""
        if not self.context.breach_notification_procedure and not self.context.breach_response_plan:
            self._add_finding(
                rule_id="NDPA-2023-Art42",
                article="Article 42",
                title="No Breach Notification Procedure",
                severity=Severity.CRITICAL,
                description=(
                    "No breach notification procedure or response plan was detected. "
                    "NDPA 2023 requires reporting breaches to NDPC within 72 hours."
                ),
                recommendation=(
                    "Establish a breach response plan with: (1) detection procedures, "
                    "(2) 72-hour notification workflow to NDPC, (3) data subject "
                    "notification process, (4) remediation steps."
                ),
                remediation_template="breach_notification",
                auto_fixable=True,
                auto_fix_suggestion=(
                    "Create a breach response playbook: (1) Define breach severity levels, "
                    "(2) Create notification templates for NDPC and data subjects, "
                    "(3) Assign response roles and responsibilities, "
                    "(4) Run tabletop exercises quarterly."
                ),
                category="security",
            )

    # ==================== NDPA 2023: Data Subject Rights ====================

    def _check_data_subject_access(self):
        """NDPA 2023 Article 45 - DSAR procedure required."""
        if not self.context.dsar_procedure:
            self._add_finding(
                rule_id="NDPA-2023-Art45",
                article="Article 45",
                title="No Data Subject Access Request Procedure",
                severity=Severity.HIGH,
                description=(
                    "No procedure for handling data subject access requests (DSARs) "
                    "was detected. Data subjects have the right to access their data "
                    "within 30 days."
                ),
                recommendation="Implement a DSAR procedure with 30-day response SLA.",
                remediation_template="dsar",
                auto_fixable=True,
                auto_fix_suggestion=(
                    "Create a DSAR workflow: (1) Intake channel (email, form, portal), "
                    "(2) Identity verification process, (3) Data extraction procedure, "
                    "(4) Response template with all required information, "
                    "(5) Tracking system for SLA compliance."
                ),
                category="data_subject_rights",
            )

    def _check_rectification(self):
        """NDPA 2023 Article 46 - Right to rectification."""
        if not self.context.rectification_procedure:
            self._add_finding(
                rule_id="NDPA-2023-Art46",
                article="Article 46",
                title="No Data Rectification Procedure",
                severity=Severity.MEDIUM,
                description=(
                    "No procedure for data rectification was detected. Data subjects "
                    "have the right to have inaccurate data corrected."
                ),
                recommendation="Implement a rectification procedure with clear SLAs.",
                category="data_subject_rights",
            )

    def _check_erasure(self):
        """NDPA 2023 Article 47 - Right to erasure."""
        if not self.context.erasure_procedure:
            self._add_finding(
                rule_id="NDPA-2023-Art47",
                article="Article 47",
                title="No Data Erasure Procedure",
                severity=Severity.HIGH,
                description=(
                    "No procedure for data erasure (right to be forgotten) was detected. "
                    "Data subjects have the right to request deletion of their personal data."
                ),
                recommendation="Implement an erasure procedure covering all data stores.",
                remediation_template="erasure",
                auto_fixable=True,
                auto_fix_suggestion=(
                    "Create an erasure workflow: (1) Verify identity of requester, "
                    "(2) Map all locations where their data exists (databases, backups, logs), "
                    "(3) Execute deletion across all systems, "
                    "(4) Confirm deletion with audit trail, "
                    "(5) Notify requester of completion."
                ),
                category="data_subject_rights",
            )

    # ==================== PII Exposure Checks ====================

    def _check_pii_exposure(self):
        """
        Checks the PII scanner results for excessive PII exposure.
        High volumes of sensitive PII (BVN, NIN) indicate compliance risk.
        """
        pii_findings = self.context.pii_inventory
        if not pii_findings:
            # No PII found — could mean data is clean or scanner missed it
            self._add_finding(
                rule_id="NDPA-2023-PII-None",
                article="General",
                title="No PII Detected in Data Sources",
                severity=Severity.INFO,
                description=(
                    "The PII scanner did not detect any Nigerian personal identifiers "
                    "(BVN, NIN, phone, email) in connected data sources. "
                    "Verify that the scanner is configured correctly and has "
                    "access to all relevant data."
                ),
                recommendation="Run the PII scanner with broader patterns to confirm.",
                category="pii_detection",
            )
            return

        # Count high-confidence critical PII
        critical_pii = [
            p for p in pii_findings
            if p.category in ("bvn", "nin") and p.confidence >= self.HIGH_PII_CONFIDENCE_THRESHOLD
        ]

        if critical_pii:
            total_critical = len(critical_pii)
            locations = list(set(p.location for p in critical_pii))
            self._add_finding(
                rule_id="NDPA-2023-PII-Critical",
                article="Articles 25, 38",
                title=f"High-Volume Critical PII Detected ({total_critical} instances)",
                severity=Severity.HIGH,
                description=(
                    f"Found {total_critical} instances of highly sensitive PII "
                    f"(BVN/NIN) across {len(locations)} location(s): "
                    f"{', '.join(locations[:5])}. "
                    f"This data requires enhanced protection under NDPA 2023."
                ),
                recommendation=(
                    "Ensure all BVN/NIN data is encrypted at rest and in transit. "
                    "Restrict access to systems containing this data. "
                    "Document the lawful basis for collecting each identifier."
                ),
                evidence={
                    "pii_by_category": self._pii_by_category(pii_findings),
                    "high_risk_locations": locations[:10],
                    "total_critical_pii": total_critical,
                },
                affected_records=total_critical,
                category="pii_detection",
            )

    def _check_unmasked_pii_in_logs(self):
        """
        Checks if PII appears in log-like locations (potential exposure).
        """
        log_pii = [
            p for p in self.context.pii_inventory
            if "log" in p.location.lower() or "audit" in p.location.lower()
        ]
        if log_pii:
            self._add_finding(
                rule_id="NDPA-2023-PII-Logs",
                article="Articles 38, 40",
                title="PII Found in Log/Audit Locations",
                severity=Severity.HIGH,
                description=(
                    f"Personal identifiers were found in {len(log_pii)} log or "
                    f"audit trail location(s). PII should not appear in logs "
                    f"unless properly masked."
                ),
                recommendation="Review logging practices. Mask or hash PII before writing to logs.",
                evidence={"log_locations": [p.location for p in log_pii[:10]]},
                auto_fixable=True,
                auto_fix_suggestion=(
                    "Implement PII-aware logging: (1) Use structured logging with "
                    "PII field detection, (2) Hash or mask PII values before writing, "
                    "(3) Use separate secure storage for raw PII references."
                ),
                category="pii_detection",
            )

    def _pii_by_category(self, findings: List[PIIFinding]) -> Dict[str, int]:
        counts = {}
        for f in findings:
            cat = f.category.value if hasattr(f.category, 'value') else str(f.category)
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    # ==================== Cross-Border Data Transfers ====================

    def _check_cross_border_transfers(self):
        """
        NDPA 2023 Article 48 + GAID 2025 - Cross-border data transfer restrictions.
        This is the HIGHEST-VALUE rule: data stored outside Nigeria in countries
        without adequacy status is the most common violation and biggest fine trigger.

        Checks:
        1. Where is data stored? (data_locations)
        2. Are transfers to countries without adequacy status?
        3. Are appropriate safeguards in place? (SCCs, BCRs)
        """
        if not self.context.data_locations:
            # Can't assess cross-border without location data
            self._add_finding(
                rule_id="NDPA-2023-Art48-Unknown",
                article="Article 48",
                title="Data Storage Locations Unknown",
                severity=Severity.HIGH,
                description=(
                    "Cannot determine where personal data is stored. NDPA 2023 restricts "
                    "cross-border transfers to countries with adequate data protection "
                    "or appropriate safeguards. You must document all data storage locations."
                ),
                recommendation=(
                    "Map all data storage locations: (1) Database server locations, "
                    "(2) Cloud provider regions, (3) Backup storage locations, "
                    "(4) Third-party processor locations."
                ),
                remediation_template="cross_border",
                auto_fixable=True,
                auto_fix_suggestion=(
                    "Conduct a data mapping exercise: (1) Inventory all databases, "
                    "(2) Check cloud provider regions (AWS, Azure, GCP), "
                    "(3) Identify backup storage locations, "
                    "(4) Document third-party data processors and their locations."
                ),
                category="cross_border",
            )
            return

        # Check each data location
        non_adequate_locations = []
        for loc in self.context.data_locations:
            country = loc.get("country", "").lower()
            has_safeguards = loc.get("safeguards", False)  # SCCs, BCRs, etc.

            # Nigeria is fine, check others
            if country != "nigeria" and country not in [c.lower() for c in self.context.adequacy_countries]:
                if not has_safeguards:
                    non_adequate_locations.append(loc)

        if non_adequate_locations:
            locations_str = ", ".join(
                f"{loc.get('service', 'Unknown')} in {loc.get('country', 'Unknown')}"
                for loc in non_adequate_locations[:5]
            )
            self._add_finding(
                rule_id="NDPA-2023-Art48",
                article="Article 48",
                title=f"Cross-Border Data Transfer Without Adequacy ({len(non_adequate_locations)} locations)",
                severity=Severity.CRITICAL,
                description=(
                    f"Personal data is stored in {len(non_adequate_locations)} location(s) "
                    f"in countries without recognized adequacy status and without documented "
                    f"safeguards: {locations_str}. "
                    f"This is a direct violation of NDPA 2023 cross-border transfer restrictions "
                    f"and is the most common fine trigger."
                ),
                recommendation=(
                    "Either: (1) Move data to Nigeria or an adequacy country, "
                    "(2) Implement Standard Contractual Clauses (SCCs), "
                    "(3) Obtain explicit consent for the transfer, or "
                    "(4) Apply Binding Corporate Rules (BCRs) if applicable."
                ),
                remediation_template="cross_border_fix",
                evidence={
                    "non_adequate_locations": non_adequate_locations,
                    "adequacy_countries": self.context.adequacy_countries,
                },
                auto_fixable=True,
                auto_fix_suggestion=(
                    "Immediate fix options: (1) Migrate data to AWS Africa (Cape Town) or "
                    "Azure South Africa North regions, (2) Implement SCCs with your cloud "
                    "provider using the NDPC-approved template, (3) Document explicit consent "
                    "for cross-border transfers in your privacy notice."
                ),
                affected_records=sum(loc.get("record_count", 0) for loc in non_adequate_locations),
                category="cross_border",
            )

        # Also flag specific cross-border transfers
        if self.context.cross_border_transfers:
            unprotected = [
                t for t in self.context.cross_border_transfers
                if not t.get("safeguards") and t.get("destination_country", "").lower() not in
                [c.lower() for c in self.context.adequacy_countries]
            ]
            if unprotected:
                self._add_finding(
                    rule_id="NDPA-2023-Art48-Transfer",
                    article="Article 48",
                    title=f"Unprotected Cross-Border Transfers Detected ({len(unprotected)} transfers)",
                    severity=Severity.CRITICAL,
                    description=(
                        f"{len(unprotected)} data transfer(s) to countries without adequacy "
                        f"status were detected without appropriate safeguards."
                    ),
                    recommendation="Implement SCCs or obtain explicit consent for each transfer.",
                    evidence={"unprotected_transfers": unprotected[:10]},
                    category="cross_border",
                )

    # ==================== GAID 2025 Rules ====================

    def _check_gaid_consent(self):
        """
        GAID 2025 - Government Accountability and Integrity in Data.
        Enhanced consent requirements beyond NDPA 2023 baseline.
        Requires granular, auditable consent records.
        """
        if not self.context.gaid_consent_records and not self.context.consent_records:
            self._add_finding(
                rule_id="GAID-2025-Consent",
                article="GAID Section 4",
                title="No GAID-Compliant Consent Records",
                severity=Severity.HIGH,
                description=(
                    "No consent records meeting GAID 2025 standards were found. "
                    "GAID 2025 requires granular, auditable consent records with "
                    "timestamp, scope, and withdrawal capability."
                ),
                recommendation=(
                    "Upgrade consent management to GAID 2025 standards: "
                    "(1) Granular consent per processing purpose, "
                    "(2) Timestamp and IP address logging, "
                    "(3) Easy withdrawal mechanism."
                ),
                remediation_template="gaid_consent",
                category="gaid_2025",
            )

    def _check_gaid_transparency(self):
        """GAID 2025 - Transparency notice requirements."""
        if not self.context.gaid_transparency_notice:
            self._add_finding(
                rule_id="GAID-2025-Transparency",
                article="GAID Section 6",
                title="No GAID-Compliant Transparency Notice",
                severity=Severity.MEDIUM,
                description=(
                    "No GAID 2025-compliant transparency notice was detected. "
                    "Organizations must provide clear, accessible information about "
                    "data processing to data subjects."
                ),
                recommendation="Publish a GAID 2025-compliant privacy notice.",
                remediation_template="gaid_transparency",
                auto_fixable=True,
                auto_fix_suggestion=(
                    "Update your privacy notice to include: (1) What data is collected, "
                    "(2) Why it's processed, (3) Who it's shared with, "
                    "(4) How long it's kept, (5) Data subject rights, "
                    "(6) Contact information for DPO."
                ),
                category="gaid_2025",
            )

    def _check_gaid_data_portability(self):
        """GAID 2025 - Data portability rights."""
        if not self.context.gaid_data_portability:
            self._add_finding(
                rule_id="GAID-2025-Portability",
                article="GAID Section 8",
                title="No Data Portability Mechanism",
                severity=Severity.MEDIUM,
                description=(
                    "No data portability mechanism was detected. GAID 2025 grants "
                    "data subjects the right to receive their data in a structured, "
                    "machine-readable format."
                ),
                recommendation="Implement a data export feature in CSV/JSON format.",
                remediation_template="gaid_portability",
                auto_fixable=True,
                auto_fix_suggestion=(
                    "Build a data export endpoint that returns all personal data "
                    "for a given data subject in JSON or CSV format. Include metadata "
                    "about processing purposes and retention periods."
                ),
                category="gaid_2025",
            )

    # ==================== Utility Methods ====================

    def calculate_compliance_score(self, findings: List[ComplianceFinding]) -> int:
        """
        Calculate compliance score 0-100 based on findings.
        Weighted by severity: CRITICAL=25, HIGH=15, MEDIUM=8, LOW=3, INFO=0
        Max possible deduction = 100
        """
        severity_weights = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }

        total_deduction = 0
        for finding in findings:
            total_deduction += severity_weights.get(finding.severity, 0)

        score = max(0, 100 - total_deduction)
        return score

    def generate_summary(self, findings: List[ComplianceFinding]) -> Dict[str, Any]:
        """Generate a summary of compliance findings."""
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        by_category = {}
        total_affected = 0

        for f in findings:
            sev = f.severity.value if hasattr(f.severity, 'value') else str(f.severity)
            by_severity[sev] = by_severity.get(sev, 0) + 1

            cat = f.category or "uncategorized"
            by_category[cat] = by_category.get(cat, 0) + 1

            total_affected += f.affected_records

        return {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "by_category": by_category,
            "total_affected_records": total_affected,
            "compliance_score": self.calculate_compliance_score(findings),
        }


# ==================== Rule Definitions for Database Seeding ====================

COMPLIANCE_RULES = [
    # NDPA 2023: Data Privacy
    {
        "rule_id": "NDPA-2023-Art25",
        "article": "Article 25",
        "title": "Consent Management",
        "description": "Data controllers must obtain explicit, informed consent before collecting or processing personal data.",
        "category": "data_privacy",
        "check_function": "_check_consent_management",
        "remediation_template": "consent_management",
        "severity_default": "critical",
    },
    {
        "rule_id": "NDPA-2023-Art27",
        "article": "Article 27",
        "title": "Data Minimization",
        "description": "Personal data collected must be adequate, relevant, and limited to what is necessary.",
        "category": "data_privacy",
        "check_function": "_check_data_minimization",
        "remediation_template": "data_minimization",
        "severity_default": "high",
    },
    {
        "rule_id": "NDPA-2023-Art28",
        "article": "Article 28",
        "title": "Purpose Limitation",
        "description": "Personal data must be collected for specified, explicit, and legitimate purposes.",
        "category": "data_privacy",
        "check_function": "_check_purpose_limitation",
        "remediation_template": "purpose_limitation",
        "severity_default": "high",
    },

    # NDPA 2023: Access Control
    {
        "rule_id": "NDPA-2023-Art31",
        "article": "Article 31",
        "title": "Access Controls",
        "description": "Appropriate technical and organizational measures must be implemented to control access to personal data.",
        "category": "access_control",
        "check_function": "_check_access_controls",
        "remediation_template": "access_control",
        "severity_default": "critical",
    },
    {
        "rule_id": "NDPA-2023-Art32",
        "article": "Article 32",
        "title": "Authentication",
        "description": "Strong authentication mechanisms must be implemented for systems processing personal data.",
        "category": "access_control",
        "check_function": "_check_authentication",
        "remediation_template": "mfa",
        "severity_default": "high",
    },
    {
        "rule_id": "NDPA-2023-Art33",
        "article": "Article 33",
        "title": "Authorization",
        "description": "Access to personal data must be restricted based on role and need-to-know basis.",
        "category": "access_control",
        "check_function": "_check_authorization",
        "remediation_template": "authorization_audit",
        "severity_default": "medium",
    },

    # NDPA 2023: Data Retention
    {
        "rule_id": "NDPA-2023-Art35",
        "article": "Article 35",
        "title": "Data Retention",
        "description": "Personal data must not be kept longer than necessary for the purposes for which it is processed.",
        "category": "retention",
        "check_function": "_check_data_retention",
        "remediation_template": "data_retention",
        "severity_default": "high",
    },
    {
        "rule_id": "NDPA-2023-Art36",
        "article": "Article 36",
        "title": "Deletion Procedures",
        "description": "Secure procedures must be in place for the deletion of personal data when no longer needed.",
        "category": "retention",
        "check_function": "_check_deletion_procedures",
        "remediation_template": "deletion_procedures",
        "severity_default": "medium",
    },

    # NDPA 2023: Security
    {
        "rule_id": "NDPA-2023-Art38",
        "article": "Article 38",
        "title": "Encryption",
        "description": "Personal data must be encrypted both at rest and in transit using industry-standard encryption.",
        "category": "security",
        "check_function": "_check_encryption_at_rest",
        "remediation_template": "encryption_at_rest",
        "severity_default": "critical",
    },
    {
        "rule_id": "NDPA-2023-Art40",
        "article": "Article 40",
        "title": "Audit Logging",
        "description": "Comprehensive audit logs must be maintained for all access to and processing of personal data.",
        "category": "security",
        "check_function": "_check_audit_logging",
        "remediation_template": "audit_logging",
        "severity_default": "high",
    },
    {
        "rule_id": "NDPA-2023-Art42",
        "article": "Article 42",
        "title": "Breach Notification",
        "description": "Data breaches must be reported to NDPC within 72 hours of becoming aware of the breach.",
        "category": "security",
        "check_function": "_check_breach_notification",
        "remediation_template": "breach_notification",
        "severity_default": "critical",
    },

    # NDPA 2023: Data Subject Rights
    {
        "rule_id": "NDPA-2023-Art45",
        "article": "Article 45",
        "title": "Data Subject Access Requests",
        "description": "Data subjects have the right to access their personal data and receive a copy within 30 days.",
        "category": "data_subject_rights",
        "check_function": "_check_data_subject_access",
        "remediation_template": "dsar",
        "severity_default": "high",
    },
    {
        "rule_id": "NDPA-2023-Art46",
        "article": "Article 46",
        "title": "Right to Rectification",
        "description": "Data subjects have the right to have inaccurate personal data rectified.",
        "category": "data_subject_rights",
        "check_function": "_check_rectification",
        "remediation_template": "rectification",
        "severity_default": "medium",
    },
    {
        "rule_id": "NDPA-2023-Art47",
        "article": "Article 47",
        "title": "Right to Erasure",
        "description": "Data subjects have the right to have their personal data erased (right to be forgotten).",
        "category": "data_subject_rights",
        "check_function": "_check_erasure",
        "remediation_template": "erasure",
        "severity_default": "high",
    },

    # Cross-Border (highest-value rule)
    {
        "rule_id": "NDPA-2023-Art48",
        "article": "Article 48",
        "title": "Cross-Border Data Transfers",
        "description": "Personal data may only be transferred to countries with adequate data protection or appropriate safeguards.",
        "category": "cross_border",
        "check_function": "_check_cross_border_transfers",
        "remediation_template": "cross_border",
        "severity_default": "critical",
    },

    # GAID 2025
    {
        "rule_id": "GAID-2025-Consent",
        "article": "GAID Section 4",
        "title": "GAID Consent Requirements",
        "description": "Granular, auditable consent records with timestamp, scope, and withdrawal capability.",
        "category": "gaid_2025",
        "check_function": "_check_gaid_consent",
        "remediation_template": "gaid_consent",
        "severity_default": "high",
    },
    {
        "rule_id": "GAID-2025-Transparency",
        "article": "GAID Section 6",
        "title": "GAID Transparency Notice",
        "description": "Clear, accessible information about data processing must be provided to data subjects.",
        "category": "gaid_2025",
        "check_function": "_check_gaid_transparency",
        "remediation_template": "gaid_transparency",
        "severity_default": "medium",
    },
    {
        "rule_id": "GAID-2025-Portability",
        "article": "GAID Section 8",
        "title": "GAID Data Portability",
        "description": "Data subjects have the right to receive their data in a structured, machine-readable format.",
        "category": "gaid_2025",
        "check_function": "_check_gaid_data_portability",
        "remediation_template": "gaid_portability",
        "severity_default": "medium",
    },
]