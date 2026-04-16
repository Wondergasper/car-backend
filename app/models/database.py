"""
CAR-Bot Database Models
Multi-tenant architecture with Row-Level Security (RLS)
All tenant-scoped tables include org_id for data isolation.
"""
from sqlalchemy import (
    Column, String, DateTime, Boolean, Text, JSON, Integer, 
    ForeignKey, Numeric, Enum as SAEnum, BigInteger, Index, CheckConstraint
)
from sqlalchemy.dialects.postgresql import UUID, BYTEA, JSONB
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
import enum
from app.db.session import Base


# ==================== Enums ====================

class UserRole(str, enum.Enum):
    OWNER = "owner"
    ADMIN = "admin"
    DPO = "dpo"  # Data Protection Officer
    ANALYST = "analyst"
    VIEWER = "viewer"


class ConnectorStatus(str, enum.Enum):
    INACTIVE = "inactive"
    ACTIVE = "active"
    ERROR = "error"
    DEGRADED = "degraded"
    MAINTENANCE = "maintenance"


class AuditStatus(str, enum.Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AuditType(str, enum.Enum):
    FULL = "full"
    INCREMENTAL = "incremental"
    TARGETED = "targeted"
    SCHEDULED = "scheduled"


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    IN_REVIEW = "in_review"
    ACCEPTED = "accepted"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class SubscriptionTier(str, enum.Enum):
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class DocumentType(str, enum.Enum):
    CAR_REPORT = "car_report"
    PRIVACY_POLICY = "privacy_policy"
    DPA_TEMPLATE = "dpa_template"
    ROPA_RECORD = "ropa_record"
    CUSTOM = "custom"


class AuditTrailAction(str, enum.Enum):
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    LOGIN = "login"
    LOGOUT = "logout"
    CONNECTOR_ADD = "connector_add"
    CONNECTOR_REMOVE = "connector_remove"
    AUDIT_START = "audit_start"
    AUDIT_COMPLETE = "audit_complete"
    REPORT_GENERATE = "report_generate"
    REPORT_DOWNLOAD = "report_download"
    API_KEY_CREATE = "api_key_create"
    API_KEY_REVOKE = "api_key_revoke"
    SETTINGS_CHANGE = "settings_change"


# ==================== New Tables ====================

class Organization(Base):
    """
    Tenant boundary - each org is isolated from others.
    All data belongs to exactly one organization.
    """
    __tablename__ = "organizations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), unique=True, nullable=False, index=True)  # URL-friendly identifier
    industry = Column(String(100))
    size = Column(Integer)  # employee count
    website = Column(String(255))
    
    # DPO Information (required by NDPA 2023)
    dpo_name = Column(String(255))
    dpo_email = Column(String(255))
    dpo_phone = Column(String(50))
    
    # Address
    address_line1 = Column(String(255))
    address_line2 = Column(String(255))
    city = Column(String(100))
    state = Column(String(100))
    country = Column(String(100), default="Nigeria")
    
    # Subscription
    subscription_tier = Column(SAEnum(SubscriptionTier), default=SubscriptionTier.FREE)
    subscription_status = Column(String(50), default="active")  # active, past_due, canceled, trialing
    stripe_customer_id = Column(String(255))
    subscription_ends_at = Column(DateTime(timezone=True))
    
    # Limits (based on tier)
    max_connectors = Column(Integer, default=3)
    max_users = Column(Integer, default=5)
    max_monthly_audits = Column(Integer, default=10)
    
    # Metadata
    settings = Column(JSONB, default=dict)  # org-level settings
    metadata = Column(JSONB, default=dict)  # custom metadata
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    deleted_at = Column(DateTime(timezone=True))  # soft delete
    
    # Relationships
    users = relationship("User", back_populates="organization")
    connectors = relationship("Connector", back_populates="organization")
    audits = relationship("Audit", back_populates="organization")
    findings = relationship("Finding", back_populates="organization")
    documents = relationship("Document", back_populates="organization")
    api_keys = relationship("APIKey", back_populates="organization")
    audit_trail = relationship("AuditTrail", back_populates="organization")

    __table_args__ = (
        Index("idx_org_slug", "slug"),
    )


class APIKey(Base):
    """
    SDK authentication - scoped keys for connector access.
    Uses HMAC-SHA256 for request authentication.
    """
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    key_prefix = Column(String(16), nullable=False, index=True)  # First 16 chars for identification
    key_hash = Column(String(64), nullable=False, unique=True, index=True)  # SHA-256 hash of the full key
    key_salt = Column(String(64), nullable=False)  # Salt for HMAC
    
    # Scoping
    permissions = Column(JSONB, default=dict)  # {"connectors": ["read", "write"], "audits": ["read"]}
    allowed_ips = Column(JSONB)  # IP whitelist
    rate_limit = Column(Integer, default=1000)  # requests per hour
    
    # Status
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime(timezone=True))
    expires_at = Column(DateTime(timezone=True))
    
    # Tracking
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    revoked_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    revoked_at = Column(DateTime(timezone=True))
    revoked_reason = Column(String(255))
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    organization = relationship("Organization", back_populates="api_keys")
    creator = relationship("User", foreign_keys=[created_by])


class ConnectorType(Base):
    """
    Registry of supported connector types with configuration schemas.
    Used for validation and dynamic UI generation.
    """
    __tablename__ = "connector_types"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug = Column(String(100), unique=True, nullable=False, index=True)  # e.g., "postgresql", "mongodb"
    name = Column(String(255), nullable=False)
    description = Column(Text)
    category = Column(String(100))  # database, api, file, cloud_app
    
    # Configuration
    config_schema = Column(JSONB, nullable=False)  # JSON Schema for connection config
    required_fields = Column(JSONB, nullable=False, default=list)
    optional_fields = Column(JSONB, nullable=False, default=list)
    
    # Capabilities
    supports_realtime = Column(Boolean, default=False)
    supports_polling = Column(Boolean, default=True)
    supports_webhook = Column(Boolean, default=False)
    polling_interval_default = Column(Integer, default=300)  # seconds
    polling_interval_min = Column(Integer, default=60)
    polling_interval_max = Column(Integer, default=86400)
    
    # Status
    is_active = Column(Boolean, default=True)
    is_beta = Column(Boolean, default=False)
    version = Column(String(50))
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    __table_args__ = (
        Index("idx_connector_type_slug", "slug"),
    )


class ConnectorEvent(Base):
    """
    Replaces webhook_events - immutable event log with payload hashing.
    Partitioned by created_at for performance.
    """
    __tablename__ = "connector_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    connector_id = Column(UUID(as_uuid=True), ForeignKey("connectors.id"), nullable=False, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    
    # Event data
    event_type = Column(String(100), nullable=False)  # data_update, schema_change, sync_complete
    payload_hash = Column(String(64), nullable=False, index=True)  # SHA-256 hash of payload
    payload_size = Column(Integer, nullable=False)  # size in bytes
    payload_sample = Column(Text)  # First 1000 chars for debugging
    
    # Processing
    processed = Column(Boolean, default=False)
    processed_at = Column(DateTime(timezone=True))
    processing_error = Column(Text)
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    
    # Idempotency
    idempotency_key = Column(String(255), index=True)  # Prevent duplicate processing
    
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    
    # Relationships
    connector = relationship("Connector", back_populates="events")
    organization = relationship("Organization")

    __table_args__ = (
        Index("idx_connector_events_org_time", "org_id", "created_at"),
        Index("idx_connector_events_connector_time", "connector_id", "created_at"),
    )


class Document(Base):
    """
    Document Studio outputs - CAR reports, privacy policies, etc.
    """
    __tablename__ = "documents"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    audit_id = Column(UUID(as_uuid=True), ForeignKey("audits.id"))
    
    # Document info
    document_type = Column(SAEnum(DocumentType), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Content
    content = Column(JSONB)  # Structured document content
    content_html = Column(Text)  # Rendered HTML
    template_id = Column(String(100))  # Template used for generation
    
    # Storage
    storage_key = Column(String(500))  # S3/R2 key for PDF
    storage_url = Column(String(500))  # Public/presigned URL
    
    # Status
    status = Column(String(50), default="draft")  # draft, generated, approved, published, archived
    version = Column(Integer, default=1)
    current_version_id = Column(UUID(as_uuid=True), ForeignKey("document_versions.id"))
    
    # Generation
    generated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    generated_at = Column(DateTime(timezone=True))
    ai_assisted = Column(Boolean, default=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    organization = relationship("Organization", back_populates="documents")
    audit = relationship("Audit")
    versions = relationship("DocumentVersion", back_populates="document")
    generated_by_user = relationship("User", foreign_keys=[generated_by])


class DocumentVersion(Base):
    """
    Version history with content hashing for audit trail.
    """
    __tablename__ = "document_versions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    document_id = Column(UUID(as_uuid=True), ForeignKey("documents.id"), nullable=False, index=True)
    version_number = Column(Integer, nullable=False)
    
    # Content
    content = Column(JSONB, nullable=False)
    content_hash = Column(String(64), nullable=False)  # SHA-256 of content
    
    # Changes
    change_summary = Column(Text)  # What changed in this version
    changed_fields = Column(JSONB)  # List of changed fields
    
    # Metadata
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    document = relationship("Document", back_populates="versions")
    creator = relationship("User")

    __table_args__ = (
        Index("idx_doc_version_doc_id_version", "document_id", "version_number", unique=True),
    )


class AuditTrail(Base):
    """
    Immutable append-only system action log.
    No UPDATE or DELETE operations allowed.
    """
    __tablename__ = "audit_trail"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    api_key_id = Column(UUID(as_uuid=True), ForeignKey("api_keys.id"))
    
    # Action details
    action = Column(SAEnum(AuditTrailAction), nullable=False)
    resource_type = Column(String(100))  # connector, audit, document, user, api_key
    resource_id = Column(UUID(as_uuid=True))
    
    # Context
    ip_address = Column(String(45))  # IPv6 max length
    user_agent = Column(String(500))
    request_id = Column(String(100), index=True)  # Correlate with logs
    
    # Data
    old_values = Column(JSONB)  # Before state (if applicable)
    new_values = Column(JSONB)  # After state (if applicable)
    metadata = Column(JSONB)  # Additional context
    
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)

    __table_args__ = (
        Index("idx_audit_trail_org_time", "org_id", "created_at"),
        CheckConstraint(
            "old_values IS NULL OR jsonb_typeof(old_values) = 'object'",
            name="check_old_values_json"
        ),
    )


class SubscriptionPlan(Base):
    """
    Billing plans - defines limits, pricing, and features.
    """
    __tablename__ = "subscription_plans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tier = Column(SAEnum(SubscriptionTier), unique=True, nullable=False)
    name = Column(String(100), nullable=False)
    description = Column(Text)
    
    # Pricing
    price_monthly = Column(Numeric(10, 2))
    price_annually = Column(Numeric(10, 2))
    currency = Column(String(3), default="NGN")
    stripe_price_id = Column(String(255))
    
    # Limits
    max_connectors = Column(Integer, nullable=False)
    max_users = Column(Integer, nullable=False)
    max_monthly_audits = Column(Integer, nullable=False)
    max_documents = Column(Integer)
    max_storage_gb = Column(Integer)
    
    # Features
    features = Column(JSONB, nullable=False, default=dict)
    # e.g., {
    #     "continuous_monitoring": true,
    #     "api_access": true,
    #     "custom_reports": false,
    #     "priority_support": false
    # }
    
    # Display
    display_order = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    is_popular = Column(Boolean, default=False)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())


# ==================== Existing Tables (Upgraded) ====================

class User(Base):
    """
    User accounts - now scoped to organizations with roles.
    """
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    role = Column(SAEnum(UserRole), default=UserRole.VIEWER, nullable=False)
    
    # Status
    is_active = Column(Boolean, default=True)
    email_verified = Column(Boolean, default=False)
    email_verified_at = Column(DateTime(timezone=True))
    
    # Tracking
    last_login_at = Column(DateTime(timezone=True))
    last_login_ip = Column(String(45))
    login_count = Column(Integer, default=0)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    deleted_at = Column(DateTime(timezone=True))  # soft delete
    
    # Relationships
    organization = relationship("Organization", back_populates="users")
    created_api_keys = relationship("APIKey", foreign_keys="APIKey.created_by")
    revoked_api_keys = relationship("APIKey", foreign_keys="APIKey.revoked_by")


class Connector(Base):
    """
    Data source connections - now org-scoped with health monitoring.
    """
    __tablename__ = "connectors"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    
    name = Column(String(255), nullable=False)
    connector_type_id = Column(UUID(as_uuid=True), ForeignKey("connector_types.id"), nullable=False)
    
    # Encrypted configuration (BYTEA for encryption)
    config_encrypted = Column(BYTEA, nullable=False)
    config_encryption_iv = Column(BYTEA)  # Initialization vector
    
    # Status & Health
    status = Column(SAEnum(ConnectorStatus), default=ConnectorStatus.INACTIVE)
    health_status = Column(String(50), default="unknown")  # healthy, degraded, unhealthy, unknown
    last_health_check = Column(DateTime(timezone=True))
    health_check_error = Column(Text)
    
    # Sync settings
    sync_enabled = Column(Boolean, default=True)
    sync_interval = Column(Integer, default=300)  # seconds
    last_sync_at = Column(DateTime(timezone=True))
    last_sync_status = Column(String(50))  # success, partial, failed
    last_sync_error = Column(Text)
    sync_records_count = Column(BigInteger, default=0)
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    deleted_at = Column(DateTime(timezone=True))  # soft delete
    
    # Relationships
    organization = relationship("Organization", back_populates="connectors")
    creator = relationship("User")
    connector_type = relationship("ConnectorType")
    events = relationship("ConnectorEvent", back_populates="connector", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="connector")

    __table_args__ = (
        Index("idx_connector_org_status", "org_id", "status"),
    )


class Audit(Base):
    """
    Compliance audit runs - now org-scoped with detailed tracking.
    """
    __tablename__ = "audits"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    initiated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    
    name = Column(String(255), nullable=False)
    audit_type = Column(SAEnum(AuditType), default=AuditType.FULL)
    scope = Column(JSONB)  # {"connectors": ["id1", "id2"], "rules": ["rule1", "rule2"]}
    
    status = Column(SAEnum(AuditStatus), default=AuditStatus.PENDING)
    progress = Column(Numeric(5, 2), default=0)  # 0.00 to 100.00
    
    # Results
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    compliance_score = Column(Integer)  # 0-100
    
    # Report
    report_storage_key = Column(String(500))  # S3/R2 key
    report_generated_at = Column(DateTime(timezone=True))
    
    # Timing
    started_at = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))
    estimated_completion = Column(DateTime(timezone=True))
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    organization = relationship("Organization", back_populates="audits")
    initiator = relationship("User")
    findings = relationship("Finding", back_populates="audit")
    documents = relationship("Document", back_populates="audit")


class Finding(Base):
    """
    Audit findings - now org-scoped with evidence and resolution tracking.
    """
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    audit_id = Column(UUID(as_uuid=True), ForeignKey("audits.id"), nullable=False, index=True)
    org_id = Column(UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False, index=True)
    connector_id = Column(UUID(as_uuid=True), ForeignKey("connectors.id"))
    
    rule_id = Column(String(100), ForeignKey("compliance_rules.rule_id"), nullable=False)
    severity = Column(SAEnum(FindingSeverity), nullable=False)
    
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)
    
    # Evidence
    evidence = Column(JSONB)  # Proof of finding (sample data, logs, screenshots)
    affected_records = Column(BigInteger)  # Estimated count of affected records
    
    # Resolution
    status = Column(SAEnum(FindingStatus), default=FindingStatus.OPEN)
    auto_fixable = Column(Boolean, default=False)
    auto_fix_suggestion = Column(Text)  # AI-generated fix
    resolution_notes = Column(Text)
    resolved_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    resolved_at = Column(DateTime(timezone=True))
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    audit = relationship("Audit", back_populates="findings")
    organization = relationship("Organization", back_populates="findings")
    connector = relationship("Connector", back_populates="findings")
    resolver = relationship("User", foreign_keys=[resolved_by])


class ComplianceRule(Base):
    """
    NDPA 2023 compliance rules - upgraded with check functions.
    """
    __tablename__ = "compliance_rules"

    rule_id = Column(String(100), primary_key=True, nullable=False, index=True)  # Changed from UUID
    article = Column(String(100), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(100))  # data_privacy, access_control, retention, etc.
    
    # Execution
    check_function = Column(String(255))  # Function name in rules_engine.py
    remediation_template = Column(Text)  # Template for generating fixes
    
    # Defaults
    severity_default = Column(SAEnum(FindingSeverity), default=FindingSeverity.HIGH)
    is_active = Column(Boolean, default=True)
    
    # Versioning
    superseded_by = Column(String(100), ForeignKey("compliance_rules.rule_id"))
    effective_from = Column(DateTime(timezone=True))
    effective_to = Column(DateTime(timezone=True))
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    __table_args__ = (
        Index("idx_compliance_rules_active", "rule_id", "is_active"),
    )
