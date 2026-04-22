"""
Pydantic schemas for API validation - upgraded for multi-tenant architecture.
"""
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from uuid import UUID
from app.models.database import UserRole, ConnectorStatus, AuditStatus, AuditType, FindingSeverity, FindingStatus, SubscriptionTier, DocumentType


# Auth Schemas
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=100)
    company_name: str = Field(min_length=2, max_length=255)
    rc_number: str = Field(min_length=4, max_length=100)
    registration_role: str = Field(min_length=3, max_length=100)
    industry: Optional[str] = Field(default=None, max_length=100)
    size: Optional[int] = Field(default=None)


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: UUID
    org_id: UUID
    email: str
    full_name: str
    role: UserRole
    is_active: bool

    class Config:
        from_attributes = True


class Token(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse


# Organization Schemas
class OrganizationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    industry: Optional[str] = None
    size: Optional[int] = None
    dpo_name: Optional[str] = None
    dpo_email: Optional[str] = None


class OrganizationUpdate(BaseModel):
    name: Optional[str] = None
    industry: Optional[str] = None
    size: Optional[int] = None
    website: Optional[str] = None
    rc_number: Optional[str] = None
    registration_role: Optional[str] = None
    dpo_name: Optional[str] = None
    dpo_email: Optional[str] = None
    dpo_phone: Optional[str] = None
    address_line1: Optional[str] = None
    address_line2: Optional[str] = None
    city: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None
    # Shallow-merged into existing org.settings (e.g. onboarding_frameworks)
    settings: Optional[Dict[str, Any]] = None


class OrganizationResponse(BaseModel):
    id: UUID
    name: str
    slug: str
    industry: Optional[str]
    size: Optional[int]
    website: Optional[str] = None
    rc_number: Optional[str] = None
    registration_role: Optional[str] = None
    dpo_name: Optional[str] = None
    dpo_email: Optional[str] = None
    dpo_phone: Optional[str] = None
    verification_status: Optional[str] = None
    verification_provider: Optional[str] = None
    verification_entity_name: Optional[str] = None
    subscription_tier: SubscriptionTier
    max_connectors: int
    max_users: int
    max_monthly_audits: int

    class Config:
        from_attributes = True


# Connector Schemas
class ConnectorCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    connector_type_id: UUID
    config: dict
    sync_interval: Optional[int] = Field(default=300, ge=60, le=86400)
    webhook_secret: Optional[str] = None


class ConnectorUpdate(BaseModel):
    name: Optional[str] = None
    config: Optional[dict] = None
    status: Optional[ConnectorStatus] = None
    sync_interval: Optional[int] = None
    sync_enabled: Optional[bool] = None
    webhook_secret: Optional[str] = None


class ConnectorResponse(BaseModel):
    id: UUID
    org_id: UUID
    name: str
    connector_type_id: UUID
    status: ConnectorStatus
    health_status: str
    last_sync_at: Optional[datetime]
    sync_enabled: bool
    sync_interval: int
    created_at: datetime

    class Config:
        from_attributes = True


# API Key Schemas
class APIKeyCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    permissions: Optional[dict] = None
    allowed_ips: Optional[list] = None
    rate_limit: Optional[int] = Field(default=1000, ge=100, le=10000)
    expires_at: Optional[datetime] = None


class APIKeyResponse(BaseModel):
    id: UUID
    org_id: UUID
    name: str
    key_prefix: str
    permissions: dict
    is_active: bool
    last_used_at: Optional[datetime]
    expires_at: Optional[datetime]
    created_at: datetime
    
    # Full key only shown once on creation
    full_key: Optional[str] = None

    class Config:
        from_attributes = True


# Audit Schemas
class AuditGenerate(BaseModel):
    name: Optional[str] = None
    audit_type: AuditType = AuditType.FULL
    scope: Optional[dict] = None  # {"connectors": [...], "rules": [...]}


class AuditResponse(BaseModel):
    id: UUID
    org_id: UUID
    name: str
    audit_type: AuditType
    status: AuditStatus
    progress: float
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    compliance_score: Optional[int]
    scope: Optional[Dict[str, Any]] = None
    report_storage_key: Optional[str] = None
    report_generated_at: Optional[datetime] = None
    created_at: datetime
    completed_at: Optional[datetime]

    class Config:
        from_attributes = True


class FindingResponse(BaseModel):
    id: UUID
    audit_id: UUID
    org_id: UUID
    connector_id: Optional[UUID]
    rule_id: str
    severity: FindingSeverity
    title: str
    description: str
    recommendation: str
    status: FindingStatus
    auto_fixable: bool
    auto_fix_suggestion: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = None
    affected_records: Optional[int] = None
    resolution_notes: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# Document Schemas
class DocumentCreate(BaseModel):
    document_type: DocumentType
    title: str = Field(min_length=2, max_length=255)
    description: Optional[str] = None
    audit_id: Optional[UUID] = None


class DocumentUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=2, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = Field(None, max_length=50)


class DocumentAnalysisSummary(BaseModel):
    headline: str
    document_preview: Optional[str] = None
    total_findings: int = 0
    by_category: Dict[str, int] = {}
    by_risk_level: Dict[str, int] = {}
    high_risk_locations: List[str] = []
    top_findings: List[Dict[str, Any]] = []
    recommendations: List[str] = []


class DocumentResponse(BaseModel):
    id: UUID
    org_id: UUID
    audit_id: Optional[UUID] = None
    document_type: DocumentType
    title: str
    description: Optional[str] = None
    status: str
    version: int
    storage_url: Optional[str]
    analysis_status: Optional[str] = None
    analysis_mode: Optional[str] = None
    latest_analysis: Optional[DocumentAnalysisSummary] = None
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# Rule Schemas
class RuleResponse(BaseModel):
    rule_id: str
    article: str
    title: str
    description: str
    category: Optional[str]
    severity_default: FindingSeverity
    is_active: bool

    class Config:
        from_attributes = True


# Subscription Schemas
class SubscriptionPlanResponse(BaseModel):
    tier: SubscriptionTier
    name: str
    description: str
    price_monthly: Optional[float]
    price_annually: Optional[float]
    max_connectors: int
    max_users: int
    max_monthly_audits: int
    features: dict
    is_popular: bool

    class Config:
        from_attributes = True
