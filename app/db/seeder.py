"""
Database Seeder — Seeds compliance rules, subscription plans, and connector types.
Runs on application startup to ensure the database has required baseline data.
"""
import logging
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.database import (
    ComplianceRule, SubscriptionPlan, ConnectorType,
    SubscriptionTier,
)
from app.core.rules_engine import COMPLIANCE_RULES

logger = logging.getLogger(__name__)


# Subscription plan definitions
SUBSCRIPTION_PLANS = [
    {
        "tier": SubscriptionTier.FREE,
        "name": "Free",
        "description": "Try CAR-Bot with limited features. Good for initial assessment.",
        "price_monthly": 0,
        "price_annually": 0,
        "currency": "NGN",
        "max_connectors": 1,
        "max_users": 2,
        "max_monthly_audits": 1,
        "max_documents": 1,
        "max_storage_gb": 1,
        "features": {
            "continuous_monitoring": False,
            "api_access": False,
            "custom_reports": False,
            "priority_support": False,
            "pii_scanning": True,
        },
        "display_order": 1,
        "is_active": True,
        "is_popular": False,
    },
    {
        "tier": SubscriptionTier.STARTER,
        "name": "Starter",
        "description": "For small businesses that need basic compliance monitoring.",
        "price_monthly": 25000,
        "price_annually": 250000,
        "currency": "NGN",
        "max_connectors": 3,
        "max_users": 5,
        "max_monthly_audits": 3,
        "max_documents": 5,
        "max_storage_gb": 5,
        "features": {
            "continuous_monitoring": False,
            "api_access": True,
            "custom_reports": False,
            "priority_support": False,
            "pii_scanning": True,
        },
        "display_order": 2,
        "is_active": True,
        "is_popular": True,
    },
    {
        "tier": SubscriptionTier.PROFESSIONAL,
        "name": "Professional",
        "description": "For growing companies that need continuous monitoring and reporting.",
        "price_monthly": 75000,
        "price_annually": 750000,
        "currency": "NGN",
        "max_connectors": 10,
        "max_users": 15,
        "max_monthly_audits": 10,
        "max_documents": 20,
        "max_storage_gb": 20,
        "features": {
            "continuous_monitoring": True,
            "api_access": True,
            "custom_reports": True,
            "priority_support": True,
            "pii_scanning": True,
        },
        "display_order": 3,
        "is_active": True,
        "is_popular": True,
    },
    {
        "tier": SubscriptionTier.ENTERPRISE,
        "name": "Enterprise",
        "description": "For large organizations with complex compliance needs.",
        "price_monthly": 200000,
        "price_annually": 2000000,
        "currency": "NGN",
        "max_connectors": -1,  # unlimited
        "max_users": -1,
        "max_monthly_audits": -1,
        "max_documents": -1,
        "max_storage_gb": 100,
        "features": {
            "continuous_monitoring": True,
            "api_access": True,
            "custom_reports": True,
            "priority_support": True,
            "pii_scanning": True,
            "dedicated_account_manager": True,
            "custom_integrations": True,
        },
        "display_order": 4,
        "is_active": True,
        "is_popular": False,
    },
]

# Connector type definitions
CONNECTOR_TYPES = [
    {
        "slug": "postgresql",
        "name": "PostgreSQL Database",
        "description": "Connect to a PostgreSQL database for continuous data auditing.",
        "category": "database",
        "config_schema": {
            "type": "object",
            "required": ["host", "port", "database", "username", "password"],
            "properties": {
                "host": {"type": "string", "title": "Host", "description": "Database server hostname or IP"},
                "port": {"type": "integer", "title": "Port", "default": 5432},
                "database": {"type": "string", "title": "Database Name"},
                "username": {"type": "string", "title": "Username"},
                "password": {"type": "string", "title": "Password", "format": "password"},
                "ssl_mode": {"type": "string", "enum": ["disable", "require", "verify-ca", "verify-full"], "default": "require"},
            },
        },
        "required_fields": ["host", "port", "database", "username", "password"],
        "optional_fields": ["ssl_mode"],
        "supports_realtime": False,
        "supports_polling": True,
        "supports_webhook": False,
        "polling_interval_default": 300,
        "polling_interval_min": 60,
        "polling_interval_max": 86400,
    },
    {
        "slug": "mysql",
        "name": "MySQL Database",
        "description": "Connect to a MySQL database for continuous data auditing.",
        "category": "database",
        "config_schema": {
            "type": "object",
            "required": ["host", "port", "database", "username", "password"],
            "properties": {
                "host": {"type": "string", "title": "Host"},
                "port": {"type": "integer", "title": "Port", "default": 3306},
                "database": {"type": "string", "title": "Database Name"},
                "username": {"type": "string", "title": "Username"},
                "password": {"type": "string", "title": "Password", "format": "password"},
                "ssl": {"type": "boolean", "default": True},
            },
        },
        "required_fields": ["host", "port", "database", "username", "password"],
        "optional_fields": ["ssl"],
        "supports_realtime": False,
        "supports_polling": True,
        "supports_webhook": False,
        "polling_interval_default": 300,
        "polling_interval_min": 60,
        "polling_interval_max": 86400,
    },
    {
        "slug": "mssql",
        "name": "Microsoft SQL Server",
        "description": "Connect to a SQL Server database for continuous data auditing.",
        "category": "database",
        "config_schema": {
            "type": "object",
            "required": ["host", "port", "database", "username", "password"],
            "properties": {
                "host": {"type": "string", "title": "Host"},
                "port": {"type": "integer", "title": "Port", "default": 1433},
                "database": {"type": "string", "title": "Database Name"},
                "username": {"type": "string", "title": "Username"},
                "password": {"type": "string", "title": "Password", "format": "password"},
                "encrypt": {"type": "boolean", "default": True},
            },
        },
        "required_fields": ["host", "port", "database", "username", "password"],
        "optional_fields": ["encrypt"],
        "supports_realtime": False,
        "supports_polling": True,
        "supports_webhook": False,
        "polling_interval_default": 300,
        "polling_interval_min": 60,
        "polling_interval_max": 86400,
    },
    {
        "slug": "mongodb",
        "name": "MongoDB",
        "description": "Connect to a MongoDB instance for continuous data auditing.",
        "category": "database",
        "config_schema": {
            "type": "object",
            "required": ["connection_string"],
            "properties": {
                "connection_string": {"type": "string", "title": "Connection String", "format": "password"},
                "database": {"type": "string", "title": "Database Name"},
            },
        },
        "required_fields": ["connection_string"],
        "optional_fields": ["database"],
        "supports_realtime": False,
        "supports_polling": True,
        "supports_webhook": False,
        "polling_interval_default": 300,
        "polling_interval_min": 60,
        "polling_interval_max": 86400,
    },
    {
        "slug": "rest_api",
        "name": "REST API",
        "description": "Connect to any REST API for data auditing via polling or webhooks.",
        "category": "api",
        "config_schema": {
            "type": "object",
            "required": ["base_url"],
            "properties": {
                "base_url": {"type": "string", "title": "Base URL"},
                "auth_type": {"type": "string", "enum": ["none", "bearer", "basic", "api_key"], "default": "bearer"},
                "auth_token": {"type": "string", "title": "Auth Token", "format": "password"},
                "headers": {"type": "object", "title": "Additional Headers"},
            },
        },
        "required_fields": ["base_url"],
        "optional_fields": ["auth_type", "auth_token", "headers"],
        "supports_realtime": False,
        "supports_polling": True,
        "supports_webhook": True,
        "polling_interval_default": 600,
        "polling_interval_min": 300,
        "polling_interval_max": 86400,
    },
    {
        "slug": "google_drive",
        "name": "Google Drive",
        "description": "Scan Google Drive files for PII and compliance data.",
        "category": "cloud_app",
        "config_schema": {
            "type": "object",
            "required": ["service_account_key", "folder_id"],
            "properties": {
                "service_account_key": {"type": "string", "title": "Service Account Key (JSON)", "format": "password"},
                "folder_id": {"type": "string", "title": "Folder ID to Scan"},
                "file_types": {"type": "array", "items": {"type": "string"}, "default": ["csv", "json", "xlsx", "txt"]},
            },
        },
        "required_fields": ["service_account_key", "folder_id"],
        "optional_fields": ["file_types"],
        "supports_realtime": False,
        "supports_polling": True,
        "supports_webhook": False,
        "polling_interval_default": 3600,
        "polling_interval_min": 1800,
        "polling_interval_max": 86400,
    },
    {
        "slug": "whatsapp_business",
        "name": "WhatsApp Business API",
        "description": "Monitor WhatsApp Business messages for PII exposure.",
        "category": "api",
        "config_schema": {
            "type": "object",
            "required": ["access_token", "phone_number_id"],
            "properties": {
                "access_token": {"type": "string", "title": "WhatsApp API Access Token", "format": "password"},
                "phone_number_id": {"type": "string", "title": "Phone Number ID"},
                "business_account_id": {"type": "string", "title": "Business Account ID"},
                "webhook_verify_token": {"type": "string", "title": "Webhook Verify Token"},
            },
        },
        "required_fields": ["access_token", "phone_number_id"],
        "optional_fields": ["business_account_id", "webhook_verify_token"],
        "supports_realtime": True,
        "supports_polling": False,
        "supports_webhook": True,
        "polling_interval_default": 0,
        "polling_interval_min": 0,
        "polling_interval_max": 0,
    },
]


async def seed_database(db: AsyncSession):
    """
    Seed the database with required baseline data.
    Idempotent — only inserts records that don't already exist.
    """
    logger.info("Starting database seeding...")

    await _seed_compliance_rules(db)
    await _seed_subscription_plans(db)
    await _seed_connector_types(db)

    await db.commit()
    logger.info("Database seeding completed.")


async def _seed_compliance_rules(db: AsyncSession):
    """Seed compliance rules from rules_engine definitions."""
    existing = await db.execute(select(ComplianceRule))
    existing_ids = {r.rule_id for r in existing.scalars().all()}

    seeded = 0
    for rule_data in COMPLIANCE_RULES:
        if rule_data["rule_id"] not in existing_ids:
            rule = ComplianceRule(**rule_data)
            db.add(rule)
            seeded += 1

    if seeded:
        logger.info(f"Seeded {seeded} compliance rules.")


async def _seed_subscription_plans(db: AsyncSession):
    """Seed subscription plans."""
    existing = await db.execute(select(SubscriptionPlan))
    existing_tiers = {r.tier for r in existing.scalars().all()}

    seeded = 0
    for plan_data in SUBSCRIPTION_PLANS:
        if plan_data["tier"] not in existing_tiers:
            plan = SubscriptionPlan(**plan_data)
            db.add(plan)
            seeded += 1

    if seeded:
        logger.info(f"Seeded {seeded} subscription plans.")


async def _seed_connector_types(db: AsyncSession):
    """Seed connector type definitions."""
    existing = await db.execute(select(ConnectorType))
    existing_slugs = {r.slug for r in existing.scalars().all()}

    seeded = 0
    for type_data in CONNECTOR_TYPES:
        if type_data["slug"] not in existing_slugs:
            connector_type = ConnectorType(**type_data)
            db.add(connector_type)
            seeded += 1

    if seeded:
        logger.info(f"Seeded {seeded} connector types.")
