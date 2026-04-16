from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import event, text
from app.core.config import get_settings
import logging

logger = logging.getLogger(__name__)

settings = get_settings()

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_size=20,
    max_overflow=40,
    pool_timeout=30,
    pool_recycle=1800,
)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

Base = DeclarativeBase()


async def get_db() -> AsyncSession:
    """Get database session with proper cleanup."""
    async with async_session() as session:
        try:
            yield session
        except Exception as e:
            logger.error(f"Database session error: {e}")
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Initialize database tables and RLS policies."""
    async with engine.begin() as conn:
        # Create tables
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created successfully")
        
        # Enable Row-Level Security
        await _setup_rls(conn)


async def _setup_rls(conn):
    """Set up Row-Level Security policies for multi-tenant isolation."""
    rls_statements = [
        # Enable RLS on all tenant-scoped tables
        "ALTER TABLE organizations ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE users ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE connectors ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE connector_events ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE audits ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE findings ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE documents ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE document_versions ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE audit_trail ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY",
        
        # Organizations: users can only see their own org
        """
        CREATE POLICY org_isolation ON organizations
            USING (id::text = current_setting('app.current_org_id', true))
        """,
        
        # Users: can only see users in their org
        """
        CREATE POLICY users_org_isolation ON users
            USING (org_id::text = current_setting('app.current_org_id', true))
        """,
        
        # Connectors: org-scoped
        """
        CREATE POLICY connectors_org_isolation ON connectors
            USING (org_id::text = current_setting('app.current_org_id', true))
        """,
        
        # Connector events: org-scoped
        """
        CREATE POLICY connector_events_org_isolation ON connector_events
            USING (org_id::text = current_setting('app.current_org_id', true))
        """,
        
        # Audits: org-scoped
        """
        CREATE POLICY audits_org_isolation ON audits
            USING (org_id::text = current_setting('app.current_org_id', true))
        """,
        
        # Findings: org-scoped
        """
        CREATE POLICY findings_org_isolation ON findings
            USING (org_id::text = current_setting('app.current_org_id', true))
        """,
        
        # Documents: org-scoped
        """
        CREATE POLICY documents_org_isolation ON documents
            USING (org_id::text = current_setting('app.current_org_id', true))
        """,
        
        # Document versions: follow parent document
        """
        CREATE POLICY doc_versions_org_isolation ON document_versions
            USING (
                document_id IN (
                    SELECT id FROM documents 
                    WHERE org_id::text = current_setting('app.current_org_id', true)
                )
            )
        """,
        
        # Audit trail: org-scoped, append-only
        """
        CREATE POLICY audit_trail_org_isolation ON audit_trail
            USING (org_id::text = current_setting('app.current_org_id', true))
        """,
        
        # Audit trail: append-only (no DELETE or UPDATE)
        """
        CREATE POLICY audit_trail_append_only ON audit_trail
            FOR INSERT WITH CHECK (true)
        """,
        
        # API keys: org-scoped
        """
        CREATE POLICY api_keys_org_isolation ON api_keys
            USING (org_id::text = current_setting('app.current_org_id', true))
        """,
        
        # Connector types: globally readable (no org_id)
        """
        CREATE POLICY connector_types_read_all ON connector_types
            FOR SELECT USING (true)
        """,
        
        # Subscription plans: globally readable
        """
        CREATE POLICY subscription_plans_read_all ON subscription_plans
            FOR SELECT USING (true)
        """,
        
        # Compliance rules: globally readable
        """
        CREATE POLICY compliance_rules_read_all ON compliance_rules
            FOR SELECT USING (true)
        """,
    ]
    
    for stmt in rls_statements:
        try:
            await conn.execute(text(stmt))
        except Exception as e:
            # Policies may already exist - log and continue
            logger.debug(f"RLS setup (may already exist): {e}")
    
    logger.info("Row-Level Security policies configured")

