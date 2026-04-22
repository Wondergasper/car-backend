"""
FastAPI application entry point.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.router import router as api_router
from app.core.config import get_settings
from app.middleware import OrganizationMiddleware
from app.db.session import engine, Base, async_session
from app.db.seeder import seed_database
from app.services.scheduler_service import start_scheduler, stop_scheduler
import logging

settings = get_settings()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created.")
    async with async_session() as db:
        try:
            await seed_database(db)
            await db.commit()
        except Exception as e:
            logger.error("Database seeding failed: %s", e, exc_info=True)
            await db.rollback()


async def init_rag():
    """Index regulatory PDFs into ChromaDB on startup (non-blocking)."""
    try:
        from app.core.rag_engine import get_rag_engine
        rag = get_rag_engine()
        if rag.is_ready:
            import asyncio
            loop = asyncio.get_event_loop()
            count = await loop.run_in_executor(None, rag.index_documents)
            logger.info("RAG engine: %d document chunks indexed.", count)
        else:
            logger.warning("RAG engine not available - install sentence-transformers chromadb pypdf")
    except Exception as e:
        logger.warning("RAG indexing skipped: %s", e)


def create_app() -> FastAPI:

    # ── OpenAPI metadata ────────────────────────────────────────────────────
    _description = """
## CAR-Bot Compliance API — v2.0

**CAR-Bot** is a multi-tenant, AI-powered compliance automation platform built for
Nigerian enterprises that must meet **NDPA 2023**, **GAID 2025**, **CBN**, and **NCC** obligations.

Use this API to:
- 🔐 **Authenticate** your organisation and obtain a JWT bearer token
- 🔌 **Connect** your data sources (PostgreSQL, MongoDB, REST APIs, cloud storage)
- 🕵️ **Run compliance audits** — PII scanning, rule evaluation, scoring
- 📋 **Manage findings** — review, bulk-update, and generate AI remediation plans
- 💬 **Chat with the AI** — ask compliance questions grounded in your own data
- 📚 **Search regulatory clauses** via semantic RAG search
- 🔔 **Register webhooks** — receive real-time compliance event notifications
- ⏰ **Schedule audits** — cron-based recurring compliance runs
- 👥 **Manage your team** — invite, role-assign, and deactivate users

---

### Authentication

All protected endpoints require a **Bearer JWT token**:

```
Authorization: Bearer <your_token>
```

Obtain a token via `POST /api/auth/login` or `POST /api/auth/register`.

---

### Third-Party / Headless Usage

This API is designed to be consumed **without the CAR-Bot frontend**.
You can integrate it directly into your own dashboards, CI/CD pipelines, or internal tools.

---

### Rate Limits

| Tier       | Audits/month | API calls/hour |
|------------|-------------|----------------|
| Free       | 10          | 100            |
| Starter    | 50          | 500            |
| Pro        | 200         | 2 000          |
| Enterprise | Unlimited   | Custom         |

---

### Support

- 📧 Email: `api-support@car-bot.ai`
- 📖 Docs: [https://docs.car-bot.ai](https://docs.car-bot.ai)
- 🐛 Issues: [GitHub Issues](https://github.com/car-bot/api/issues)
"""

    _tags_metadata = [
        {
            "name": "Authentication",
            "description": "Register organisations, login users, and manage JWT sessions. "
                           "All other endpoints require the Bearer token returned here.",
            "externalDocs": {
                "description": "Auth guide",
                "url": "https://docs.car-bot.ai/auth",
            },
        },
        {
            "name": "Audits",
            "description": "Trigger, monitor, and retrieve compliance audit runs. "
                           "Audits scan connected data sources against NDPA 2023 / GAID 2025 rule sets.",
        },
        {
            "name": "Connectors",
            "description": "Create and manage data-source connections. "
                           "Connector configs are AES-256 encrypted at rest.",
        },
        {
            "name": "Compliance Rules",
            "description": "Browse the full library of NDPA 2023 compliance rules used by the audit engine.",
        },
        {
            "name": "Webhooks",
            "description": "Receive inbound data-change events from connected sources. "
                           "All requests are HMAC-SHA256 signed for security.",
        },
        {
            "name": "API Keys",
            "description": "Create scoped, rate-limited API keys for machine-to-machine access "
                           "(e.g. CI/CD pipelines, internal tools).",
        },
        {
            "name": "Team Management",
            "description": "Invite team members, assign roles (Owner / Admin / DPO / Analyst / Viewer), "
                           "and deactivate users.",
        },
        {
            "name": "AI Chat",
            "description": "Ask compliance questions in natural language. "
                           "Responses are grounded in your connected data via RAG.",
        },
        {
            "name": "Notifications",
            "description": "Register outgoing webhooks to receive compliance alerts in Slack, "
                           "Microsoft Teams, or any HTTP endpoint.",
        },
        {
            "name": "Scheduled Audits",
            "description": "Schedule recurring audits using standard cron expressions.",
        },
        {
            "name": "RAG - Clause Search",
            "description": "Semantic search across NDPA 2023, GAID 2025, CBN, and NCC regulatory PDFs "
                           "using the embedded vector engine.",
        },
        {
            "name": "Compliance Frameworks",
            "description": "Browse supported compliance frameworks and cross-walk mappings between them.",
        },
        {
            "name": "Documents",
            "description": "Upload and manage organisation documents (policies, evidence files) stored securely.",
        },
    ]

    app = FastAPI(
        title="CAR-Bot Compliance API",
        description=_description,
        version="2.0.0",
        openapi_tags=_tags_metadata,
        contact={
            "name": "CAR-Bot API Support",
            "url": "https://car-bot.ai/support",
            "email": "api-support@car-bot.ai",
        },
        license_info={
            "name": "Proprietary — CAR-Bot Ltd",
            "url": "https://car-bot.ai/terms",
        },
        servers=[
            {"url": "https://car-bot-api.onrender.com", "description": "Production"},
            {"url": "http://localhost:8000",             "description": "Local Development"},
        ],
        docs_url="/docs",
        redoc_url="/redoc",
        swagger_ui_parameters={
            "defaultModelsExpandDepth": -1,      # collapse schemas by default
            "syntaxHighlight.theme": "monokai",
            "tryItOutEnabled": True,
            "persistAuthorization": True,        # JWT survives page refresh
            "displayRequestDuration": True,
            "filter": True,                      # enables search bar
            "deepLinking": True,
        },
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(OrganizationMiddleware)

    if not os.path.exists("media"):
        os.makedirs("media")
    app.mount("/media", StaticFiles(directory="media"), name="media")

    app.include_router(api_router, prefix="/api")

    # ── Inject Bearer JWT security scheme into OpenAPI spec ─────────────────
    # This makes the "Authorize 🔒" button appear in Swagger UI and shows
    # the padlock on every protected endpoint.
    from fastapi.openapi.utils import get_openapi

    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            tags=_tags_metadata,
            contact=app.contact,
            license_info=app.license_info,
            servers=app.servers,
            routes=app.routes,
        )
        # Public endpoints: do not imply Bearer auth in OpenAPI (Swagger UI).
        for path_key, path_item in schema.get("paths", {}).items():
            is_public = (
                path_key == "/health"
                or path_key in ("/api/auth/register", "/api/auth/login")
                or path_key.startswith("/api/badge")
            )
            if is_public:
                for op in path_item.values():
                    if isinstance(op, dict):
                        op["security"] = []

        schema.setdefault("components", {})
        schema["components"]["securitySchemes"] = {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "Paste the JWT token returned by `/api/auth/login`. "
                               "Format: `Bearer <token>`",
            }
        }
        # Apply security globally — every endpoint requires auth by default
        # (public endpoints like /health and /api/auth/* still work since they
        #  have no dependency on get_current_user)
        schema["security"] = [{"BearerAuth": []}]
        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi  # type: ignore

    @app.on_event("startup")
    async def startup():
        try:
            await init_db()
            start_scheduler()
            await init_rag()
            logger.info("CAR-Bot API v2.0 started. Intelligence layer ready.")
        except Exception as e:
            logger.error("Startup failed: %s", e, exc_info=True)
            logger.warning("Continuing with degraded startup.")

    @app.on_event("shutdown")
    async def shutdown():
        stop_scheduler()
        logger.info("CAR-Bot API shutting down.")

    @app.get("/health")
    async def health_check():
        from app.core.rag_engine import get_rag_engine
        rag = get_rag_engine()
        return {
            "status": "healthy",
            "version": "2.0.0",
            "rag_ready": rag.is_ready,
            "rag_chunks": rag.document_count,
        }

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        logger.error("Unhandled exception: %s", exc, exc_info=True)
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

    return app


app = create_app()
