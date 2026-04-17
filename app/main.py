"""
FastAPI application entry point for Render deployment.
This module is imported by the ASGI server (uvicorn) to start the application.
"""
import sys
import os

# Add parent directory to path so we can import from root modules
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
import logging

settings = get_settings()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def init_db():
    """Create tables and seed baseline data on startup."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created.")

    async with async_session() as db:
        try:
            await seed_database(db)
            await db.commit()
        except Exception as e:
            logger.error(f"Database seeding failed: {e}", exc_info=True)
            await db.rollback()


def create_app() -> FastAPI:
    app = FastAPI(
        title="CAR-Bot API",
        description="Compliance Audit & Reporting Bot API based on NDPA 2023",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://localhost:3001"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(OrganizationMiddleware)

    if not os.path.exists("media"):
        os.makedirs("media")
    app.mount("/media", StaticFiles(directory="media"), name="media")

    app.include_router(api_router, prefix="/api")

    @app.on_event("startup")
    async def startup():
        try:
            await init_db()
            logger.info("CAR-Bot API started.")
        except Exception as e:
            logger.error(f"Startup initialization failed: {e}", exc_info=True)
            # Don't crash - continue without database seeding
            logger.warning("Continuing without database initialization.")

    @app.get("/health")
    async def health_check():
        return {"status": "healthy", "version": "1.0.0"}

    @app.exception_handler(Exception)
    async def generic_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled exception: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    return app


app = create_app()
