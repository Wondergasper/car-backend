"""
conftest.py – shared fixtures for the entire CAR-Bot test suite.

Strategy
--------
* Uses an in-memory SQLite database (via aiosqlite) so tests run without
  any live Supabase / PostgreSQL instance.
* Patches every heavyweight optional dependency (sentence-transformers,
  chromadb, torch, APScheduler, Resend) with lightweight stubs so the
  test suite boots even on a bare Python install.
* Provides a pre-registered Organisation + Owner user with a valid JWT token
  so individual tests can call protected endpoints immediately.
"""

import asyncio
import hashlib
import hmac as _hmac
import json
import os
import sys
import types
import uuid
from datetime import datetime, timedelta, timezone
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from jose import jwt
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# ── Ensure project root is on sys.path ────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# ── UUID → SQLite-compatible TypeDecorator (MUST be first, before model imports)
# postgresql.UUID(as_uuid=True) uses .hex on bind which SQLite can't handle.
# We swap it for a TypeDecorator that round-trips as VARCHAR(36).
import uuid as _uuid_mod
from sqlalchemy.types import TypeDecorator, String as _SA_String
import sqlalchemy.dialects.postgresql as _pg_dialect

class _SQLiteCompatUUID(TypeDecorator):
    """Stores UUIDs as VARCHAR(36) strings — works with SQLite & PostgreSQL."""
    impl = _SA_String(36)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        try:
            return _uuid_mod.UUID(str(value))
        except (ValueError, AttributeError):
            return value

# Patch before any model is imported
_pg_dialect.UUID = _SQLiteCompatUUID  # type: ignore

# ── Lightweight stubs for optional heavy deps ──────────────────────────────────

def _make_stub(name: str) -> types.ModuleType:
    mod = types.ModuleType(name)
    mod.__spec__ = None  # type: ignore
    return mod


def _patch_optional_deps():
    """Pre-register stubs before the app imports them."""
    heavy = [
        # DB drivers (not needed - we use aiosqlite)
        "asyncpg",
        "psycopg",
        "psycopg_binary",
        # AI / ML
        "torch", "transformers", "accelerate",
        "sentence_transformers",
        "chromadb",
        "pypdf", "PyPDF2",
        "evidently",
        # Google AI
        "google",
        "google.generativeai",
        "google.ai",
        # Notification / storage
        "resend",
        "reportlab",
        "reportlab.lib",
        "reportlab.platypus",
        # Scheduler
        "apscheduler",
        "apscheduler.schedulers",
        "apscheduler.schedulers.background",
        "apscheduler.schedulers.asyncio",
        "apscheduler.schedulers.blocking",
        "apscheduler.triggers",
        "apscheduler.triggers.cron",
        "apscheduler.triggers.interval",
        "apscheduler.triggers.date",
        "apscheduler.executors",
        "apscheduler.executors.pool",
        "apscheduler.jobstores",
        "apscheduler.jobstores.base",
        "apscheduler.events",
    ]
    for pkg in heavy:
        if pkg not in sys.modules:
            sys.modules[pkg] = _make_stub(pkg)

    # APScheduler stubs  -- patch every class that might be imported
    _sched_classes = {
        "apscheduler.schedulers.background":  ["BackgroundScheduler"],
        "apscheduler.schedulers.asyncio":     ["AsyncIOScheduler"],
        "apscheduler.schedulers.blocking":    ["BlockingScheduler"],
        "apscheduler.triggers.cron":          ["CronTrigger"],
        "apscheduler.triggers.interval":      ["IntervalTrigger"],
        "apscheduler.triggers.date":          ["DateTrigger"],
        "apscheduler.executors.pool":         ["ThreadPoolExecutor", "ProcessPoolExecutor"],
        "apscheduler.jobstores.base":         ["BaseJobStore"],
        "apscheduler.events":                 ["JobExecutionEvent", "EVENT_JOB_EXECUTED", "EVENT_JOB_ERROR"],
    }
    for mod_name, attrs in _sched_classes.items():
        mod = sys.modules.get(mod_name)
        if mod:
            for attr in attrs:
                if not hasattr(mod, attr):
                    setattr(mod, attr, MagicMock)

    # Sentence-transformers stub
    st = sys.modules["sentence_transformers"]
    st.SentenceTransformer = MagicMock  # type: ignore

    # ChromaDB stub
    chroma = sys.modules["chromadb"]

    class _FakeCollection:
        def add(self, *a, **kw): pass
        def query(self, *a, **kw):
            return {"documents": [[]], "metadatas": [[]], "distances": [[]]}
        def count(self): return 0

    chroma.Client = MagicMock(return_value=MagicMock(
        get_or_create_collection=MagicMock(return_value=_FakeCollection())
    ))
    chroma.PersistentClient = chroma.Client

    # evidently stub
    evidently = sys.modules["evidently"]
    evidently.Report = MagicMock  # type: ignore

    # resend stub
    resend = sys.modules["resend"]
    resend.Emails = MagicMock  # type: ignore
    resend.api_key = ""


_patch_optional_deps()

# ── Postgres-only type shims for SQLite ────────────────────────────────────────
# SQLite knows nothing about JSONB, BYTEA, etc.  Teach its compiler to render
# each of them using its closest native equivalent so create_all() succeeds.
from sqlalchemy.dialects.sqlite.base import SQLiteTypeCompiler
from sqlalchemy import LargeBinary as _LargeBinary, JSON as _JSON, String as _String

_TYPE_MAP = {
    "visit_JSONB":  lambda self, type_, **kw: "JSON",
    "visit_BYTEA":  lambda self, type_, **kw: "BLOB",
    "visit_UUID":   lambda self, type_, **kw: "VARCHAR(36)",
    "visit_INET":   lambda self, type_, **kw: "VARCHAR(45)",
    "visit_CIDR":   lambda self, type_, **kw: "VARCHAR(45)",
    "visit_TSVECTOR": lambda self, type_, **kw: "TEXT",
    "visit_ARRAY":  lambda self, type_, **kw: "TEXT",
}
for _method, _impl in _TYPE_MAP.items():
    if not hasattr(SQLiteTypeCompiler, _method):
        setattr(SQLiteTypeCompiler, _method, _impl)  # type: ignore

# ── UUID → String TypeDecorator for SQLite ────────────────────────────────────
# The model uses UUID(as_uuid=True) which expects objects with .hex etc.
# For SQLite we store/retrieve UUIDs as plain strings.
import uuid as _uuid_module
from sqlalchemy.types import TypeDecorator, String as _SAString

class _SQLiteUUID(TypeDecorator):
    """Stores UUID as a VARCHAR(36) string in SQLite."""
    impl = _SAString(36)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, _uuid_module.UUID):
            return str(value)
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if not isinstance(value, _uuid_module.UUID):
            try:
                return _uuid_module.UUID(str(value))
            except (ValueError, AttributeError):
                return value
        return value

# Monkey-patch postgresql.UUID so SQLite tests use _SQLiteUUID instead
import sqlalchemy.dialects.postgresql as _pg_dialect
_pg_dialect.UUID = _SQLiteUUID  # type: ignore

# Also patch it in the already-imported models module if it exists
try:
    import app.models.database as _models_mod
    # Re-visit all columns that use UUID and swap in _SQLiteUUID
    # (they've already been set; this ensures new column types resolve correctly)
except ImportError:
    pass

# ── NOW import the app and its internals ───────────────────────────────────────
from app.core.config import get_settings
from app.db.session import Base, get_db
from app.models.database import Organization, User, UserRole
import app.core.security as _security_mod

# ── Patch passlib bcrypt (passlib 1.7.4 + bcrypt 5.x python 3.14 bug) ─────────
# On Python 3.14 passlib probes bcrypt with a >72 byte string which bcrypt 5.x
# rejects. Replace get_password_hash and verify_password with direct bcrypt calls.
import bcrypt as _bcrypt

def _safe_hash(password: str) -> str:
    return _bcrypt.hashpw(password.encode(), _bcrypt.gensalt()).decode()

def _safe_verify(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False

_security_mod.get_password_hash = _safe_hash  # type: ignore
_security_mod.verify_password = _safe_verify   # type: ignore

# Re-export for conftest-level use
get_password_hash = _safe_hash
create_access_token = _security_mod.create_access_token

settings = get_settings()


# ── In-memory SQLite engine ────────────────────────────────────────────────────
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSessionLocal = sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def event_loop():
    """Single event loop for the entire session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def create_tables():
    """Create all tables once per test session.

    Strips Postgres-only CHECK constraints (e.g. jsonb_typeof) that SQLite
    cannot execute, using SQLAlchemy's DDL event system.
    """
    from sqlalchemy import event as sa_event
    from sqlalchemy.schema import Table
    from app.models.database import AuditTrail

    # Remove PG-specific CHECK constraints from the AuditTrail table
    _stripped = []
    for constraint in list(AuditTrail.__table__.constraints):
        from sqlalchemy import CheckConstraint
        if isinstance(constraint, CheckConstraint):
            sqltext = str(constraint.sqltext)
            if "jsonb_typeof" in sqltext or "jsonb_" in sqltext:
                AuditTrail.__table__.constraints.discard(constraint)
                _stripped.append(constraint)

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield

    # Restore stripped constraints (for correctness, even though session ends)
    for c in _stripped:
        AuditTrail.__table__.constraints.add(c)

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="session")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """A long-lived session scoped to the entire test session (for seed data)."""
    async with TestSessionLocal() as session:
        yield session


@pytest_asyncio.fixture(scope="session")
async def seed_org_user(db_session: AsyncSession):
    """Seed one Organisation + Owner user and return (org, user)."""
    org = Organization(
        name="Acme Corp",
        slug="acme-corp",
        industry="fintech",
        max_monthly_audits=50,
        max_connectors=10,
        max_users=20,
    )
    db_session.add(org)
    await db_session.flush()

    # Use bcrypt directly to avoid passlib 1.7.4 + bcrypt 5.x probe bug
    import bcrypt as _bcrypt_lib
    _pw = "SecureP@ss123".encode()
    _hashed = _bcrypt_lib.hashpw(_pw, _bcrypt_lib.gensalt()).decode()

    user = User(
        org_id=org.id,
        email="owner@acme.com",
        hashed_password=_hashed,
        full_name="Acme Owner",
        role=UserRole.OWNER,
        is_active=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(org)
    await db_session.refresh(user)
    return org, user


@pytest_asyncio.fixture(scope="session")
async def auth_token(seed_org_user) -> str:
    """Return a valid JWT bearer token for the seeded owner user."""
    org, user = seed_org_user
    token = create_access_token(
        data={"sub": str(user.id), "org_id": str(org.id), "role": user.role},
        expires_delta=timedelta(hours=24),
    )
    return token


@pytest_asyncio.fixture(scope="session")
async def client(auth_token: str) -> AsyncGenerator[AsyncClient, None]:
    """
    Async HTTP test client wired to the FastAPI app.
    Overrides the DB dependency with the in-memory SQLite session.
    Patches scheduler.start() so it never spawns real threads.
    """
    # Import app lazily (after stubs are registered)
    from app.main import create_app

    # Patch scheduler so it does not start real background threads
    with patch("app.services.scheduler_service.start_scheduler", return_value=None), \
         patch("app.services.scheduler_service.stop_scheduler", return_value=None), \
         patch("app.main.init_rag", new_callable=AsyncMock), \
         patch("app.main.seed_database", new_callable=AsyncMock):

        application: FastAPI = create_app()

        # Override DB dependency
        async def override_get_db():
            async with TestSessionLocal() as session:
                yield session

        application.dependency_overrides[get_db] = override_get_db

        transport = ASGITransport(app=application)
        async with AsyncClient(
            transport=transport,
            base_url="http://testserver",
            headers={"Authorization": f"Bearer {auth_token}"},
        ) as ac:
            yield ac


@pytest.fixture()
def auth_headers(auth_token: str) -> dict:
    return {"Authorization": f"Bearer {auth_token}"}


# ── Utility helpers ────────────────────────────────────────────────────────────

def make_hmac_sig(secret: str, body: bytes) -> str:
    """Compute sha256 HMAC signature matching the webhook validator."""
    dig = _hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={dig}"
