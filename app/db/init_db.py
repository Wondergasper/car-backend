from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import async_session
from app.models.database import ComplianceRule
from app.core.rules_engine import COMPLIANCE_RULES


async def seed_rules():
    """Seed the database with NDPA 2023 compliance rules."""
    async with async_session() as session:
        async with session.begin():
            # Check if rules already exist
            result = await session.execute(text("SELECT COUNT(*) FROM compliance_rules"))
            count = result.scalar()
            if count > 0:
                print("Rules already seeded. Skipping.")
                return

            # Insert rules
            for rule_data in COMPLIANCE_RULES:
                rule = ComplianceRule(**rule_data)
                session.add(rule)

            await session.commit()
            print(f"Seeded {len(COMPLIANCE_RULES)} compliance rules.")


async def init_database():
    """Initialize database tables."""
    from app.db.session import engine, Base

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    print("Database initialized.")
    await seed_rules()
