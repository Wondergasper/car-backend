from sqlalchemy import select
from app.db.session import async_session
from app.models.database import User
import asyncio

async def list_users():
    async with async_session() as session:
        result = await session.execute(select(User))
        users = result.scalars().all()
        for u in users:
            print(f"User: {u.email} (Org: {u.org_id})")

if __name__ == "__main__":
    asyncio.run(list_users())
