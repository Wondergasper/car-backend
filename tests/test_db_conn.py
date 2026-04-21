import asyncio
from sqlalchemy import text
from app.db.session import engine

async def test_connection():
    print("Testing connection to Supabase...")
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT version();"))
            row = result.fetchone()
            print(f"Connection Successful!")
            print(f"PostgreSQL Version: {row[0]}")
    except Exception as e:
        print(f"Connection Failed: {e}")

if __name__ == "__main__":
    asyncio.run(test_connection())
