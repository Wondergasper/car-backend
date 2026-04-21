import asyncio
import uuid
from app.db.session import async_session
from app.models.database import Organization, User, UserRole
from app.core.security import get_password_hash

async def seed_admin():
    print("Seeding Initial Administrative Data...")
    async with async_session() as session:
        async with session.begin():
            # Create Organization
            org_id = uuid.uuid4()
            org = Organization(
                id=org_id,
                name="Wonder Gasper Corp",
                slug="wonder-gasper",
                industry="Technology",
                dpo_name="Gasper Wonder",
                dpo_email="gasper@wondercorp.com"
            )
            session.add(org)
            
            # Create Admin User
            user = User(
                id=uuid.uuid4(),
                org_id=org_id,
                email="admin@wondercorp.com",
                hashed_password=get_password_hash("admin123"),
                full_name="Gasper Wonder Admin",
                role=UserRole.OWNER,
                is_active=True,
                email_verified=True
            )
            session.add(user)
            
            print("\n" + "="*40)
            print("LOGIN DETAILS FOR CAR-BOT")
            print("="*40)
            print(f"Organization: {org.name}")
            print(f"Email:        {user.email}")
            print(f"Password:     admin123")
            print("="*40)
            
    print("\nSeed Complete. You can now use these details to log in to the UI.")

if __name__ == "__main__":
    asyncio.run(seed_admin())
