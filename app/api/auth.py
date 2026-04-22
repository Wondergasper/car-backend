"""
Authentication API - upgraded for multi-tenant organizations.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.models.database import User, Organization, UserRole
from app.schemas.schemas import (
    UserCreate,
    UserLogin,
    Token,
    UserResponse,
    OrganizationUpdate,
    OrganizationResponse,
)
from app.core.security import get_password_hash, verify_password, create_access_token
from app.api.dependencies import get_current_user
from datetime import timedelta
from app.core.config import get_settings
from app.services.entity_verification import verify_entity

router = APIRouter()
settings = get_settings()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    # Check if user already exists
    result = await db.execute(select(User).where(User.email == user_data.email))
    existing_user = result.scalar_one_or_none()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # Create organization for this user
    org_slug = user_data.company_name.lower().replace(" ", "-").replace(".", "")
    # Ensure unique slug
    base_slug = org_slug
    counter = 1
    while True:
        result = await db.execute(select(Organization).where(Organization.slug == org_slug))
        if not result.scalar_one_or_none():
            break
        org_slug = f"{base_slug}-{counter}"
        counter += 1
    
    verification = await verify_entity(
        company_name=user_data.company_name,
        rc_number=user_data.rc_number,
    )

    org = Organization(
        name=user_data.company_name,
        slug=org_slug,
        industry=user_data.industry,
        settings={
            "rc_number": user_data.rc_number,
            "registration_role": user_data.registration_role,
            **verification,
        },
    )
    db.add(org)
    await db.flush()  # Get org ID
    
    # Create user as org owner
    new_user = User(
        org_id=org.id,
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password),
        full_name=user_data.company_name + " Admin",  # Will be updated during onboarding
        role=UserRole.OWNER,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    await db.refresh(org)
    
    return new_user


@router.post("/login", response_model=Token)
async def login(credentials: UserLogin, db: AsyncSession = Depends(get_db)):
    # Find user
    result = await db.execute(select(User).where(User.email == credentials.email))
    user = result.scalar_one_or_none()
    if not user or not verify_password(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    # Create access token with org_id
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "org_id": str(user.org_id),
            "role": user.role,
        },
        expires_delta=access_token_expires,
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user,
    }


@router.get("/me", response_model=UserResponse)
async def get_current_user_endpoint(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/organization", response_model=OrganizationResponse)
async def get_my_organization(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")
    return org


@router.patch("/organization", response_model=OrganizationResponse)
async def update_my_organization(
    data: OrganizationUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update the signed-in user's organisation (owners and admins)."""
    if current_user.role not in (UserRole.OWNER, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only organisation owners and admins can update organisation details.",
        )

    result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Organisation not found")

    payload = data.model_dump(exclude_unset=True)
    settings_patch = payload.pop("settings", None)
    rc_number = payload.pop("rc_number", None)
    registration_role = payload.pop("registration_role", None)
    if settings_patch is not None:
        base = dict(org.settings) if org.settings else {}
        base.update(settings_patch)
        org.settings = base

    if rc_number is not None or registration_role is not None:
        base = dict(org.settings) if org.settings else {}
        if rc_number is not None:
            base["rc_number"] = rc_number
            verification = await verify_entity(
                company_name=payload.get("name", org.name),
                rc_number=rc_number,
            )
            base.update(verification)
        if registration_role is not None:
            base["registration_role"] = registration_role
        org.settings = base

    for key, value in payload.items():
        setattr(org, key, value)

    await db.commit()
    await db.refresh(org)
    return org
