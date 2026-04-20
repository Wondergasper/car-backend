"""
Team Member Management API.
Allows org owners and admins to list, invite, update, and deactivate users.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from pydantic import BaseModel, EmailStr
from datetime import datetime, timezone

from app.db.session import get_db
from app.models.database import User, Organization, UserRole
from app.schemas.schemas import UserResponse
from app.api.dependencies import get_current_user
from app.core.security import get_password_hash
import secrets
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


class UserInvite(BaseModel):
    email: EmailStr
    full_name: str
    role: UserRole = UserRole.VIEWER


class UserRoleUpdate(BaseModel):
    role: UserRole


def _require_admin(current_user: User):
    if current_user.role not in (UserRole.OWNER, UserRole.ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or Owner role required",
        )


@router.get("/", response_model=List[UserResponse])
async def list_team_members(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 50,
):
    """List all active users in the organization."""
    result = await db.execute(
        select(User)
        .where(
            User.org_id == current_user.org_id,
            User.deleted_at.is_(None),
        )
        .order_by(User.created_at.asc())
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


@router.post("/invite", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def invite_team_member(
    invite_data: UserInvite,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Invite a new team member to the organization."""
    _require_admin(current_user)

    # Check org user limit
    org_result = await db.execute(
        select(Organization).where(Organization.id == current_user.org_id)
    )
    org = org_result.scalar_one()

    user_count_result = await db.execute(
        select(User).where(
            User.org_id == current_user.org_id,
            User.deleted_at.is_(None),
        )
    )
    user_count = len(user_count_result.scalars().all())
    if user_count >= org.max_users:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"User limit reached ({org.max_users}). Upgrade your plan to add more teammates.",
        )

    # Check if email already exists
    existing = await db.execute(select(User).where(User.email == invite_data.email))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email already exists.",
        )

    # Create user with a temporary random password; they should reset via email later
    temp_password = secrets.token_urlsafe(16)
    new_user = User(
        org_id=current_user.org_id,
        email=invite_data.email,
        full_name=invite_data.full_name,
        hashed_password=get_password_hash(temp_password),
        role=invite_data.role,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    logger.info(f"User {invite_data.email} invited to org {current_user.org_id} by {current_user.email}")
    return new_user


@router.put("/{user_id}/role", response_model=UserResponse)
async def update_user_role(
    user_id: str,
    data: UserRoleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update a team member's role."""
    _require_admin(current_user)

    # Only OWNER can assign OWNER role
    if data.role == UserRole.OWNER and current_user.role != UserRole.OWNER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the organization owner can assign the Owner role.",
        )

    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.org_id == current_user.org_id,
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.role = data.role
    await db.commit()
    await db.refresh(user)
    return user


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def deactivate_team_member(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Soft-delete (deactivate) a team member."""
    _require_admin(current_user)

    if str(current_user.id) == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot deactivate your own account.",
        )

    result = await db.execute(
        select(User).where(
            User.id == user_id,
            User.org_id == current_user.org_id,
        )
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.is_active = False
    user.deleted_at = datetime.now(timezone.utc)
    await db.commit()
    return None
