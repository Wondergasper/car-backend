"""
API Key management endpoints with scoped permissions.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
import secrets
import hashlib
from datetime import datetime
from app.db.session import get_db
from app.models.database import User, Organization, APIKey
from app.schemas.schemas import APIKeyCreate, APIKeyResponse
from app.api.dependencies import get_current_user

router = APIRouter()


def generate_api_key() -> tuple[str, str, str, str]:
    """
    Generate a new API key with prefix, salt, and hash.
    Returns: (full_key, key_prefix, key_hash, key_salt)
    """
    # Generate a random key
    raw_key = secrets.token_urlsafe(48)
    key_prefix = raw_key[:16]
    key_salt = secrets.token_urlsafe(32)
    
    # Hash with salt
    key_hash = hashlib.sha256(f"{raw_key}{key_salt}".encode()).hexdigest()
    
    return raw_key, key_prefix, key_hash, key_salt


@router.get("/", response_model=List[APIKeyResponse])
async def list_api_keys(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(APIKey).where(
            APIKey.org_id == current_user.org_id,
            APIKey.revoked_at.is_(None)
        )
    )
    keys = result.scalars().all()
    return keys


@router.post("/", response_model=APIKeyResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    api_key_data: APIKeyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Generate key
    full_key, key_prefix, key_hash, key_salt = generate_api_key()
    
    new_key = APIKey(
        org_id=current_user.org_id,
        name=api_key_data.name,
        key_prefix=key_prefix,
        key_hash=key_hash,
        key_salt=key_salt,
        permissions=api_key_data.permissions or {},
        allowed_ips=api_key_data.allowed_ips,
        rate_limit=api_key_data.rate_limit,
        expires_at=api_key_data.expires_at,
        created_by=current_user.id,
    )
    db.add(new_key)
    await db.commit()
    await db.refresh(new_key)
    
    # Return full key only once
    response = APIKeyResponse.model_validate(new_key)
    response.full_key = full_key
    return response


@router.post("/{key_id}/revoke", response_model=APIKeyResponse)
async def revoke_api_key(
    key_id: str,
    reason: str = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_id,
            APIKey.org_id == current_user.org_id,
            APIKey.revoked_at.is_(None)
        )
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    api_key.is_active = False
    api_key.revoked_by = current_user.id
    api_key.revoked_at = datetime.utcnow()
    api_key.revoked_reason = reason
    
    await db.commit()
    await db.refresh(api_key)
    return api_key


@router.get("/{key_id}", response_model=APIKeyResponse)
async def get_api_key(
    key_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(APIKey).where(
            APIKey.id == key_id,
            APIKey.org_id == current_user.org_id
        )
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    return api_key
