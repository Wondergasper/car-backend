from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from app.db.session import get_db
from app.models.database import User, ComplianceRule
from app.schemas.schemas import RuleResponse
from app.api.dependencies import get_current_user

router = APIRouter()


@router.get("/", response_model=List[RuleResponse])
async def list_rules(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(select(ComplianceRule).where(ComplianceRule.is_active == True))
    rules = result.scalars().all()
    return rules
