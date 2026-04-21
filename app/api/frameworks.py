"""
Frameworks API - Multi-framework compliance data.
GET /api/frameworks/          - List available frameworks
GET /api/frameworks/{id}      - Framework detail + controls
GET /api/frameworks/crosswalk - Control mapping between frameworks
"""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List, Optional

from app.api.dependencies import get_current_user
from app.models.database import User
from app.core.framework_loader import get_framework_loader
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


class ControlItem(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    evidence_requirements: List[str] = []
    maps_to: List[str] = []


class FrameworkSummary(BaseModel):
    id: str
    name: str
    version: Optional[str] = None
    issuing_body: Optional[str] = None
    control_count: int


class FrameworkDetail(BaseModel):
    id: str
    name: str
    version: Optional[str] = None
    issuing_body: Optional[str] = None
    controls: List[ControlItem]


class CrosswalkItem(BaseModel):
    source: str
    title: str
    matched: List[str]


@router.get("/", response_model=List[FrameworkSummary])
async def list_frameworks(current_user: User = Depends(get_current_user)):
    loader = get_framework_loader()
    frameworks = []
    for fw_id in loader.list_available():
        fw = loader.load(fw_id)
        if fw:
            frameworks.append(FrameworkSummary(
                id=fw_id,
                name=fw.get("framework", fw_id),
                version=fw.get("version"),
                issuing_body=fw.get("issuing_body"),
                control_count=len(fw.get("controls", [])),
            ))
    return frameworks


@router.get("/{framework_id}", response_model=FrameworkDetail)
async def get_framework(framework_id: str, current_user: User = Depends(get_current_user)):
    loader = get_framework_loader()
    fw = loader.load(framework_id)
    if not fw:
        raise HTTPException(status_code=404, detail=f"Framework '{framework_id}' not found")
    return FrameworkDetail(
        id=framework_id,
        name=fw.get("framework", framework_id),
        version=fw.get("version"),
        issuing_body=fw.get("issuing_body"),
        controls=[ControlItem(**c) for c in fw.get("controls", [])],
    )


@router.get("/crosswalk/map")
async def crosswalk(
    from_fw: str, to_fw: str, current_user: User = Depends(get_current_user)
):
    loader = get_framework_loader()
    result = loader.crosswalk(from_fw, to_fw)
    return {"from": from_fw, "to": to_fw, "mappings": result, "count": len(result)}
