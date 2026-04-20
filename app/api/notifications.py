"""
Outgoing Webhook Registration API.
Org admins register URLs to receive real-time event payloads from CAR-Bot.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional
from pydantic import BaseModel, HttpUrl
from datetime import datetime, timezone
import secrets

from app.db.session import get_db
from app.models.database import User, Organization
from app.api.dependencies import get_current_user

router = APIRouter()


class WebhookCreate(BaseModel):
    name: str
    url: str
    events: List[str] = ["audit.completed", "finding.critical"]
    secret: Optional[str] = None


class WebhookResponse(BaseModel):
    id: str
    name: str
    url: str
    events: List[str]
    is_active: bool
    created_at: str


# In-memory store (replace with DB model in production)
_webhook_store: dict = {}


@router.get("/webhooks", response_model=List[WebhookResponse])
async def list_webhooks(
    current_user: User = Depends(get_current_user),
):
    org_hooks = [
        {**v, "id": k}
        for k, v in _webhook_store.items()
        if v["org_id"] == str(current_user.org_id)
    ]
    return [WebhookResponse(**h) for h in org_hooks]


@router.post("/webhooks", response_model=WebhookResponse, status_code=status.HTTP_201_CREATED)
async def register_webhook(
    data: WebhookCreate,
    current_user: User = Depends(get_current_user),
):
    hook_id = secrets.token_urlsafe(12)
    hook = {
        "id": hook_id,
        "org_id": str(current_user.org_id),
        "name": data.name,
        "url": data.url,
        "events": data.events,
        "secret": data.secret or secrets.token_urlsafe(32),
        "is_active": True,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    _webhook_store[hook_id] = hook
    return WebhookResponse(**hook)


@router.delete("/webhooks/{hook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(
    hook_id: str,
    current_user: User = Depends(get_current_user),
):
    hook = _webhook_store.get(hook_id)
    if not hook or hook["org_id"] != str(current_user.org_id):
        raise HTTPException(status_code=404, detail="Webhook not found")
    del _webhook_store[hook_id]
    return None


def get_org_webhooks(org_id: str) -> List[dict]:
    """Helper: return active webhook configs for an org."""
    return [
        v for v in _webhook_store.values()
        if v["org_id"] == org_id and v.get("is_active")
    ]
