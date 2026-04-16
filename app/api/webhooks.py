"""
Webhook/Connector Events API - receives data events from connected sources.
Uses ConnectorEvent model for immutable event logging.
"""
import hashlib
import hmac
import json
from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, Dict, Any
from datetime import datetime
from uuid import UUID
from app.db.session import get_db
from app.models.database import Connector, ConnectorEvent

router = APIRouter()


def _validate_webhook_signature(request_body: bytes, signature_header: str, secret: str) -> bool:
    """
    Validate webhook HMAC-SHA256 signature.
    
    Expects signature_header in format: "sha256=<hexdigest>"
    """
    if not signature_header.startswith("sha256="):
        return False
    
    expected_signature = signature_header[7:]  # Remove "sha256=" prefix
    
    computed_signature = hmac.new(
        secret.encode(),
        request_body,
        hashlib.sha256
    ).hexdigest()
    
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(computed_signature, expected_signature)


# Inline schemas for webhook events
class WebhookEventCreate(BaseModel):
    connector_id: UUID
    event_type: str = "data_update"
    payload: Dict[str, Any] = {}
    idempotency_key: Optional[str] = None


class WebhookEventResponse(BaseModel):
    id: UUID
    connector_id: UUID
    org_id: UUID
    event_type: str
    payload_hash: str
    processed: bool
    created_at: datetime

    class Config:
        from_attributes = True


@router.post("/", response_model=WebhookEventResponse, status_code=status.HTTP_201_CREATED)
async def receive_webhook(
    request: Request,
    event_data: WebhookEventCreate,
    db: AsyncSession = Depends(get_db),
):
    # Get raw request body for signature validation
    body = await request.body()
    
    # Verify connector exists
    result = await db.execute(
        select(Connector).where(Connector.id == event_data.connector_id)
    )
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    
    # Validate webhook signature
    signature_header = request.headers.get("X-Hub-Signature-256")
    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing webhook signature")
    
    if not connector.webhook_secret:
        raise HTTPException(status_code=500, detail="Connector webhook secret not configured")
    
    if not _validate_webhook_signature(body, signature_header, connector.webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # Compute payload hash for deduplication
    payload_str = json.dumps(event_data.payload, sort_keys=True)
    payload_hash = hashlib.sha256(payload_str.encode()).hexdigest()

    # Check idempotency
    if event_data.idempotency_key:
        existing = await db.execute(
            select(ConnectorEvent).where(
                ConnectorEvent.idempotency_key == event_data.idempotency_key
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Duplicate event (idempotency key exists)")

    # Create connector event
    new_event = ConnectorEvent(
        connector_id=event_data.connector_id,
        org_id=connector.org_id,
        event_type=event_data.event_type,
        payload_hash=payload_hash,
        payload_size=len(payload_str),
        payload_sample=payload_str[:1000],
        idempotency_key=event_data.idempotency_key,
        processed=False,
    )
    db.add(new_event)
    await db.commit()
    await db.refresh(new_event)

    # TODO: Trigger processing via Celery
    return new_event


@router.post("/{connector_id}/events", response_model=WebhookEventResponse, status_code=status.HTTP_201_CREATED)
async def receive_connector_webhook(
    connector_id: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    # Get raw request body for signature validation
    body = await request.body()
    
    # Parse event data from body
    try:
        event_data = await request.json()
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    
    # Verify connector exists
    result = await db.execute(
        select(Connector).where(Connector.id == connector_id)
    )
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    
    # Validate webhook signature
    signature_header = request.headers.get("X-Hub-Signature-256")
    if not signature_header:
        raise HTTPException(status_code=401, detail="Missing webhook signature")
    
    if not connector.webhook_secret:
        raise HTTPException(status_code=500, detail="Connector webhook secret not configured")
    
    if not _validate_webhook_signature(body, signature_header, connector.webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # Compute payload hash
    payload = event_data.get("payload", event_data)
    payload_str = json.dumps(payload, sort_keys=True, default=str)
    payload_hash = hashlib.sha256(payload_str.encode()).hexdigest()

    # Create connector event
    new_event = ConnectorEvent(
        connector_id=connector_id,
        org_id=connector.org_id,
        event_type=event_data.get("event_type", "data_update"),
        payload_hash=payload_hash,
        payload_size=len(payload_str),
        payload_sample=payload_str[:1000],
        processed=False,
    )
    db.add(new_event)
    await db.commit()
    await db.refresh(new_event)

    return new_event
