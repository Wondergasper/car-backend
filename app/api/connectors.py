"""
Connectors API - org-scoped with health monitoring.
Uses AES-256 encryption for connector configurations.
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
import json
from datetime import datetime
from app.db.session import get_db
from app.models.database import User, Connector, Organization
from app.schemas.schemas import ConnectorCreate, ConnectorUpdate, ConnectorResponse
from app.api.dependencies import get_current_user
from app.core.crypto import crypto_service

router = APIRouter()


def _encrypt_config(config: dict) -> tuple[bytes, bytes]:
    """Encrypt connector config and return (ciphertext, iv)."""
    config_json = json.dumps(config)
    ciphertext = crypto_service.encrypt(config_json)
    return ciphertext, b""  # Fernet includes IV internally


def _decrypt_config(ciphertext: bytes) -> dict:
    """Decrypt connector config from ciphertext bytes."""
    config_json = crypto_service.decrypt(ciphertext)
    return json.loads(config_json)


@router.get("/", response_model=List[ConnectorResponse])
async def list_connectors(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # RLS ensures user can only see their org's connectors
    result = await db.execute(
        select(Connector).where(
            Connector.org_id == current_user.org_id,
            Connector.deleted_at.is_(None)
        )
    )
    connectors = result.scalars().all()
    return connectors


@router.post("/", response_model=ConnectorResponse, status_code=status.HTTP_201_CREATED)
async def create_connector(
    request: Request,
    connector_data: ConnectorCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Check org limits
    result = await db.execute(select(Organization).where(Organization.id == current_user.org_id))
    org = result.scalar_one()
    
    result = await db.execute(
        select(Connector).where(
            Connector.org_id == org.id,
            Connector.deleted_at.is_(None)
        )
    )
    existing_connectors = len(result.scalars().all())
    
    if existing_connectors >= org.max_connectors:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Connector limit reached ({org.max_connectors}). Upgrade your plan to add more.",
        )
    
    # Encrypt config before storing
    config_ciphertext, config_iv = _encrypt_config(connector_data.config)

    new_connector = Connector(
        org_id=org.id,
        created_by=current_user.id,
        name=connector_data.name,
        connector_type_id=connector_data.connector_type_id,
        config_encrypted=config_ciphertext,
        config_encryption_iv=config_iv,
        sync_interval=connector_data.sync_interval,
    )
    db.add(new_connector)
    await db.commit()
    await db.refresh(new_connector)
    return new_connector


@router.get("/{connector_id}", response_model=ConnectorResponse)
async def get_connector(
    connector_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Connector).where(
            Connector.id == connector_id,
            Connector.org_id == current_user.org_id,
            Connector.deleted_at.is_(None)
        )
    )
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    return connector


@router.put("/{connector_id}", response_model=ConnectorResponse)
async def update_connector(
    connector_id: str,
    connector_data: ConnectorUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Connector).where(
            Connector.id == connector_id,
            Connector.org_id == current_user.org_id
        )
    )
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")

    update_data = connector_data.model_dump(exclude_unset=True)

    # Encrypt config if being updated
    if "config" in update_data:
        config_ciphertext, config_iv = _encrypt_config(update_data.pop("config"))
        connector.config_encrypted = config_ciphertext
        connector.config_encryption_iv = config_iv

    for key, value in update_data.items():
        setattr(connector, key, value)

    await db.commit()
    await db.refresh(connector)
    return connector


@router.delete("/{connector_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_connector(
    connector_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Connector).where(
            Connector.id == connector_id,
            Connector.org_id == current_user.org_id
        )
    )
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")

    # Soft delete
    from datetime import datetime
    connector.deleted_at = datetime.utcnow()
    await db.commit()
    return None


@router.post("/{connector_id}/test", status_code=status.HTTP_200_OK)
async def test_connector(
    connector_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = await db.execute(
        select(Connector).where(
            Connector.id == connector_id,
            Connector.org_id == current_user.org_id
        )
    )
    connector = result.scalar_one_or_none()
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")

    # Decrypt config
    try:
        config = _decrypt_config(connector.config_encrypted)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to decrypt connector config: {e}")

    # Get connector type slug
    type_result = await db.execute(
        select(ConnectorType).where(ConnectorType.id == connector.connector_type_id)
    )
    connector_type = type_result.scalar_one_or_none()
    if not connector_type:
        raise HTTPException(status_code=404, detail="Connector type not found")

    # Test connection based on connector type
    from app.connectors import SQLConnector, GoogleDriveConnector, WhatsAppConnector

    try:
        if connector_type.slug in ("postgresql", "mysql", "mssql"):
            config["driver"] = connector_type.slug
            sql_connector = SQLConnector(config)
            connected = sql_connector.connect()
        elif connector_type.slug == "google_drive":
            gd_connector = GoogleDriveConnector(config)
            connected = gd_connector.connect()
        elif connector_type.slug == "whatsapp_business":
            wa_connector = WhatsAppConnector(config)
            connected = wa_connector.connect()
        else:
            connected = False

        if connected:
            return {
                "status": "success",
                "message": f"Successfully connected to {connector.name}",
                "connector_type": connector_type.slug,
            }
        else:
            return {
                "status": "failed",
                "message": f"Connection test failed for {connector.name}",
                "connector_type": connector_type.slug,
            }

    except ImportError as e:
        return {
            "status": "error",
            "message": f"Required library not installed: {e}",
        }
    except Exception as e:
        return {
            "status": "failed",
            "message": f"Connection test failed: {str(e)}",
        }


from app.models.database import ConnectorType
