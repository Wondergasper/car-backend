"""
Documents API — org-scoped uploads stored under ./media/documents/{org_id}/.
Served via the existing /media static mount.
"""
import hashlib
import json
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.db.session import get_db
from app.models.database import Audit, AuditStatus, AuditType, ConnectorEvent, Document, DocumentType, Organization, User
from app.schemas.schemas import DocumentResponse, DocumentUpdate
from app.services.audit_processor import run_audit
from app.services.document_analysis import build_document_analysis, extract_document_payload

router = APIRouter()


def _safe_filename(name: str) -> str:
    base = Path(name).name
    out = "".join(c for c in base if c.isalnum() or c in "._- ")
    return (out or "upload")[:180]


def _document_to_response(doc: Document) -> DocumentResponse:
    analysis = (doc.content or {}).get("analysis", {}) if isinstance(doc.content, dict) else {}
    return DocumentResponse.model_validate(
        {
            **doc.__dict__,
            "analysis_status": analysis.get("status"),
            "analysis_mode": analysis.get("mode"),
            "latest_analysis": analysis.get("summary"),
        }
    )


async def _create_connector_event(
    db: AsyncSession,
    current_user: User,
    payload: dict,
    content: bytes,
    document_id: uuid.UUID,
) -> ConnectorEvent:
    payload_with_metadata = {
        "document_id": str(document_id),
        "document_type": "uploaded_document",
        **payload,
    }
    payload_json = json.dumps(payload_with_metadata, default=str)
    event = ConnectorEvent(
        org_id=current_user.org_id,
        connector_id=None,
        event_type="manual_file_upload",
        payload_hash=hashlib.sha256(content).hexdigest(),
        payload_size=len(content),
        payload_sample=payload_json,
        processed=False,
    )
    db.add(event)
    await db.flush()
    return event


async def _run_full_audit_for_document(
    db: AsyncSession,
    current_user: User,
    title: str,
) -> Audit:
    org = (
        await db.execute(select(Organization).where(Organization.id == current_user.org_id))
    ).scalar_one()

    audit = Audit(
        org_id=current_user.org_id,
        initiated_by=current_user.id,
        name=f"Document Audit - {title[:120]}",
        audit_type=AuditType.FULL,
        scope={"source": "document_upload"},
        status=AuditStatus.IN_PROGRESS,
    )
    db.add(audit)
    await db.commit()
    await db.refresh(audit)

    completed_audit = await run_audit(str(audit.id), db)
    result = await db.execute(select(Audit).where(Audit.id == completed_audit.id))
    return result.scalar_one()


async def _process_document(
    db: AsyncSession,
    current_user: User,
    file: UploadFile,
    title: Optional[str],
    document_type: str,
    analysis_mode: str,
) -> DocumentResponse:
    try:
        dt = DocumentType(document_type)
    except ValueError:
        dt = DocumentType.CUSTOM

    doc_id = uuid.uuid4()
    safe = _safe_filename(file.filename or "upload")
    rel_dir = Path("documents") / str(current_user.org_id)
    abs_dir = Path("media") / rel_dir
    abs_dir.mkdir(parents=True, exist_ok=True)
    filename = f"{doc_id.hex}_{safe}"
    abs_path = abs_dir / filename
    content = await file.read()
    abs_path.write_bytes(content)

    payload = extract_document_payload(file.filename or "upload", content)
    analysis = build_document_analysis(
        filename=file.filename or "upload",
        payload=payload,
        content=content,
        location_prefix=f"document/{doc_id}",
    )

    storage_key = str(rel_dir / filename)
    storage_url = f"/media/{storage_key.replace(chr(92), '/')}"

    doc_title = (title or file.filename or "Uploaded document").strip()[:255]
    doc = Document(
        id=doc_id,
        org_id=current_user.org_id,
        document_type=dt,
        title=doc_title,
        storage_key=storage_key,
        storage_url=storage_url,
        status="analyzed" if analysis_mode == "instant" else "uploaded",
        generated_by=current_user.id,
        ai_assisted=True,
        content={
            "analysis": analysis,
            "source": {
                "file_name": file.filename or "upload",
                "mime_type": file.content_type,
                "analysis_mode": analysis_mode,
            },
        },
    )
    db.add(doc)
    await db.flush()

    if analysis_mode == "audit":
        await _create_connector_event(db, current_user, payload, content, doc.id)
        await db.commit()
        completed_audit = await _run_full_audit_for_document(db, current_user, doc_title)
        doc.audit_id = completed_audit.id
        doc.status = "audited"
        await db.commit()
        await db.refresh(doc)
    else:
        await db.commit()
        await db.refresh(doc)

    return _document_to_response(doc)


@router.get("/", response_model=List[DocumentResponse])
async def list_documents(
    doc_type: Optional[str] = Query(None, alias="type"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    q = (
        select(Document)
        .where(Document.org_id == current_user.org_id)
        .order_by(Document.created_at.desc())
    )
    if doc_type:
        try:
            dt = DocumentType(doc_type)
            q = q.where(Document.document_type == dt)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid document type filter")
    r = await db.execute(q)
    return [_document_to_response(doc) for doc in r.scalars().all()]


@router.post("/", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def upload_document(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    file: UploadFile = File(...),
    title: Optional[str] = Form(None),
    document_type: str = Form("custom"),
    analysis_mode: str = Form("instant"),
):
    if analysis_mode not in {"instant", "audit"}:
        raise HTTPException(status_code=400, detail="analysis_mode must be 'instant' or 'audit'")

    return await _process_document(db, current_user, file, title, document_type, analysis_mode)


@router.post("/{document_id}/analyze", response_model=DocumentResponse)
async def analyze_existing_document(
    document_id: str,
    analysis_mode: str = Form("instant"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if analysis_mode not in {"instant", "audit"}:
        raise HTTPException(status_code=400, detail="analysis_mode must be 'instant' or 'audit'")

    r = await db.execute(
        select(Document).where(
            Document.id == document_id,
            Document.org_id == current_user.org_id,
        )
    )
    doc = r.scalar_one_or_none()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if not doc.storage_key:
        raise HTTPException(status_code=400, detail="Document file is not available")

    path = Path("media") / doc.storage_key
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Stored document file is missing")

    content = path.read_bytes()
    payload = extract_document_payload(path.name, content)
    analysis = build_document_analysis(
        filename=doc.title,
        payload=payload,
        content=content,
        location_prefix=f"document/{doc.id}",
    )

    existing_content = doc.content if isinstance(doc.content, dict) else {}
    doc.content = {
        **existing_content,
        "analysis": {
            **analysis,
            "mode": analysis_mode,
        },
    }
    doc.status = "analyzed" if analysis_mode == "instant" else "uploaded"

    if analysis_mode == "audit":
        await _create_connector_event(db, current_user, payload, content, doc.id)
        await db.commit()
        completed_audit = await _run_full_audit_for_document(db, current_user, doc.title)
        doc.audit_id = completed_audit.id
        doc.status = "audited"

    await db.commit()
    await db.refresh(doc)
    return _document_to_response(doc)


@router.get("/{document_id}/download")
async def download_document(
    document_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    r = await db.execute(
        select(Document).where(
            Document.id == document_id,
            Document.org_id == current_user.org_id,
        )
    )
    doc = r.scalar_one_or_none()
    if not doc or not doc.storage_key:
        raise HTTPException(status_code=404, detail="Document or file not found")
    path = Path("media") / doc.storage_key
    if not path.is_file():
        raise HTTPException(status_code=404, detail="File missing on disk")
    return FileResponse(
        path=str(path),
        filename=doc.title.replace("/", "-")[:200] + Path(path.name).suffix,
        media_type="application/octet-stream",
    )


@router.get("/{document_id}", response_model=DocumentResponse)
async def get_document(
    document_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    r = await db.execute(
        select(Document).where(
            Document.id == document_id,
            Document.org_id == current_user.org_id,
        )
    )
    doc = r.scalar_one_or_none()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    return _document_to_response(doc)


@router.put("/{document_id}", response_model=DocumentResponse)
async def update_document(
    document_id: str,
    data: DocumentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    r = await db.execute(
        select(Document).where(
            Document.id == document_id,
            Document.org_id == current_user.org_id,
        )
    )
    doc = r.scalar_one_or_none()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    for k, v in data.model_dump(exclude_unset=True).items():
        setattr(doc, k, v)
    await db.commit()
    await db.refresh(doc)
    return _document_to_response(doc)


@router.delete("/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_document(
    document_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    r = await db.execute(
        select(Document).where(
            Document.id == document_id,
            Document.org_id == current_user.org_id,
        )
    )
    doc = r.scalar_one_or_none()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    if doc.storage_key:
        p = Path("media") / doc.storage_key
        if p.is_file():
            try:
                p.unlink()
            except OSError:
                pass
    await db.execute(
        delete(Document).where(
            Document.id == document_id,
            Document.org_id == current_user.org_id,
        )
    )
    await db.commit()
    return None
