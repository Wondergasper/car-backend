"""
Documents API — org-scoped uploads stored under ./media/documents/{org_id}/.
Served via the existing /media static mount.
"""
import uuid
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import FileResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.db.session import get_db
from app.models.database import Document, DocumentType, User
from app.schemas.schemas import DocumentResponse, DocumentUpdate

router = APIRouter()


def _safe_filename(name: str) -> str:
    base = Path(name).name
    out = "".join(c for c in base if c.isalnum() or c in "._- ")
    return (out or "upload")[:180]


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
    return r.scalars().all()


@router.post("/", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def upload_document(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    file: UploadFile = File(...),
    title: Optional[str] = Form(None),
    document_type: str = Form("custom"),
):
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
        status="draft",
        generated_by=current_user.id,
        ai_assisted=False,
    )
    db.add(doc)
    await db.commit()
    await db.refresh(doc)
    return doc


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
    return doc


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
    return doc


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
