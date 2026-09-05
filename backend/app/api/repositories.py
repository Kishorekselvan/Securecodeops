import os
import shutil
import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.models import Repository, User
from app.schemas.schemas import RepositoryOut
from app.core.config import settings
from app.utils.archive import safe_extract_zip, ArchiveSecurityError

router = APIRouter(prefix="/repositories", tags=["Repositories"])

@router.get("", response_model=List[RepositoryOut])
async def list_repositories(db: AsyncSession = Depends(get_db)):
    stmt = select(Repository).order_by(Repository.created_at.desc())
    res = await db.execute(stmt)
    return res.scalars().all()

@router.get("/{repo_id}", response_model=RepositoryOut)
async def get_repository(repo_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Repository).where(Repository.id == repo_id)
    res = await db.execute(stmt)
    repo = res.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")
    return repo

@router.post("/upload", response_model=RepositoryOut)
async def upload_repository_zip(
    file: UploadFile = File(...),
    name: Optional[str] = Form(None),
    description: Optional[str] = Form(None),
    db: AsyncSession = Depends(get_db)
):
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip repository archives are accepted.")
    
    repo_name = name or os.path.splitext(file.filename)[0]
    repo_id = str(uuid.uuid4())
    repo_storage_dir = os.path.join(settings.UPLOAD_DIR, repo_id)
    zip_dest_path = os.path.join(settings.UPLOAD_DIR, f"{repo_id}.zip")

    try:
        # Save ZIP safely with size guard
        contents = await file.read()
        if len(contents) > settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024:
            raise HTTPException(status_code=413, detail=f"File exceeds maximum size of {settings.MAX_UPLOAD_SIZE_MB}MB")

        with open(zip_dest_path, "wb") as f:
            f.write(contents)

        # Safe extraction with Zip Slip and Zip bomb protection
        extract_res = safe_extract_zip(zip_dest_path, repo_storage_dir)

        # Remove temporary zip archive
        if os.path.exists(zip_dest_path):
            os.remove(zip_dest_path)

        repo = Repository(
            id=repo_id,
            name=repo_name,
            description=description or f"Uploaded ZIP repository archive ({file.filename})",
            storage_path=repo_storage_dir,
            file_count=extract_res["file_count"],
            is_demo=False
        )
        db.add(repo)
        await db.commit()
        await db.refresh(repo)
        return repo

    except ArchiveSecurityError as e:
        if os.path.exists(repo_storage_dir):
            shutil.rmtree(repo_storage_dir, ignore_errors=True)
        if os.path.exists(zip_dest_path):
            os.remove(zip_dest_path)
        raise HTTPException(status_code=400, detail=f"Archive Security Violation: {str(e)}")
    except Exception as e:
        if os.path.exists(repo_storage_dir):
            shutil.rmtree(repo_storage_dir, ignore_errors=True)
        raise HTTPException(status_code=500, detail=f"Failed to process repository archive: {str(e)}")

@router.post("/demo", response_model=RepositoryOut)
async def create_demo_repository(db: AsyncSession = Depends(get_db)):
    """Initializes or returns the built-in educational demo repository."""
    stmt = select(Repository).where(Repository.is_demo == True)
    res = await db.execute(stmt)
    existing_demo = res.scalar_one_or_none()
    if existing_demo:
        return existing_demo

    demo_source_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../demo_repo"))
    repo_id = str(uuid.uuid4())
    dest_dir = os.path.join(settings.UPLOAD_DIR, f"demo_{repo_id}")
    shutil.copytree(demo_source_dir, dest_dir)

    repo = Repository(
        id=repo_id,
        name="SecureCodeOps AI Demo Project (Vulnerable App)",
        description="Comprehensive educational vulnerable microservice containing real-world CWE-89, CWE-78, CWE-798, CWE-502, CWE-79, and vulnerable dependencies.",
        storage_path=dest_dir,
        is_demo=True,
        languages=["Python", "JavaScript", "Config"]
    )
    db.add(repo)
    await db.commit()
    await db.refresh(repo)
    return repo
