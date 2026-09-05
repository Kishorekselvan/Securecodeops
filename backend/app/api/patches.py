import os
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.models import Patch, Finding, Scan, Repository
from app.schemas.schemas import PatchOut
from app.agents.patch_agent import PatchRecommendationAgent

router = APIRouter(prefix="/patches", tags=["Patches"])

@router.get("", response_model=List[PatchOut])
async def list_patches(
    scan_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    validated_only: bool = Query(False),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Patch)
    if scan_id:
        stmt = stmt.where(Patch.scan_id == scan_id)
    if status:
        stmt = stmt.where(Patch.status == status.upper())
    if validated_only:
        stmt = stmt.where(Patch.is_validated == True)
    stmt = stmt.order_by(Patch.created_at.desc())
    res = await db.execute(stmt)
    return res.scalars().all()

@router.get("/{patch_id}", response_model=PatchOut)
async def get_patch(patch_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Patch).where(Patch.id == patch_id)
    res = await db.execute(stmt)
    patch = res.scalar_one_or_none()
    if not patch:
        raise HTTPException(status_code=404, detail="Patch not found")
    return patch

@router.get("/{patch_id}/download")
async def download_patch_file(patch_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Patch).where(Patch.id == patch_id)
    res = await db.execute(stmt)
    patch = res.scalar_one_or_none()
    if not patch:
        raise HTTPException(status_code=404, detail="Patch not found")
    
    filename = f"remediation_{os.path.basename(patch.file_path)}.patch"
    return Response(
        content=patch.diff,
        media_type="text/plain",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@router.post("/{patch_id}/apply", response_model=PatchOut)
async def apply_patch_to_working_copy(patch_id: str, db: AsyncSession = Depends(get_db)):
    """Applies patch to the repository working directory."""
    stmt = select(Patch).where(Patch.id == patch_id)
    res = await db.execute(stmt)
    patch = res.scalar_one_or_none()
    if not patch:
        raise HTTPException(status_code=404, detail="Patch not found")

    stmt_scan = select(Scan).where(Scan.id == patch.scan_id)
    res_scan = await db.execute(stmt_scan)
    scan = res_scan.scalar_one_or_none()
    
    stmt_repo = select(Repository).where(Repository.id == scan.repository_id)
    res_repo = await db.execute(stmt_repo)
    repo = res_repo.scalar_one_or_none()

    if repo and os.path.exists(repo.storage_path):
        target_file = os.path.join(repo.storage_path, patch.file_path)
        try:
            with open(target_file, "w", encoding="utf-8") as f:
                f.write(patch.patched_code)
            patch.status = "APPLIED"
            await db.commit()
            await db.refresh(patch)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to write patch: {str(e)}")

    return patch

@router.post("/{patch_id}/reject", response_model=PatchOut)
async def reject_patch(patch_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Patch).where(Patch.id == patch_id)
    res = await db.execute(stmt)
    patch = res.scalar_one_or_none()
    if not patch:
        raise HTTPException(status_code=404, detail="Patch not found")

    patch.status = "REJECTED"
    await db.commit()
    await db.refresh(patch)
    return patch
