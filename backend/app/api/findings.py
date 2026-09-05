from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.models import Finding
from app.schemas.schemas import FindingOut

router = APIRouter(prefix="/findings", tags=["Findings"])

@router.get("", response_model=List[FindingOut])
async def list_findings(
    scan_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    scanner: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    ai_status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Finding)
    if scan_id:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if severity:
        stmt = stmt.where(Finding.severity == severity.upper())
    if category:
        stmt = stmt.where(Finding.category == category)
    if scanner:
        stmt = stmt.where(Finding.scanner == scanner.lower())
    if status:
        stmt = stmt.where(Finding.status == status.upper())
    if ai_status:
        stmt = stmt.where(Finding.ai_validation_status == ai_status.upper())
        
    stmt = stmt.order_by(Finding.created_at.desc())
    res = await db.execute(stmt)
    return res.scalars().all()

@router.get("/{finding_id}", response_model=FindingOut)
async def get_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Finding).where(Finding.id == finding_id)
    res = await db.execute(stmt)
    finding = res.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

@router.patch("/{finding_id}/status", response_model=FindingOut)
async def update_finding_status(
    finding_id: str,
    status: str = Query(..., pattern="^(OPEN|RESOLVED|FALSE_POSITIVE|SUPPRESSED)$"),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Finding).where(Finding.id == finding_id)
    res = await db.execute(stmt)
    finding = res.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    finding.status = status
    await db.commit()
    await db.refresh(finding)
    return finding
