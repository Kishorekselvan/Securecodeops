from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.models import Dependency
from app.schemas.schemas import DependencyOut

router = APIRouter(prefix="/dependencies", tags=["Dependencies"])

@router.get("", response_model=List[DependencyOut])
async def list_dependencies(
    scan_id: Optional[str] = Query(None),
    vulnerable_only: bool = Query(False),
    ecosystem: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Dependency)
    if scan_id:
        stmt = stmt.where(Dependency.scan_id == scan_id)
    if vulnerable_only:
        stmt = stmt.where(Dependency.is_vulnerable == True)
    if ecosystem:
        stmt = stmt.where(Dependency.ecosystem == ecosystem.lower())
    stmt = stmt.order_by(Dependency.risk_contribution.desc(), Dependency.package_name.asc())
    res = await db.execute(stmt)
    return res.scalars().all()

@router.get("/{dep_id}", response_model=DependencyOut)
async def get_dependency(dep_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Dependency).where(Dependency.id == dep_id)
    res = await db.execute(stmt)
    dep = res.scalar_one_or_none()
    if not dep:
        raise HTTPException(status_code=404, detail="Dependency record not found")
    return dep
