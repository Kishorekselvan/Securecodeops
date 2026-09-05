from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.models import Threat
from app.schemas.schemas import ThreatOut

router = APIRouter(prefix="/threats", tags=["Threat Modeling"])

@router.get("", response_model=List[ThreatOut])
async def list_threats(
    scan_id: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Threat)
    if scan_id:
        stmt = stmt.where(Threat.scan_id == scan_id)
    if category:
        stmt = stmt.where(Threat.category == category)
    if risk_level:
        stmt = stmt.where(Threat.risk_level == risk_level)
    stmt = stmt.order_by(Threat.risk_score.desc())
    res = await db.execute(stmt)
    return res.scalars().all()

@router.get("/{threat_id}", response_model=ThreatOut)
async def get_threat(threat_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Threat).where(Threat.id == threat_id)
    res = await db.execute(stmt)
    threat = res.scalar_one_or_none()
    if not threat:
        raise HTTPException(status_code=404, detail="Threat model entry not found")
    return threat
