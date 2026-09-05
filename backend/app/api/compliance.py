from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.models import ComplianceCheck
from app.schemas.schemas import ComplianceCheckOut

router = APIRouter(prefix="/compliance", tags=["Compliance"])

@router.get("", response_model=List[ComplianceCheckOut])
async def list_compliance_checks(
    scan_id: Optional[str] = Query(None),
    framework: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(ComplianceCheck)
    if scan_id:
        stmt = stmt.where(ComplianceCheck.scan_id == scan_id)
    if framework:
        stmt = stmt.where(ComplianceCheck.framework == framework.upper())
    if status:
        stmt = stmt.where(ComplianceCheck.status == status.upper())
    stmt = stmt.order_by(ComplianceCheck.framework.asc(), ComplianceCheck.control_id.asc())
    res = await db.execute(stmt)
    return res.scalars().all()

@router.get("/framework-summary")
async def get_framework_summary(
    scan_id: str = Query(...),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(ComplianceCheck).where(ComplianceCheck.scan_id == scan_id)
    res = await db.execute(stmt)
    checks = res.scalars().all()
    
    summary: Dict[str, Any] = {}
    for c in checks:
        fw = c.framework
        if fw not in summary:
            summary[fw] = {"total_controls": 0, "pass": 0, "fail": 0, "partial": 0, "score": 0.0}
        summary[fw]["total_controls"] += 1
        st = c.status.lower()
        if st in summary[fw]:
            summary[fw][st] += 1

    for fw, stats in summary.items():
        total = stats["total_controls"]
        passes = stats["pass"]
        stats["score"] = round((passes / max(total, 1)) * 100.0, 1)

    return summary
