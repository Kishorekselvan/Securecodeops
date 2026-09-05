from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.models import AgentLog
from app.schemas.schemas import AgentLogOut

router = APIRouter(prefix="/agent-logs", tags=["Agent Logs"])

@router.get("", response_model=List[AgentLogOut])
async def list_agent_logs(
    scan_id: str = Query(...),
    agent_name: Optional[str] = Query(None),
    level: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db)
):
    stmt = select(AgentLog).where(AgentLog.scan_id == scan_id)
    if agent_name:
        stmt = stmt.where(AgentLog.agent_name == agent_name)
    if level:
        stmt = stmt.where(AgentLog.level == level.upper())
    stmt = stmt.order_by(AgentLog.timestamp.asc())
    res = await db.execute(stmt)
    return res.scalars().all()
