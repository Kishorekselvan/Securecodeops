import asyncio
import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db.session import get_db, AsyncSessionLocal
from app.models.models import Scan, Repository
from app.schemas.schemas import ScanCreate, ScanSummary, ScanDetailsOut
from app.agents.supervisor import SupervisorAgent
from app.services.events import event_manager

router = APIRouter(prefix="/scans", tags=["Scans"])

async def _run_supervisor_in_background(scan_id: str):
    async with AsyncSessionLocal() as session:
        supervisor = SupervisorAgent(session)
        await supervisor.run_scan_pipeline(scan_id)

@router.post("", response_model=ScanSummary)
async def create_and_start_scan(
    scan_in: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(Repository).where(Repository.id == scan_in.repository_id)
    res = await db.execute(stmt)
    repo = res.scalar_one_or_none()
    if not repo:
        raise HTTPException(status_code=404, detail="Repository not found")

    scan = Scan(
        repository_id=scan_in.repository_id,
        status="QUEUED",
        current_stage="Queued for Supervisor Agent"
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Launch multi-agent pipeline in background
    background_tasks.add_task(_run_supervisor_in_background, scan.id)
    return scan

@router.get("", response_model=List[ScanSummary])
async def list_scans(db: AsyncSession = Depends(get_db)):
    stmt = select(Scan).order_by(Scan.started_at.desc())
    res = await db.execute(stmt)
    return res.scalars().all()

@router.get("/{scan_id}", response_model=ScanDetailsOut)
async def get_scan_details(scan_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Scan).options(
        selectinload(Scan.repository),
        selectinload(Scan.agents),
        selectinload(Scan.findings),
        selectinload(Scan.threats),
        selectinload(Scan.dependencies),
        selectinload(Scan.compliance_checks),
        selectinload(Scan.patches),
        selectinload(Scan.report)
    ).where(Scan.id == scan_id)
    
    res = await db.execute(stmt)
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Attach repository name
    scan_dict = ScanDetailsOut.model_validate(scan)
    if scan.repository:
        scan_dict.repository_name = scan.repository.name
    return scan_dict

@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Scan).where(Scan.id == scan_id)
    res = await db.execute(stmt)
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {
        "id": scan.id,
        "status": scan.status,
        "progress": scan.progress,
        "current_stage": scan.current_stage,
        "security_score": scan.security_score,
        "duration_seconds": scan.duration_seconds
    }

@router.get("/{scan_id}/events")
async def stream_scan_events(scan_id: str):
    """Server-Sent Events (SSE) live event stream for scan progress and agent activities."""
    queue = event_manager.subscribe_sse(scan_id)

    async def event_generator():
        try:
            while True:
                data = await queue.get()
                yield f"event: {data['event']}\ndata: {json.dumps(data)}\n\n"
                if data["event"] in ["SCAN_COMPLETED", "SCAN_FAILED"]:
                    break
        finally:
            event_manager.unsubscribe_sse(scan_id, queue)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@router.websocket("/ws/{scan_id}")
async def websocket_scan_events(websocket: WebSocket, scan_id: str):
    await event_manager.connect_ws(scan_id, websocket)
    try:
        while True:
            # Keep connection open until client disconnects
            await websocket.receive_text()
    except WebSocketDisconnect:
        event_manager.disconnect_ws(scan_id, websocket)
