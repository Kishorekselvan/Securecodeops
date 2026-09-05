from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.models import Finding, DeveloperFeedback
from app.schemas.schemas import FindingOut, DeveloperFeedbackCreate, DeveloperFeedbackOut, ContinuousLearningStatsOut
from app.analysis.learning_engine import learning_engine

router = APIRouter(prefix="/findings", tags=["Findings"])

@router.get("/learning/stats", response_model=ContinuousLearningStatsOut)
async def get_learning_stats():
    """Returns aggregated continuous learning statistics from the local knowledge base."""
    return learning_engine.get_stats()

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

@router.post("/{finding_id}/feedback", response_model=DeveloperFeedbackOut)
async def submit_developer_feedback(
    finding_id: str,
    feedback: DeveloperFeedbackCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Continuous Learning Feedback Endpoint (Paper Section II-B)
    Records developer feedback, updates the finding status, and feeds the local knowledge base.
    """
    stmt = select(Finding).where(Finding.id == finding_id)
    res = await db.execute(stmt)
    finding = res.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Update finding status accordingly
    if feedback.feedback_type == "FALSE_POSITIVE":
        finding.status = "FALSE_POSITIVE"
        finding.ai_validation_status = "FALSE_POSITIVE"
    elif feedback.feedback_type == "CONFIRMED_TRUE_POSITIVE":
        finding.status = "OPEN"
        finding.ai_validation_status = "VALIDATED"
    elif feedback.feedback_type == "SUPPRESSED":
        finding.status = "SUPPRESSED"

    feedback_record = DeveloperFeedback(
        finding_id=finding.id,
        rule_id=finding.cwe or finding.title,
        category=finding.category,
        file_pattern=finding.file_path,
        feedback_type=feedback.feedback_type,
        developer_notes=feedback.developer_notes
    )
    db.add(feedback_record)
    await db.commit()
    await db.refresh(feedback_record)

    # Ingest into Continuous Learning Engine local knowledge base
    learning_engine.record_feedback(
        finding_id=finding.id,
        category=finding.category,
        rule_id=finding.cwe or finding.title,
        file_path=finding.file_path,
        feedback_type=feedback.feedback_type,
        developer_notes=feedback.developer_notes
    )

    return feedback_record

@router.get("/{finding_id}/feedbacks", response_model=List[DeveloperFeedbackOut])
async def get_finding_feedbacks(finding_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(DeveloperFeedback).where(DeveloperFeedback.finding_id == finding_id).order_by(DeveloperFeedback.created_at.desc())
    res = await db.execute(stmt)
    return res.scalars().all()

