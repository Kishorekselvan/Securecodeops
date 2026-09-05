import os
import io
import csv
import json
from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.models.models import Report, Scan, Finding
from app.schemas.schemas import ReportOut

router = APIRouter(prefix="/reports", tags=["Reports"])

@router.get("/{scan_id}", response_model=ReportOut)
async def get_report_by_scan_id(scan_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Report).where(Report.scan_id == scan_id)
    res = await db.execute(stmt)
    report = res.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not generated yet for this scan.")
    return report

@router.get("/{scan_id}/pdf")
async def download_pdf_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Report).where(Report.scan_id == scan_id)
    res = await db.execute(stmt)
    report = res.scalar_one_or_none()
    if not report or not report.pdf_path or not os.path.exists(report.pdf_path):
        raise HTTPException(status_code=404, detail="PDF report not found.")
    
    return FileResponse(
        report.pdf_path,
        media_type="application/pdf",
        filename=os.path.basename(report.pdf_path)
    )

@router.get("/{scan_id}/export-json")
async def export_json_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Report).where(Report.scan_id == scan_id)
    res = await db.execute(stmt)
    report = res.scalar_one_or_none()
    if not report or not report.json_data:
        raise HTTPException(status_code=404, detail="Report JSON data not found.")
    
    content = json.dumps(report.json_data, indent=2)
    return Response(
        content=content,
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=SecureCodeOps_Scan_{scan_id[:8]}.json"}
    )

@router.get("/{scan_id}/export-csv")
async def export_findings_csv(scan_id: str, db: AsyncSession = Depends(get_db)):
    stmt = select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.severity.asc())
    res = await db.execute(stmt)
    findings = res.scalars().all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Finding ID", "Severity", "Title", "Category", "CWE", "OWASP",
        "File Path", "Line", "Scanner", "Status", "AI Validation", "Confidence"
    ])

    for f in findings:
        writer.writerow([
            f.id, f.severity, f.title, f.category, f.cwe or "", f.owasp or "",
            f.file_path, f.line_number or "", f.scanner, f.status,
            f.ai_validation_status, f.confidence
        ])

    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=findings_scan_{scan_id[:8]}.csv"}
    )
