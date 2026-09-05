from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.models.models import Scan, FileRecord, Finding, Threat, Dependency
from app.schemas.schemas import KnowledgeGraphOut
from app.analysis.knowledge_graph import KnowledgeGraphBuilder

router = APIRouter(prefix="/knowledge-graph", tags=["Knowledge Graph"])

@router.get("/{scan_id}", response_model=KnowledgeGraphOut)
async def get_knowledge_graph(scan_id: str, db: AsyncSession = Depends(get_db)):
    stmt_scan = select(Scan).options(
        selectinload(Scan.repository).selectinload(FileRecord.repository)
    ).where(Scan.id == scan_id)
    
    stmt = select(Scan).where(Scan.id == scan_id)
    res = await db.execute(stmt)
    scan = res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    kg_builder = KnowledgeGraphBuilder(scan_id)

    # 1. Add Files and their AST symbols
    stmt_files = select(FileRecord).where(FileRecord.repository_id == scan.repository_id)
    res_files = await db.execute(stmt_files)
    files = res_files.scalars().all()

    for f in files:
        kg_builder.add_file_node(f.relative_path, f.language or "Unknown", f.line_count)
        ast_sum = f.ast_summary or {}
        
        for sym in ast_sum.get("symbols", []):
            if sym.get("type") == "function":
                kg_builder.add_function_node(f.relative_path, sym["name"], sym["line"], sym.get("details", {}).get("args"))

        for ep in ast_sum.get("endpoints", []):
            kg_builder.add_endpoint_node(
                f.relative_path,
                ep["name"],
                ep.get("details", {}).get("method", "HTTP"),
                ep.get("details", {}).get("path", ep["name"]),
                ep["line"]
            )

        for db_call in ast_sum.get("db_operations", []):
            kg_builder.add_database_node(f.relative_path, db_call["name"], db_call["line"])

        for auth in ast_sum.get("auth_checks", []):
            kg_builder.add_auth_node(f.relative_path, auth["name"], auth["line"])

        for sec in ast_sum.get("sensitive_data", []):
            kg_builder.add_sensitive_data_node(f.relative_path, sec["name"], sec["line"])

    # 2. Add Dependencies
    stmt_deps = select(Dependency).where(Dependency.scan_id == scan_id)
    res_deps = await db.execute(stmt_deps)
    for dep in res_deps.scalars().all():
        kg_builder.add_dependency_node(dep.package_name, dep.installed_version, dep.is_vulnerable, dep.cve_id)

    # 3. Add Findings
    stmt_findings = select(Finding).where(Finding.scan_id == scan_id)
    res_findings = await db.execute(stmt_findings)
    for find in res_findings.scalars().all():
        kg_builder.add_finding_node(find.id, find.title, find.severity, find.file_path, find.line_number)

    # 4. Add Threats
    stmt_threats = select(Threat).where(Threat.scan_id == scan_id)
    res_threats = await db.execute(stmt_threats)
    for thr in res_threats.scalars().all():
        kg_builder.add_threat_node(thr.id, thr.title, thr.category, thr.risk_level, thr.affected_component)

    return kg_builder.to_dict()
