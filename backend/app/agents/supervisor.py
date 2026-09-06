import os
import uuid
import time
import datetime
from typing import Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.models import (
    Scan, ScanAgent, FileRecord, Finding, Threat, Dependency, ComplianceCheck, Patch, Report, AgentLog, Repository
)
from app.services.events import event_manager
from app.services.pdf_generator import SecurityReportPDFGenerator
from app.core.config import settings

from app.agents.repository_agent import RepositoryAnalysisAgent
from app.agents.threat_model_agent import ThreatModelingAgent
from app.agents.vulnerability_agent import VulnerabilityDetectionAgent
from app.agents.dependency_agent import DependencyScannerAgent
from app.agents.code_review_agent import SecureCodeReviewAgent
from app.agents.compliance_agent import ComplianceAgent
from app.agents.patch_agent import PatchRecommendationAgent
from app.agents.report_agent import ReportGenerationAgent

class SupervisorAgent:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.repo_agent = RepositoryAnalysisAgent()
        self.vuln_agent = VulnerabilityDetectionAgent()
        self.threat_agent = ThreatModelingAgent()
        self.dep_agent = DependencyScannerAgent()
        self.code_review_agent = SecureCodeReviewAgent()
        self.compliance_agent = ComplianceAgent()
        self.patch_agent = PatchRecommendationAgent()
        self.report_agent = ReportGenerationAgent()

    async def log_agent_event(self, scan_id: str, agent_name: str, level: str, message: str, details: Dict[str, Any] = None):
        log_entry = AgentLog(
            scan_id=scan_id,
            agent_name=agent_name,
            level=level,
            message=message,
            details=details or {}
        )
        self.db.add(log_entry)
        await self.db.commit()
        await event_manager.broadcast_event(scan_id, "AGENT_LOG", {
            "agent_name": agent_name,
            "level": level,
            "message": message,
            "timestamp": datetime.datetime.utcnow().isoformat()
        })

    async def update_scan_progress(self, scan: Scan, progress: float, stage: str):
        scan.progress = progress
        scan.current_stage = stage
        await self.db.commit()
        await event_manager.broadcast_event(scan.id, "SCAN_PROGRESS", {
            "scan_id": scan.id,
            "progress": progress,
            "current_stage": stage,
            "status": scan.status
        })

    async def run_scan_pipeline(self, scan_id: str):
        # 1. Fetch Scan and Repository
        stmt = select(Scan).where(Scan.id == scan_id)
        res = await self.db.execute(stmt)
        scan = res.scalar_one_or_none()
        if not scan:
            return

        stmt_repo = select(Repository).where(Repository.id == scan.repository_id)
        res_repo = await self.db.execute(stmt_repo)
        repo = res_repo.scalar_one_or_none()
        if not repo:
            scan.status = "FAILED"
            scan.error_message = "Repository record not found."
            await self.db.commit()
            return

        scan.status = "RUNNING"
        scan.started_at = datetime.datetime.utcnow()
        await self.db.commit()
        
        start_overall_time = time.time()

        try:
            repo_dir = repo.storage_path
            
            # --- STAGE 1: Repository Analysis Agent ---
            await self.update_scan_progress(scan, 10.0, "Repository Analysis Agent Running")
            await self.log_agent_event(scan_id, self.repo_agent.name, "INFO", "Inspecting directory structure, parsing multi-language ASTs, and building Knowledge Graph.")
            
            repo_res = await self.repo_agent.execute(repo_dir, scan_id)
            
            # Save files
            for f in repo_res.get("files", []):
                file_rec = FileRecord(
                    repository_id=repo.id,
                    relative_path=f["relative_path"],
                    language=f["language"],
                    size_bytes=f["size_bytes"],
                    line_count=f["line_count"],
                    ast_summary=f["ast_summary"],
                    is_sensitive=f["is_sensitive"]
                )
                self.db.add(file_rec)
                
            # Update repo metadata
            repo.languages = repo_res.get("languages", [])
            repo.frameworks = repo_res.get("frameworks", [])
            repo.file_count = repo_res.get("file_count", 0)
            repo.lines_of_code = repo_res.get("lines_of_code", 0)
            
            # Record Agent completion
            agent_rec = ScanAgent(
                scan_id=scan_id,
                name=self.repo_agent.name,
                agent_type=self.repo_agent.agent_type,
                status="COMPLETED",
                duration_seconds=repo_res["duration_seconds"],
                findings_count=len(repo_res.get("files", [])),
                input_summary={"repo_dir": repo_dir},
                output_summary={"languages": repo.languages, "frameworks": repo.frameworks, "files": repo.file_count}
            )
            self.db.add(agent_rec)
            await self.db.commit()
            await self.log_agent_event(scan_id, self.repo_agent.name, "SUCCESS", f"Identified {repo.file_count} files ({repo.lines_of_code} LOC), languages: {repo.languages}, frameworks: {repo.frameworks}.")

            # --- STAGE 2: Vulnerability Detection Agent ---
            await self.update_scan_progress(scan, 30.0, "Vulnerability Detection & AI Validation Agent")
            await self.log_agent_event(scan_id, self.vuln_agent.name, "INFO", "Executing Semgrep, Bandit, Trivy, GitLeaks, and AI Exploitability Validation.")

            vuln_res = await self.vuln_agent.execute(repo_dir, scan_id)
            all_findings = vuln_res.get("findings", [])
            
            # Save findings
            for f in all_findings:
                fid = str(uuid.uuid4())
                f["id"] = fid  # Keep in dict for patch agent and threats reference
                finding_rec = Finding(
                    id=fid,
                    scan_id=scan_id,
                    title=f["title"],
                    description=f["description"],
                    severity=f["severity"],
                    confidence=f["confidence"],
                    category=f["category"],
                    cwe=f.get("cwe"),
                    owasp=f.get("owasp"),
                    file_path=f["file_path"],
                    line_number=f.get("line_number"),
                    end_line_number=f.get("end_line_number"),
                    code_snippet=f.get("code_snippet"),
                    evidence=f.get("evidence", {}),
                    scanner=f["scanner"],
                    status="OPEN",
                    ai_validation_status=f.get("ai_validation_status", "PENDING"),
                    ai_reasoning=f.get("ai_reasoning"),
                    ai_confidence=f.get("ai_confidence"),
                    ai_severity_adjustment=f.get("ai_severity_adjustment"),
                    ai_attack_scenario=f.get("ai_attack_scenario"),
                    ai_remediation=f.get("ai_remediation")
                )
                self.db.add(finding_rec)

            agent_rec = ScanAgent(
                scan_id=scan_id,
                name=self.vuln_agent.name,
                agent_type=self.vuln_agent.agent_type,
                status="COMPLETED",
                duration_seconds=vuln_res["duration_seconds"],
                findings_count=len(all_findings),
                input_summary={"target": repo_dir},
                output_summary={"findings_detected": len(all_findings), "scanners": vuln_res.get("scanner_statuses")}
            )
            self.db.add(agent_rec)
            await self.db.commit()
            await self.log_agent_event(scan_id, self.vuln_agent.name, "SUCCESS", f"Normalized {len(all_findings)} security findings across deterministic scanners with AI validation.")

            # --- STAGE 3: Dependency Scanner Agent ---
            await self.update_scan_progress(scan, 50.0, "Dependency Scanner Agent")
            await self.log_agent_event(scan_id, self.dep_agent.name, "INFO", "Parsing package manifests, auditing CVEs, and computing reachability exposure factors.")

            dep_res = await self.dep_agent.execute(repo_dir, repo_res.get("files", []))
            all_deps = dep_res.get("dependencies", [])

            for d in all_deps:
                dep_rec = Dependency(
                    scan_id=scan_id,
                    package_name=d["package_name"],
                    installed_version=d["installed_version"],
                    ecosystem=d["ecosystem"],
                    manifest_file=d["manifest_file"],
                    is_direct=d["is_direct"],
                    is_vulnerable=d["is_vulnerable"],
                    cve_id=d.get("cve_id"),
                    cvss_score=d.get("cvss_score"),
                    severity=d.get("severity"),
                    affected_versions=d.get("affected_versions"),
                    fixed_version=d.get("fixed_version"),
                    exposure_factor=d.get("exposure_factor", 1.0),
                    risk_contribution=d.get("risk_contribution", 0.0),
                    recommendation=d.get("recommendation")
                )
                self.db.add(dep_rec)

            agent_rec = ScanAgent(
                scan_id=scan_id,
                name=self.dep_agent.name,
                agent_type=self.dep_agent.agent_type,
                status="COMPLETED",
                duration_seconds=dep_res["duration_seconds"],
                findings_count=dep_res.get("vulnerable_dependencies", 0),
                input_summary={"manifest_types": ["requirements.txt", "package.json", "pom.xml"]},
                output_summary={"scanned": dep_res["total_dependencies"], "vulnerable": dep_res["vulnerable_dependencies"]}
            )
            self.db.add(agent_rec)
            await self.db.commit()
            await self.log_agent_event(scan_id, self.dep_agent.name, "SUCCESS", f"Audited {dep_res['total_dependencies']} dependencies. Found {dep_res['vulnerable_dependencies']} vulnerable packages.")

            # --- STAGE 4: Threat Modeling Agent ---
            await self.update_scan_progress(scan, 65.0, "STRIDE Threat Modeling Agent")
            await self.log_agent_event(scan_id, self.threat_agent.name, "INFO", "Conducting STRIDE threat analysis, calculating Impact x Probability risk, and mapping attack paths.")

            threat_res = await self.threat_agent.execute(repo_res, all_findings)
            all_threats = threat_res.get("threats", [])

            for t in all_threats:
                threat_rec = Threat(
                    scan_id=scan_id,
                    category=t["category"],
                    title=t["title"],
                    description=t["description"],
                    affected_component=t["affected_component"],
                    attack_vector=t["attack_vector"],
                    impacted_assets=t.get("impacted_assets", []),
                    impact=t["impact"],
                    probability=t["probability"],
                    risk_score=t["risk_score"],
                    risk_level=t["risk_level"],
                    existing_controls=t.get("existing_controls", []),
                    recommended_controls=t.get("recommended_controls", []),
                    attack_path=t.get("attack_path", [])
                )
                self.db.add(threat_rec)

            agent_rec = ScanAgent(
                scan_id=scan_id,
                name=self.threat_agent.name,
                agent_type=self.threat_agent.agent_type,
                status="COMPLETED",
                duration_seconds=threat_res["duration_seconds"],
                findings_count=len(all_threats),
                input_summary={"components_analyzed": len(repo_res.get("endpoints", [])) + len(repo_res.get("db_operations", []))},
                output_summary={"threats_generated": len(all_threats)}
            )
            self.db.add(agent_rec)
            await self.db.commit()
            await self.log_agent_event(scan_id, self.threat_agent.name, "SUCCESS", f"Generated {len(all_threats)} STRIDE threat models with concrete attack-path vectors.")

            # --- STAGE 5: Secure Code Review Agent ---
            await self.update_scan_progress(scan, 75.0, "Secure Code Review Agent")
            await self.log_agent_event(scan_id, self.code_review_agent.name, "INFO", "Auditing 13 security domains: Auth, Cryptography, Logging, Error Handling, Memory Safety.")

            code_review_res = await self.code_review_agent.execute(repo_dir, repo_res.get("files", []))
            all_reviews = code_review_res.get("issues", [])

            agent_rec = ScanAgent(
                scan_id=scan_id,
                name=self.code_review_agent.name,
                agent_type=self.code_review_agent.agent_type,
                status="COMPLETED",
                duration_seconds=code_review_res["duration_seconds"],
                findings_count=len(all_reviews),
                input_summary={"domains_checked": 13},
                output_summary={"issues_identified": len(all_reviews)}
            )
            self.db.add(agent_rec)
            await self.db.commit()
            await self.log_agent_event(scan_id, self.code_review_agent.name, "SUCCESS", f"Completed 13-domain code review with {len(all_reviews)} targeted recommendations.")

            # --- STAGE 6: Compliance Agent ---
            await self.update_scan_progress(scan, 85.0, "Compliance Verification Agent")
            await self.log_agent_event(scan_id, self.compliance_agent.name, "INFO", "Evaluating OWASP Top 10 2021, GDPR Art 32, ISO 27001, NIST SP 800-53, and PCI-DSS.")

            comp_res = await self.compliance_agent.execute(all_findings, all_deps)
            all_comp_checks = comp_res.get("compliance_checks", [])

            for c in all_comp_checks:
                comp_rec = ComplianceCheck(
                    scan_id=scan_id,
                    framework=c["framework"],
                    control_id=c["control_id"],
                    control_name=c["control_name"],
                    status=c["status"],
                    score=c["score"],
                    evidence=c.get("evidence", []),
                    affected_files=c.get("affected_files", []),
                    recommendation=c.get("recommendation")
                )
                self.db.add(comp_rec)

            agent_rec = ScanAgent(
                scan_id=scan_id,
                name=self.compliance_agent.name,
                agent_type=self.compliance_agent.agent_type,
                status="COMPLETED",
                duration_seconds=comp_res["duration_seconds"],
                findings_count=len(all_comp_checks),
                input_summary={"frameworks": list(comp_res.get("framework_scores", {}).keys())},
                output_summary={"overall_compliance": comp_res.get("overall_compliance_score")}
            )
            self.db.add(agent_rec)
            await self.db.commit()
            await self.log_agent_event(scan_id, self.compliance_agent.name, "SUCCESS", f"Computed overall compliance score: {comp_res.get('overall_compliance_score')}% across 5 frameworks.")

            # --- STAGE 7: Patch Recommendation & Validation Agent ---
            await self.update_scan_progress(scan, 92.0, "Patch Recommendation & Re-Scan Validation Agent")
            await self.log_agent_event(scan_id, self.patch_agent.name, "INFO", "Synthesizing context-aware patches and executing sandbox re-scans for validation.")

            all_patches = await self.patch_agent.generate_and_validate_patches(repo_dir, all_findings)

            for p in all_patches:
                patch_rec = Patch(
                    scan_id=scan_id,
                    finding_id=p["finding_id"],
                    file_path=p["file_path"],
                    original_code=p["original_code"],
                    patched_code=p["patched_code"],
                    diff=p["diff"],
                    explanation=p["explanation"],
                    confidence=p["confidence"],
                    status=p["status"],
                    is_validated=p["is_validated"],
                    vulnerabilities_before=p["vulnerabilities_before"],
                    vulnerabilities_after=p["vulnerabilities_after"],
                    vulnerabilities_resolved=p["vulnerabilities_resolved"],
                    vulnerabilities_introduced=p["vulnerabilities_introduced"],
                    validation_output=p.get("validation_output")
                )
                self.db.add(patch_rec)

            agent_rec = ScanAgent(
                scan_id=scan_id,
                name=self.patch_agent.name,
                agent_type=self.patch_agent.agent_type,
                status="COMPLETED",
                duration_seconds=3.0,
                findings_count=len(all_patches),
                input_summary={"validated_findings": len(all_findings)},
                output_summary={"patches_created": len(all_patches), "re_scan_verified": sum(1 for p in all_patches if p.get("is_validated"))}
            )
            self.db.add(agent_rec)
            await self.db.commit()
            await self.log_agent_event(scan_id, self.patch_agent.name, "SUCCESS", f"Generated {len(all_patches)} secure patches ({sum(1 for p in all_patches if p.get('is_validated'))} verified by sandbox re-scanning).")

            # --- STAGE 8: Report Generation Agent ---
            await self.update_scan_progress(scan, 98.0, "Report Generation Agent")
            await self.log_agent_event(scan_id, self.report_agent.name, "INFO", "Compiling Executive Summary, transparent Security Score, and generating downloadable PDF report.")

            report_res = await self.report_agent.execute(
                scan_id=scan_id,
                repo_name=repo.name,
                findings=all_findings,
                threats=all_threats,
                dependencies=all_deps,
                compliance_data=comp_res,
                patches=all_patches,
                code_reviews=all_reviews
            )

            # Generate PDF file
            pdf_filename = f"Security_Report_{repo.name}_{scan_id[:8]}.pdf"
            pdf_path = os.path.join(settings.REPORTS_DIR, pdf_filename)
            try:
                SecurityReportPDFGenerator.generate_pdf(report_res["json_data"], pdf_path)
            except Exception as pdf_err:
                pdf_path = None

            report_rec = Report(
                scan_id=scan_id,
                title=report_res["title"],
                executive_summary=report_res["executive_summary"],
                score_breakdown=report_res["score_breakdown"],
                pdf_path=pdf_path,
                json_data=report_res["json_data"]
            )
            self.db.add(report_rec)

            agent_rec = ScanAgent(
                scan_id=scan_id,
                name=self.report_agent.name,
                agent_type=self.report_agent.agent_type,
                status="COMPLETED",
                duration_seconds=report_res["duration_seconds"],
                findings_count=1,
                input_summary={"scan_id": scan_id},
                output_summary={"security_score": report_res["score_breakdown"]["security_score"], "pdf_generated": bool(pdf_path)}
            )
            self.db.add(agent_rec)

            # --- Finalize Scan ---
            total_duration = round(time.time() - start_overall_time, 2)
            
            crit_count = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
            high_count = sum(1 for f in all_findings if f.get("severity") == "HIGH")
            med_count = sum(1 for f in all_findings if f.get("severity") == "MEDIUM")
            low_count = sum(1 for f in all_findings if f.get("severity") == "LOW")
            info_count = sum(1 for f in all_findings if f.get("severity") == "INFO")
            
            fp_count = sum(1 for f in all_findings if f.get("ai_validation_status") == "FALSE_POSITIVE")
            fp_rate = round((fp_count / max(len(all_findings), 1)) * 100.0, 1)

            scan.status = "COMPLETED"
            scan.progress = 100.0
            scan.current_stage = "Analysis Completed Successfully"
            scan.security_score = report_res["score_breakdown"]["security_score"]
            scan.compliance_score = comp_res.get("overall_compliance_score", 100.0)
            scan.dependency_risk = dep_res.get("dependency_risk_score", 0.0)
            scan.false_positive_reduction_rate = fp_rate
            scan.total_vulnerabilities = len(all_findings)
            scan.critical_count = crit_count
            scan.high_count = high_count
            scan.medium_count = med_count
            scan.low_count = low_count
            scan.info_count = info_count
            scan.dependency_vulnerabilities = dep_res.get("vulnerable_dependencies", 0)
            scan.completed_at = datetime.datetime.utcnow()
            scan.duration_seconds = total_duration

            await self.db.commit()
            await self.log_agent_event(scan_id, "Supervisor Agent", "SUCCESS", f"Multi-Agent DevSecOps workflow completed in {total_duration}s. Final Security Score: {scan.security_score}/100.")
            await event_manager.broadcast_event(scan_id, "SCAN_COMPLETED", {
                "scan_id": scan_id,
                "status": "COMPLETED",
                "security_score": scan.security_score,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "duration_seconds": total_duration
            })

        except Exception as e:
            scan.status = "FAILED"
            scan.current_stage = "Pipeline Failed"
            scan.error_message = str(e)
            scan.completed_at = datetime.datetime.utcnow()
            scan.duration_seconds = round(time.time() - start_overall_time, 2)
            await self.db.commit()
            await self.log_agent_event(scan_id, "Supervisor Agent", "ERROR", f"Pipeline error: {str(e)}")
            await event_manager.broadcast_event(scan_id, "SCAN_FAILED", {
                "scan_id": scan_id,
                "error": str(e)
            })
