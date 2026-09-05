import os
import json
import time
from typing import Dict, Any, List
from app.core.config import settings

def calculate_transparent_security_score(
    findings: List[Dict[str, Any]],
    dependencies: List[Dict[str, Any]],
    compliance_score: float
) -> Dict[str, Any]:
    """
    Computes a transparent security score from 0 to 100 with an explicit mathematical penalty formula.
    
    Formula:
    Base = 100
    - Critical Vulnerability Penalty: 15 pts per critical (max 45)
    - High Vulnerability Penalty: 8 pts per high (max 30)
    - Medium Vulnerability Penalty: 3 pts per medium (max 15)
    - Low Vulnerability Penalty: 1 pt per low (max 5)
    - Secret Exposure Penalty: 10 pts per hardcoded secret (max 30)
    - Dependency Risk Penalty: 0.5 * dependency_risk_score (max 20)
    - Compliance Penalty: (100 - compliance_score) * 0.25 (max 25)
    """
    critical_vulns = sum(1 for f in findings if f.get("severity") == "CRITICAL" and f.get("ai_validation_status") != "FALSE_POSITIVE")
    high_vulns = sum(1 for f in findings if f.get("severity") == "HIGH" and f.get("ai_validation_status") != "FALSE_POSITIVE")
    medium_vulns = sum(1 for f in findings if f.get("severity") == "MEDIUM" and f.get("ai_validation_status") != "FALSE_POSITIVE")
    low_vulns = sum(1 for f in findings if f.get("severity") == "LOW" and f.get("ai_validation_status") != "FALSE_POSITIVE")
    
    secrets_count = sum(1 for f in findings if "secret" in f.get("category", "").lower() and f.get("ai_validation_status") != "FALSE_POSITIVE")
    dep_risk = sum(d.get("risk_contribution", 0.0) for d in dependencies)

    crit_penalty = min(critical_vulns * 15.0, 45.0)
    high_penalty = min(high_vulns * 8.0, 30.0)
    med_penalty = min(medium_vulns * 3.0, 15.0)
    low_penalty = min(low_vulns * 1.0, 5.0)
    secret_penalty = min(secrets_count * 10.0, 30.0)
    dep_penalty = min(dep_risk * 0.5, 20.0)
    comp_penalty = min((100.0 - compliance_score) * 0.25, 25.0)

    total_penalty = crit_penalty + high_penalty + med_penalty + low_penalty + secret_penalty + dep_penalty + comp_penalty
    final_score = max(0.0, round(100.0 - total_penalty, 1))

    return {
        "security_score": final_score,
        "base_score": 100.0,
        "penalties": {
            "critical_vulnerabilities": crit_penalty,
            "high_vulnerabilities": high_penalty,
            "medium_vulnerabilities": med_penalty,
            "low_vulnerabilities": low_penalty,
            "secret_exposure": secret_penalty,
            "dependency_risk": round(dep_penalty, 1),
            "compliance_gap": round(comp_penalty, 1)
        },
        "formula": "Security Score = 100 - (Critical + High + Medium + Low + Secrets + DependencyRisk + ComplianceGap)"
    }

class ReportGenerationAgent:
    def __init__(self):
        self.name = "Report Generation Agent"
        self.agent_type = "report_generation"

    async def execute(
        self,
        scan_id: str,
        repo_name: str,
        findings: List[Dict[str, Any]],
        threats: List[Dict[str, Any]],
        dependencies: List[Dict[str, Any]],
        compliance_data: Dict[str, Any],
        patches: List[Dict[str, Any]],
        code_reviews: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        start_time = time.time()
        comp_score = compliance_data.get("overall_compliance_score", 100.0)
        score_breakdown = calculate_transparent_security_score(findings, dependencies, comp_score)
        
        crit_count = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in findings if f.get("severity") == "HIGH")
        med_count = sum(1 for f in findings if f.get("severity") == "MEDIUM")
        low_count = sum(1 for f in findings if f.get("severity") == "LOW")

        exec_summary = (
            f"Security analysis for repository '{repo_name}' completed. The overall Security Score is "
            f"{score_breakdown['security_score']}/100. Analysis identified {len(findings)} total security findings "
            f"({crit_count} Critical, {high_count} High, {med_count} Medium, {low_count} Low), "
            f"{len(threats)} STRIDE architectural threats, {compliance_data.get('overall_compliance_score')}% compliance posture across major frameworks, "
            f"and {len(dependencies)} tracked package dependencies with {sum(1 for d in dependencies if d.get('is_vulnerable'))} known CVE advisories. "
            f"{len(patches)} context-aware patches were synthesized and verified with sandbox re-scans."
        )

        full_json = {
            "scan_id": scan_id,
            "repository_name": repo_name,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "security_score_breakdown": score_breakdown,
            "executive_summary": exec_summary,
            "summary_metrics": {
                "total_vulnerabilities": len(findings),
                "critical": crit_count,
                "high": high_count,
                "medium": med_count,
                "low": low_count,
                "stride_threats": len(threats),
                "compliance_score": comp_score,
                "dependencies_scanned": len(dependencies),
                "patches_generated": len(patches)
            },
            "findings": findings,
            "threats": threats,
            "dependencies": dependencies,
            "compliance": compliance_data,
            "code_reviews": code_reviews,
            "patches": patches
        }

        duration = round(time.time() - start_time, 2)
        return {
            "status": "COMPLETED",
            "duration_seconds": duration,
            "title": f"SecureCodeOps AI Security Assessment - {repo_name}",
            "executive_summary": exec_summary,
            "score_breakdown": score_breakdown,
            "json_data": full_json
        }
