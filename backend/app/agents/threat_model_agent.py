import time
from typing import Dict, Any, List
from app.ai.provider import get_llm_provider
from app.ai.prompts import STRIDE_THREAT_SYSTEM_PROMPT
from app.analysis.data_flow import DataFlowAnalyzer

def calculate_risk_level(score: int) -> str:
    if score >= 17:
        return "Critical"
    elif score >= 10:
        return "High"
    elif score >= 5:
        return "Medium"
    return "Low"

class ThreatModelingAgent:
    def __init__(self):
        self.name = "Threat Modeling Agent"
        self.agent_type = "threat_modeling"
        self.provider = get_llm_provider()

    async def execute(self, repo_analysis: Dict[str, Any], findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        start_time = time.time()
        threats: List[Dict[str, Any]] = []

        endpoints = repo_analysis.get("endpoints", [])
        db_ops = repo_analysis.get("db_operations", [])
        auth_checks = repo_analysis.get("auth_checks", [])
        sensitive_data = repo_analysis.get("sensitive_data", [])

        # 1. Deterministic Architecture-driven STRIDE generation
        # Spoofing
        if not auth_checks or len(auth_checks) < len(endpoints):
            impact = 4
            prob = 4
            score = impact * prob
            threats.append({
                "category": "Spoofing",
                "title": "Unauthenticated API Request Spoofing / Missing Authentication",
                "description": "Public API endpoints lack explicit token validation or authentication middleware, permitting attackers to impersonate legitimate clients.",
                "affected_component": "API Gateway / Route Endpoints",
                "attack_vector": "Network HTTP Requests with omitted credentials",
                "impacted_assets": ["User Accounts", "Protected Resources"],
                "impact": impact,
                "probability": prob,
                "risk_score": score,
                "risk_level": calculate_risk_level(score),
                "existing_controls": [a["name"] for a in auth_checks] if auth_checks else ["None"],
                "recommended_controls": ["Enforce JWT/OAuth2 Bearer token authentication middleware globally."],
                "attack_path": [
                    {"step": 1, "name": "Unauthenticated Client", "type": "User_Input", "description": "Attacker crafts HTTP request without auth tokens."},
                    {"step": 2, "name": "Unprotected Endpoint", "type": "Entry_Point", "description": "Handler processes request without calling auth middleware."},
                    {"step": 3, "name": "Resource Compromise", "type": "Impacted_Asset", "description": "Privileged operations execute under guest identity."}
                ]
            })

        # Tampering & Information Disclosure via SQLi or sensitive data
        for f in findings:
            cat = f.get("category", "").lower()
            if "sql injection" in cat:
                impact = 5
                prob = 4
                score = impact * prob
                attack_path = DataFlowAnalyzer.generate_attack_path_for_finding(f, endpoints)
                threats.append({
                    "category": "Tampering",
                    "title": f"Database Tampering & Manipulation via {f.get('title')}",
                    "description": f"Untrusted input supplied to {f.get('file_path')} alters query logic, allowing attackers to modify database records or bypass schema integrity.",
                    "affected_component": f"{f.get('file_path')}:{f.get('line_number')}",
                    "attack_vector": "SQL Injection Payload in User Input",
                    "impacted_assets": ["Database Tables", "Application State"],
                    "impact": impact,
                    "probability": prob,
                    "risk_score": score,
                    "risk_level": calculate_risk_level(score),
                    "existing_controls": ["Dynamic SQL query execution"],
                    "recommended_controls": ["Use Parameterized Queries / ORM Prepared Statements."],
                    "attack_path": attack_path
                })
            elif "secret" in cat:
                impact = 5
                prob = 4
                score = impact * prob
                threats.append({
                    "category": "Information Disclosure",
                    "title": f"Credential Leakage / Information Disclosure ({f.get('title')})",
                    "description": f"Hardcoded credential located at {f.get('file_path')} compromises backend services.",
                    "affected_component": f"{f.get('file_path')}:{f.get('line_number')}",
                    "attack_vector": "Source Code Inspection / Artifact Extraction",
                    "impacted_assets": ["API Keys", "Cryptographic Secrets", "Database Credentials"],
                    "impact": impact,
                    "probability": prob,
                    "risk_score": score,
                    "risk_level": calculate_risk_level(score),
                    "existing_controls": ["Static code variable"],
                    "recommended_controls": ["Store all secrets in environment variables or KMS / Vault secrets manager."],
                    "attack_path": DataFlowAnalyzer.generate_attack_path_for_finding(f, endpoints)
                })

        # Repudiation
        impact = 3
        prob = 3
        score = impact * prob
        threats.append({
            "category": "Repudiation",
            "title": "Insufficient Audit Logging for State-Changing Operations",
            "description": "Lack of immutable audit logging on security-sensitive actions allows malicious actors to deny performing unauthorized updates.",
            "affected_component": "Application Business Logic",
            "attack_vector": "Tampered user parameters without log provenance",
            "impacted_assets": ["Audit Trail", "System Integrity"],
            "impact": impact,
            "probability": prob,
            "risk_score": score,
            "risk_level": calculate_risk_level(score),
            "existing_controls": ["Default runtime stdout"],
            "recommended_controls": ["Implement centralized tamper-evident audit logging with user identity tracking."],
            "attack_path": [
                {"step": 1, "name": "State Mutation", "type": "User_Input", "description": "Attacker triggers data deletion or modification."},
                {"step": 2, "name": "Missing Audit Event", "type": "Vulnerable_Sink", "description": "No record of user IP, timestamp, or operation stored."},
                {"step": 3, "name": "Non-Repudiation Failure", "type": "Impacted_Asset", "description": "Inability to correlate action to specific identity in forensic investigation."}
            ]
        })

        # Denial of Service
        impact = 3
        prob = 4
        score = impact * prob
        threats.append({
            "category": "Denial of Service",
            "title": "Unbounded Payload Ingestion & Missing Rate Limiting",
            "description": "Endpoints do not enforce per-client rate limits or request body size caps, enabling resource exhaustion.",
            "affected_component": "API Ingress / Worker Threads",
            "attack_vector": "HTTP Flood / High-Volume Concurrent Requests",
            "impacted_assets": ["Server CPU/Memory", "Database Connection Pool"],
            "impact": impact,
            "probability": prob,
            "risk_score": score,
            "risk_level": calculate_risk_level(score),
            "existing_controls": ["Default server socket listener"],
            "recommended_controls": ["Deploy IP/Token rate limiting and strict body size thresholds."],
            "attack_path": [
                {"step": 1, "name": "High-Concurrency Traffic", "type": "User_Input", "description": "Attacker dispatches thousands of concurrent requests."},
                {"step": 2, "name": "Worker Saturation", "type": "Vulnerable_Sink", "description": "Application pool exhausts available threads."},
                {"step": 3, "name": "Service Outage", "type": "Impacted_Asset", "description": "Legitimate requests receive HTTP 504 / 503 timeouts."}
            ]
        })

        # Elevation of Privilege
        impact = 5
        prob = 3
        score = impact * prob
        threats.append({
            "category": "Elevation of Privilege",
            "title": "Broken Object Level Authorization (BOLA / IDOR)",
            "description": "Endpoints accepting direct object IDs allow authenticated users to view or modify records belonging to other tenants.",
            "affected_component": "Database Query Handlers",
            "attack_vector": "Altering path parameter IDs (`/users/1` -> `/users/2`)",
            "impacted_assets": ["Tenant Isolation", "Admin Privileges"],
            "impact": impact,
            "probability": prob,
            "risk_score": score,
            "risk_level": calculate_risk_level(score),
            "existing_controls": ["Basic session check"],
            "recommended_controls": ["Validate user ownership on every database lookup before returning resource."],
            "attack_path": [
                {"step": 1, "name": "ID Parameter Tampering", "type": "User_Input", "description": "Attacker supplies victim's resource ID."},
                {"step": 2, "name": "Missing Ownership Filter", "type": "Sanitization_Bypass", "description": "Database query retrieves record by ID without checking tenant owner ID."},
                {"step": 3, "name": "Privilege Escalation", "type": "Impacted_Asset", "description": "Attacker reads or mutates unauthorized private entity."}
            ]
        })

        # Sort threats by risk score descending
        threats.sort(key=lambda t: t["risk_score"], reverse=True)

        duration = round(time.time() - start_time, 2)
        return {
            "status": "COMPLETED",
            "duration_seconds": duration,
            "threats_count": len(threats),
            "threats": threats
        }
