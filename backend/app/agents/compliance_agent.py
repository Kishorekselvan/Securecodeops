import time
from typing import Dict, Any, List

COMPLIANCE_FRAMEWORKS = {
    "OWASP_TOP_10": [
        {"id": "A01:2021", "name": "Broken Access Control", "cwe_list": ["CWE-22", "CWE-285", "CWE-639"]},
        {"id": "A02:2021", "name": "Cryptographic Failures", "cwe_list": ["CWE-312", "CWE-327", "CWE-798"]},
        {"id": "A03:2021", "name": "Injection", "cwe_list": ["CWE-78", "CWE-89", "CWE-79", "CWE-95"]},
        {"id": "A04:2021", "name": "Insecure Design", "cwe_list": ["CWE-209", "CWE-699"]},
        {"id": "A05:2021", "name": "Security Misconfiguration", "cwe_list": ["CWE-942", "CWE-16"]},
        {"id": "A06:2021", "name": "Vulnerable and Outdated Components", "cwe_list": ["CWE-1395", "CWE-1104"]},
        {"id": "A07:2021", "name": "Identification and Authentication Failures", "cwe_list": ["CWE-287", "CWE-384"]},
        {"id": "A08:2021", "name": "Software and Data Integrity Failures", "cwe_list": ["CWE-502", "CWE-829"]},
        {"id": "A09:2021", "name": "Security Logging and Monitoring Failures", "cwe_list": ["CWE-778", "CWE-117"]},
        {"id": "A10:2021", "name": "Server-Side Request Forgery (SSRF)", "cwe_list": ["CWE-918"]}
    ],
    "GDPR": [
        {"id": "Art-32-1-a", "name": "Pseudonymisation and Encryption of Personal Data", "cwe_list": ["CWE-312", "CWE-798"]},
        {"id": "Art-32-1-b", "name": "Confidentiality, Integrity, and Availability of Processing Systems", "cwe_list": ["CWE-89", "CWE-78", "CWE-502"]},
        {"id": "Art-32-1-d", "name": "Regular Testing and Evaluation of Technical Security Measures", "cwe_list": ["CWE-1395"]}
    ],
    "ISO_27001": [
        {"id": "A.8.20", "name": "Network Security and Boundary Protection", "cwe_list": ["CWE-918", "CWE-942"]},
        {"id": "A.8.24", "name": "Use of Cryptography and Key Management", "cwe_list": ["CWE-327", "CWE-798"]},
        {"id": "A.8.28", "name": "Secure Coding and Application Security Practices", "cwe_list": ["CWE-89", "CWE-78", "CWE-79"]}
    ],
    "NIST_SP_800_53": [
        {"id": "AC-3", "name": "Access Enforcement", "cwe_list": ["CWE-22", "CWE-285"]},
        {"id": "IA-2", "name": "Identification and Authentication", "cwe_list": ["CWE-287", "CWE-798"]},
        {"id": "SC-13", "name": "Cryptographic Protection", "cwe_list": ["CWE-312", "CWE-327"]},
        {"id": "SI-10", "name": "Information Input Validation", "cwe_list": ["CWE-89", "CWE-78", "CWE-79"]}
    ],
    "PCI_DSS": [
        {"id": "Req-6.5", "name": "Address Common Flaws in Custom Code", "cwe_list": ["CWE-89", "CWE-78", "CWE-79", "CWE-502"]},
        {"id": "Req-3.4", "name": "Protect Cardholder and Sensitive Data with Strong Cryptography", "cwe_list": ["CWE-312", "CWE-798"]},
        {"id": "Req-6.2", "name": "Ensure Third-Party Software Components are Patch-Current", "cwe_list": ["CWE-1395"]}
    ]
}

class ComplianceAgent:
    def __init__(self):
        self.name = "Compliance Agent"
        self.agent_type = "compliance"

    async def execute(self, findings: List[Dict[str, Any]], dependencies: List[Dict[str, Any]]) -> Dict[str, Any]:
        start_time = time.time()
        compliance_checks: List[Dict[str, Any]] = []
        framework_scores: Dict[str, float] = {}

        # Collect failing CWEs from findings and dependencies
        failing_cwes: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            cwe = f.get("cwe")
            if cwe:
                failing_cwes.setdefault(cwe, []).append(f)

        for dep in dependencies:
            if dep.get("is_vulnerable"):
                failing_cwes.setdefault("CWE-1395", []).append({
                    "title": f"Vulnerable dependency {dep.get('package_name')}",
                    "file_path": dep.get("manifest_file"),
                    "severity": dep.get("severity", "HIGH")
                })

        for fw_name, controls in COMPLIANCE_FRAMEWORKS.items():
            fw_pass_count = 0
            
            for ctrl in controls:
                ctrl_id = ctrl["id"]
                ctrl_name = ctrl["name"]
                cwe_list = ctrl["cwe_list"]
                
                matched_violations = []
                affected_files = set()
                
                for cwe in cwe_list:
                    if cwe in failing_cwes:
                        for v in failing_cwes[cwe]:
                            matched_violations.append(f"{v.get('title')} ({cwe}) in {v.get('file_path')}")
                            if v.get("file_path"):
                                affected_files.add(v.get("file_path"))

                if not matched_violations:
                    status = "PASS"
                    score = 100.0
                    fw_pass_count += 1
                    evidence = ["No security violations mapped to this control detected in repository."]
                    recommendation = "Maintain current control effectiveness."
                else:
                    # If violations are all low/medium -> PARTIAL, if any HIGH/CRITICAL -> FAIL
                    has_critical = any("CRITICAL" in str(v) or "HIGH" in str(v) for v in matched_violations)
                    status = "FAIL" if has_critical else "PARTIAL"
                    score = 0.0 if status == "FAIL" else 50.0
                    evidence = matched_violations[:5]
                    recommendation = f"Remediate {len(matched_violations)} finding(s) violating control {ctrl_id}: {ctrl_name}."

                compliance_checks.append({
                    "framework": fw_name,
                    "control_id": ctrl_id,
                    "control_name": ctrl_name,
                    "status": status,
                    "score": score,
                    "evidence": evidence,
                    "affected_files": list(affected_files),
                    "recommendation": recommendation
                })

            framework_scores[fw_name] = round((fw_pass_count / len(controls)) * 100.0, 1)

        overall_compliance = round(sum(framework_scores.values()) / max(len(framework_scores), 1), 1)
        duration = round(time.time() - start_time, 2)

        return {
            "status": "COMPLETED",
            "duration_seconds": duration,
            "overall_compliance_score": overall_compliance,
            "framework_scores": framework_scores,
            "compliance_checks": compliance_checks
        }
