import os
import json
import time
import shutil
from typing import List, Dict, Any, Optional
from app.scanners.base import BaseScanner
from app.analysis.dependency_parser import DependencyParser

class TrivyScanner(BaseScanner):
    def __init__(self, enabled: bool = True):
        super().__init__("trivy", enabled)

    def is_available(self) -> bool:
        return shutil.which("trivy") is not None

    def scan(self, target_dir: str) -> Dict[str, Any]:
        start_time = time.time()
        findings = []
        is_native = self.is_available()

        if is_native and self.enabled:
            output = self.run_cli_command(
                ["trivy", "fs", "--format", "json", "-q", target_dir],
                cwd=target_dir,
                timeout_seconds=60
            )
            if output:
                try:
                    data = json.loads(output)
                    for target in data.get("Results", []):
                        target_file = target.get("Target", "manifest")
                        rel_path = os.path.relpath(target_file, target_dir) if os.path.isabs(target_file) else target_file
                        for vuln in target.get("Vulnerabilities", []):
                            findings.append({
                                "id": f"trivy-{vuln.get('VulnerabilityID')}-{rel_path}",
                                "title": f"Vulnerable Dependency: {vuln.get('PkgName')}@{vuln.get('InstalledVersion')}",
                                "description": vuln.get("Title") or vuln.get("Description") or "Vulnerable dependency identified.",
                                "severity": vuln.get("Severity", "MEDIUM").upper(),
                                "confidence": 0.95,
                                "category": "Vulnerable Dependency",
                                "cwe": (vuln.get("CweIDs") or ["CWE-1395"])[0],
                                "owasp": "A06:2021-Vulnerable and Outdated Components",
                                "file_path": rel_path.replace("\\", "/"),
                                "line_number": 1,
                                "end_line_number": 1,
                                "code_snippet": f"{vuln.get('PkgName')} == {vuln.get('InstalledVersion')}",
                                "evidence": {
                                    "cve": vuln.get("VulnerabilityID"),
                                    "installed_version": vuln.get("InstalledVersion"),
                                    "fixed_version": vuln.get("FixedVersion"),
                                    "cvss": vuln.get("CVSS", {}).get("nvd", {}).get("V3Score")
                                },
                                "scanner": "trivy"
                            })
                    return {
                        "scanner": "trivy",
                        "is_native": True,
                        "executed": True,
                        "findings": findings,
                        "error": None,
                        "duration_seconds": round(time.time() - start_time, 2)
                    }
                except Exception:
                    pass

        # Fallback Dependency Scanner
        findings = self._run_manifest_scan(target_dir)
        return {
            "scanner": "trivy",
            "is_native": False,
            "executed": True,
            "findings": findings,
            "error": None if findings else "Native trivy unavailable; executed manifest dependency scanner.",
            "duration_seconds": round(time.time() - start_time, 2)
        }

    def _run_manifest_scan(self, target_dir: str) -> List[Dict[str, Any]]:
        findings = []
        for root, _, files in os.walk(target_dir):
            if any(ignore in root for ignore in ['.git', 'node_modules', '__pycache__', '.venv']):
                continue
            for file in files:
                if file.lower() in ["requirements.txt", "package.json", "pyproject.toml", "pom.xml"]:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, target_dir).replace("\\", "/")
                    try:
                        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        deps = DependencyParser.parse_manifest(file_path, content)
                        for dep in deps:
                            if dep["is_vulnerable"]:
                                findings.append({
                                    "id": f"trivy-{dep['cve_id']}-{rel_path}",
                                    "title": f"Vulnerable Dependency: {dep['package_name']}@{dep['installed_version']}",
                                    "description": dep["recommendation"],
                                    "severity": dep["severity"] or "HIGH",
                                    "confidence": 0.95,
                                    "category": "Vulnerable Dependency",
                                    "cwe": "CWE-1395",
                                    "owasp": "A06:2021-Vulnerable and Outdated Components",
                                    "file_path": rel_path,
                                    "line_number": 1,
                                    "end_line_number": 1,
                                    "code_snippet": f"{dep['package_name']} == {dep['installed_version']}",
                                    "evidence": {
                                        "cve": dep["cve_id"],
                                        "cvss": dep["cvss_score"],
                                        "fixed_version": dep["fixed_version"],
                                        "affected_versions": dep["affected_versions"]
                                    },
                                    "scanner": "trivy"
                                })
                    except Exception:
                        continue
        return findings
