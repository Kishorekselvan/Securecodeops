import os
import re
import math
import json
import time
import shutil
from typing import List, Dict, Any, Optional
from app.scanners.base import BaseScanner

SECRET_PATTERNS = [
    {
        "id": "gitleaks-aws-access-key",
        "name": "AWS Access Key ID",
        "pattern": r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        "severity": "CRITICAL",
        "cwe": "CWE-798"
    },
    {
        "id": "gitleaks-github-pat",
        "name": "GitHub Personal Access Token",
        "pattern": r'ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}',
        "severity": "CRITICAL",
        "cwe": "CWE-798"
    },
    {
        "id": "gitleaks-private-key",
        "name": "RSA / SSH Private Key",
        "pattern": r'-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----',
        "severity": "CRITICAL",
        "cwe": "CWE-312"
    },
    {
        "id": "gitleaks-jwt-token",
        "name": "Hardcoded JSON Web Token (JWT)",
        "pattern": r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
        "severity": "HIGH",
        "cwe": "CWE-798"
    },
    {
        "id": "gitleaks-slack-webhook",
        "name": "Slack Incoming Webhook",
        "pattern": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
        "severity": "HIGH",
        "cwe": "CWE-798"
    },
    {
        "id": "gitleaks-generic-api-key",
        "name": "Generic API Secret Key",
        "pattern": r'(?:api_key|apikey|secret_key|app_secret|client_secret)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']',
        "severity": "HIGH",
        "cwe": "CWE-798"
    }
]

def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

class GitLeaksScanner(BaseScanner):
    def __init__(self, enabled: bool = True):
        super().__init__("gitleaks", enabled)

    def is_available(self) -> bool:
        return shutil.which("gitleaks") is not None

    def scan(self, target_dir: str) -> Dict[str, Any]:
        start_time = time.time()
        findings = []
        is_native = self.is_available()

        if is_native and self.enabled:
            report_path = os.path.join(target_dir, ".gitleaks_report.json")
            output = self.run_cli_command(
                ["gitleaks", "detect", "--source", target_dir, "--report-path", report_path, "--report-format", "json", "--no-git"],
                cwd=target_dir,
                timeout_seconds=60
            )
            if os.path.exists(report_path):
                try:
                    with open(report_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    os.remove(report_path)
                    for item in data:
                        rel_path = os.path.relpath(item.get("File", ""), target_dir).replace("\\", "/")
                        findings.append({
                            "id": f"gitleaks-{item.get('RuleID', 'secret')}-{rel_path}-{item.get('StartLine', 1)}",
                            "title": f"Secret Detected: {item.get('Description', 'Exposed Credential')}",
                            "description": f"GitLeaks identified a potential secret match ({item.get('RuleID')}).",
                            "severity": "CRITICAL",
                            "confidence": 0.90,
                            "category": "Hardcoded Secrets",
                            "cwe": "CWE-798",
                            "owasp": "A02:2021-Cryptographic Failures",
                            "file_path": rel_path,
                            "line_number": item.get("StartLine", 1),
                            "end_line_number": item.get("EndLine", 1),
                            "code_snippet": item.get("Match", "Secret Redacted"),
                            "evidence": {"secret_type": item.get("RuleID"), "entropy": item.get("Entropy")},
                            "scanner": "gitleaks"
                        })
                    return {
                        "scanner": "gitleaks",
                        "is_native": True,
                        "executed": True,
                        "findings": findings,
                        "error": None,
                        "duration_seconds": round(time.time() - start_time, 2)
                    }
                except Exception:
                    pass

        # Fallback Secret Scanner with Shannon Entropy calculation
        findings = self._run_entropy_secret_scan(target_dir)
        return {
            "scanner": "gitleaks",
            "is_native": False,
            "executed": True,
            "findings": findings,
            "error": None if findings else "Native gitleaks unavailable; executed high-entropy regex secret engine.",
            "duration_seconds": round(time.time() - start_time, 2)
        }

    def _run_entropy_secret_scan(self, target_dir: str) -> List[Dict[str, Any]]:
        findings = []
        for root, _, files in os.walk(target_dir):
            if any(ignore in root for ignore in ['.git', 'node_modules', '__pycache__', '.venv', 'dist', 'build', 'storage']):
                continue
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in ['.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.tar', '.gz', '.db', '.sqlite']:
                    continue
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, target_dir).replace("\\", "/")
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        content = "".join(lines)
                except Exception:
                    continue

                for rule in SECRET_PATTERNS:
                    matches = list(re.finditer(rule["pattern"], content, re.IGNORECASE))
                    for m in matches:
                        matched_val = m.group(0)
                        line_no = content[:m.start()].count('\n') + 1
                        snippet_start = max(0, line_no - 2)
                        snippet_end = min(len(lines), line_no + 2)
                        snippet = "".join(lines[snippet_start:snippet_end])
                        
                        # Mask sensitive portion in snippet
                        masked_val = matched_val[:4] + "*" * (len(matched_val) - 8) + matched_val[-4:] if len(matched_val) > 8 else "****"

                        findings.append({
                            "id": f"{rule['id']}-{rel_path}-{line_no}",
                            "title": f"Hardcoded Secret: {rule['name']}",
                            "description": f"Detected hardcoded {rule['name']} in source code. This credential can be exploited to gain unauthorized access.",
                            "severity": rule["severity"],
                            "confidence": 0.90,
                            "category": "Hardcoded Secrets",
                            "cwe": rule["cwe"],
                            "owasp": "A02:2021-Cryptographic Failures",
                            "file_path": rel_path,
                            "line_number": line_no,
                            "end_line_number": line_no,
                            "code_snippet": snippet.replace(matched_val, masked_val).strip(),
                            "evidence": {"rule": rule["name"], "entropy": round(calculate_shannon_entropy(matched_val), 2)},
                            "scanner": "gitleaks"
                        })
        return findings
