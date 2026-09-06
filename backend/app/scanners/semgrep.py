import os
import re
import json
import time
import shutil
import uuid
from typing import List, Dict, Any, Optional
from app.scanners.base import BaseScanner

DETERMINISTIC_RULES = [
    {
        "id": "semgrep-sqli-dynamic-query",
        "title": "SQL Injection via Dynamic String Formatting / Concatenation",
        "category": "SQL Injection",
        "severity": "CRITICAL",
        "cwe": "CWE-89",
        "owasp": "A03:2021-Injection",
        "pattern": r'(?:(?:execute|cursor\.execute|raw|query)\s*\(\s*(?:f["\']|["\'].*?%|["\'].*?\.format|\w+\s*\+\s*["\'])|(?:query|sql|statement)\s*=\s*(?:f["\'](?:SELECT|INSERT|UPDATE|DELETE)|["\'](?:SELECT|INSERT|UPDATE|DELETE).*?["\']\s*[\+%]))',
        "description": "Constructing SQL queries using dynamic string concatenation or unescaped formatting allows SQL injection.",
        "extensions": [".py", ".js", ".ts", ".java"]
    },
    {
        "id": "semgrep-cmd-injection-shell-true",
        "title": "Command Injection via Shell Subprocess",
        "category": "Command Injection",
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "owasp": "A03:2021-Injection",
        "pattern": r'(?:os\.system\s*\(|subprocess\.(?:Popen|run|call)\s*\(.*?(?:shell\s*=\s*True|f["\']|\+))',
        "description": "Executing system shell commands with concatenated user input allows arbitrary command execution.",
        "extensions": [".py"]
    },
    {
        "id": "semgrep-insecure-deserialization-pickle",
        "title": "Insecure Deserialization via Pickle/Yaml",
        "category": "Insecure Deserialization",
        "severity": "HIGH",
        "cwe": "CWE-502",
        "owasp": "A08:2021-Software and Data Integrity Failures",
        "pattern": r'(?:pickle\.loads|yaml\.load\s*\([^,)]*\))',
        "description": "Deserializing untrusted data with pickle or unsafe yaml.load allows arbitrary code execution.",
        "extensions": [".py"]
    },
    {
        "id": "semgrep-hardcoded-jwt-secret",
        "title": "Hardcoded JWT Secret / Weak Signing Key",
        "category": "Hardcoded Secrets",
        "severity": "HIGH",
        "cwe": "CWE-798",
        "owasp": "A02:2021-Cryptographic Failures",
        "pattern": r'(?:jwt\.(?:encode|decode|sign|verify)\s*\(.*?(?:["\']secret["\']|["\']123456["\']|["\']mysecretkey["\']|["\']supersecret["\'])|JWT_SECRET\s*=\s*["\'][^"\']+["\'])',
        "description": "Hardcoding symmetric JWT secret keys allows token forgery and complete authentication bypass.",
        "extensions": [".py", ".js", ".ts"]
    },
    {
        "id": "semgrep-xss-dangerously-set-html",
        "title": "Cross-Site Scripting (XSS) via dangerouslySetInnerHTML or innerHTML",
        "category": "Cross-Site Scripting",
        "severity": "HIGH",
        "cwe": "CWE-79",
        "owasp": "A03:2021-Injection",
        "pattern": r'(?:dangerouslySetInnerHTML\s*=|innerHTML\s*=|`.*?<div.*?<\$\{.*?\}|res\.send\s*\(\s*`.*?<[a-z]+.*?\$\{)',
        "description": "Rendering unescaped HTML directly to the DOM or HTTP response enables client-side Cross-Site Scripting.",
        "extensions": [".js", ".jsx", ".ts", ".tsx", ".html"]
    },
    {
        "id": "semgrep-ssrf-unvalidated-url",
        "title": "Potential Server-Side Request Forgery (SSRF)",
        "category": "Server-Side Request Forgery",
        "severity": "HIGH",
        "cwe": "CWE-918",
        "owasp": "A10:2021-Server-Side Request Forgery",
        "pattern": r'(?:requests\.(?:get|post)|axios\.(?:get|post)|fetch|urllib\.request\.urlopen)\s*\(\s*(?:target_url|request\.(?:args|form|json)|req\.(?:query|body)|url)',
        "description": "Passing user-controlled URLs directly to HTTP client requests without whitelist validation causes SSRF.",
        "extensions": [".py", ".js", ".ts"]
    },
    {
        "id": "semgrep-cors-wildcard-origin",
        "title": "Overly Permissive CORS Configuration with Wildcard",
        "category": "Security Misconfiguration",
        "severity": "MEDIUM",
        "cwe": "CWE-942",
        "owasp": "A05:2021-Security Misconfiguration",
        "pattern": r'(?:Access-Control-Allow-Origin["\']?\s*,\s*["\']\*["\']|Access-Control-Allow-Origin["\']?\s*:\s*["\']\*["\']|allow_origins\s*=\s*\[\s*["\']\*["\']\s*\])',
        "description": "Configuring Access-Control-Allow-Origin to wildcard (*) allows any untrusted domain to make cross-origin requests.",
        "extensions": [".py", ".js", ".ts", ".json"]
    },
    {
        "id": "semgrep-path-traversal-open",
        "title": "Path Traversal via Unvalidated File Path",
        "category": "Path Traversal",
        "severity": "HIGH",
        "cwe": "CWE-22",
        "owasp": "A01:2021-Broken Access Control",
        "pattern": r'(?:open|fs\.readFileSync|fs\.readFile)\s*\(\s*(?:os\.path\.join|path\.join)?\s*\(?.*?(?:request\.|req\.|logFile)',
        "description": "Accessing files using untrusted user input without path normalization allows directory traversal.",
        "extensions": [".py", ".js", ".ts"]
    }
]

class SemgrepScanner(BaseScanner):
    def __init__(self, enabled: bool = True):
        super().__init__("semgrep", enabled)

    def is_available(self) -> bool:
        return shutil.which("semgrep") is not None

    def scan(self, target_dir: str) -> Dict[str, Any]:
        start_time = time.time()
        findings = []
        is_native = self.is_available()

        if is_native and self.enabled:
            output = self.run_cli_command(
                ["semgrep", "scan", "--json", "--quiet", target_dir],
                cwd=target_dir,
                timeout_seconds=60
            )
            if output:
                try:
                    data = json.loads(output)
                    for res in data.get("results", []):
                        extra = res.get("extra", {})
                        meta = extra.get("metadata", {})
                        rel_path = os.path.relpath(res.get("path", ""), target_dir)
                        findings.append({
                            "id": str(uuid.uuid4()),
                            "title": meta.get("message") or res.get("check_id"),
                            "description": extra.get("message") or "Semgrep detected a security pattern match.",
                            "severity": extra.get("severity", "MEDIUM").upper(),
                            "confidence": 0.85,
                            "category": meta.get("category", "General Vulnerability"),
                            "cwe": meta.get("cwe", [None])[0] if isinstance(meta.get("cwe"), list) else meta.get("cwe"),
                            "owasp": meta.get("owasp", [None])[0] if isinstance(meta.get("owasp"), list) else meta.get("owasp"),
                            "file_path": rel_path.replace("\\", "/"),
                            "line_number": res.get("start", {}).get("line"),
                            "end_line_number": res.get("end", {}).get("line"),
                            "code_snippet": extra.get("lines", ""),
                            "evidence": {"raw_match": res.get("check_id")},
                            "scanner": "semgrep"
                        })
                    return {
                        "scanner": "semgrep",
                        "is_native": True,
                        "executed": True,
                        "findings": findings,
                        "error": None,
                        "duration_seconds": round(time.time() - start_time, 2)
                    }
                except Exception:
                    pass

        # Fallback Deterministic Engine
        findings = self._run_deterministic_rules(target_dir)
        return {
            "scanner": "semgrep",
            "is_native": False,
            "executed": True,
            "findings": findings,
            "error": None if findings else "Native semgrep unavailable; executed deterministic rule engine.",
            "duration_seconds": round(time.time() - start_time, 2)
        }

    def _run_deterministic_rules(self, target_dir: str) -> List[Dict[str, Any]]:
        findings = []
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv', 'dist', 'build']]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, target_dir).replace("\\", "/")
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        content = "".join(lines)
                except Exception:
                    continue

                for rule in DETERMINISTIC_RULES:
                    if ext not in rule["extensions"]:
                        continue
                    
                    matches = list(re.finditer(rule["pattern"], content, re.IGNORECASE))
                    for m in matches:
                        line_no = content[:m.start()].count('\n') + 1
                        snippet_start = max(0, line_no - 2)
                        snippet_end = min(len(lines), line_no + 2)
                        snippet = "".join(lines[snippet_start:snippet_end])

                        findings.append({
                            "id": str(uuid.uuid4()),
                            "title": rule["title"],
                            "description": rule["description"],
                            "severity": rule["severity"],
                            "confidence": 0.85,
                            "category": rule["category"],
                            "cwe": rule["cwe"],
                            "owasp": rule["owasp"],
                            "file_path": rel_path,
                            "line_number": line_no,
                            "end_line_number": line_no,
                            "code_snippet": snippet.strip(),
                            "evidence": {"matched_pattern": rule["pattern"], "matched_text": m.group(0)},
                            "scanner": "semgrep"
                        })
        return findings
