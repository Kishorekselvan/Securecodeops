import os
import ast
import json
import time
import shutil
from typing import List, Dict, Any, Optional
from app.scanners.base import BaseScanner

class BanditScanner(BaseScanner):
    def __init__(self, enabled: bool = True):
        super().__init__("bandit", enabled)

    def is_available(self) -> bool:
        return shutil.which("bandit") is not None

    def scan(self, target_dir: str) -> Dict[str, Any]:
        start_time = time.time()
        findings = []
        is_native = self.is_available()

        if is_native and self.enabled:
            output = self.run_cli_command(
                ["bandit", "-r", target_dir, "-f", "json", "-q"],
                cwd=target_dir,
                timeout_seconds=60
            )
            if output:
                try:
                    data = json.loads(output)
                    for res in data.get("results", []):
                        rel_path = os.path.relpath(res.get("filename", ""), target_dir).replace("\\", "/")
                        findings.append({
                            "id": f"bandit-{res.get('test_id', 'issue')}-{rel_path}-{res.get('line_number')}",
                            "title": res.get("test_name", "Bandit Security Issue"),
                            "description": res.get("issue_text", "Bandit detected a Python security flaw."),
                            "severity": res.get("issue_severity", "MEDIUM").upper(),
                            "confidence": 0.85 if res.get("issue_confidence") == "HIGH" else 0.70,
                            "category": "Python Security Flaw",
                            "cwe": res.get("issue_cwe", {}).get("link", "").split("=")[-1] or "CWE-20",
                            "owasp": "A03:2021-Injection",
                            "file_path": rel_path,
                            "line_number": res.get("line_number"),
                            "end_line_number": res.get("line_range", [res.get("line_number")])[-1],
                            "code_snippet": res.get("code", "").strip(),
                            "evidence": {"test_id": res.get("test_id"), "test_name": res.get("test_name")},
                            "scanner": "bandit"
                        })
                    return {
                        "scanner": "bandit",
                        "is_native": True,
                        "executed": True,
                        "findings": findings,
                        "error": None,
                        "duration_seconds": round(time.time() - start_time, 2)
                    }
                except Exception:
                    pass

        # Fallback AST Bandit Python Analyzer
        findings = self._run_ast_bandit(target_dir)
        return {
            "scanner": "bandit",
            "is_native": False,
            "executed": True,
            "findings": findings,
            "error": None if findings else "Native bandit unavailable; executed AST security analyzer.",
            "duration_seconds": round(time.time() - start_time, 2)
        }

    def _run_ast_bandit(self, target_dir: str) -> List[Dict[str, Any]]:
        findings = []
        for root, _, files in os.walk(target_dir):
            if any(ignore in root for ignore in ['.git', 'node_modules', '__pycache__', '.venv']):
                continue
            for file in files:
                if not file.endswith('.py'):
                    continue
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, target_dir).replace("\\", "/")
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        lines = content.splitlines()
                        tree = ast.parse(content, filename=file_path)
                except Exception:
                    continue

                for node in ast.walk(tree):
                    # B307: eval
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "eval":
                        line = node.lineno
                        snippet = lines[line - 1] if 0 <= line - 1 < len(lines) else "eval(...)"
                        findings.append({
                            "id": f"bandit-B307-{rel_path}-{line}",
                            "title": "B307: Use of possibly insecure function - eval",
                            "description": "Use of eval detected. Arbitrary user input passed to eval can result in remote code execution.",
                            "severity": "HIGH",
                            "confidence": 0.90,
                            "category": "Code Injection",
                            "cwe": "CWE-95",
                            "owasp": "A03:2021-Injection",
                            "file_path": rel_path,
                            "line_number": line,
                            "end_line_number": line,
                            "code_snippet": snippet.strip(),
                            "evidence": {"function": "eval"},
                            "scanner": "bandit"
                        })

                    # B602: subprocess with shell=True
                    elif isinstance(node, ast.Call):
                        func_name = ""
                        if isinstance(node.func, ast.Attribute):
                            func_name = node.func.attr
                        elif isinstance(node.func, ast.Name):
                            func_name = node.func.id
                            
                        if func_name in ["Popen", "call", "check_call", "check_output", "run"]:
                            for kw in node.keywords:
                                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                                    line = node.lineno
                                    snippet = lines[line - 1] if 0 <= line - 1 < len(lines) else "subprocess(..., shell=True)"
                                    findings.append({
                                        "id": f"bandit-B602-{rel_path}-{line}",
                                        "title": "B602: Subprocess call with shell=True identified",
                                        "description": "subprocess call with shell=True seems to be used. This creates severe command injection vulnerabilities.",
                                        "severity": "CRITICAL",
                                        "confidence": 0.95,
                                        "category": "Command Injection",
                                        "cwe": "CWE-78",
                                        "owasp": "A03:2021-Injection",
                                        "file_path": rel_path,
                                        "line_number": line,
                                        "end_line_number": line,
                                        "code_snippet": snippet.strip(),
                                        "evidence": {"call": func_name, "shell": True},
                                        "scanner": "bandit"
                                    })

                    # B105 / B106: Hardcoded password / secret strings
                    elif isinstance(node, ast.Assign):
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                var_name = target.id.lower()
                                if any(sec in var_name for sec in ["password", "jwt_secret", "api_key", "secret_key"]):
                                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                                        val = node.value.value
                                        if len(val) > 4 and val not in ["", "none", "env", "default"]:
                                            line = node.lineno
                                            snippet = lines[line - 1] if 0 <= line - 1 < len(lines) else f"{target.id} = '...'"
                                            findings.append({
                                                "id": f"bandit-B105-{rel_path}-{line}",
                                                "title": f"B105: Possible hardcoded password / token: '{target.id}'",
                                                "description": "Possible hardcoded secret or token assignment detected in code.",
                                                "severity": "HIGH",
                                                "confidence": 0.85,
                                                "category": "Hardcoded Secrets",
                                                "cwe": "CWE-798",
                                                "owasp": "A02:2021-Cryptographic Failures",
                                                "file_path": rel_path,
                                                "line_number": line,
                                                "end_line_number": line,
                                                "code_snippet": snippet.strip(),
                                                "evidence": {"variable": target.id},
                                                "scanner": "bandit"
                                            })
        return findings
