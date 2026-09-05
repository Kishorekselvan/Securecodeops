import os
import time
from typing import Dict, Any, List
from app.ai.provider import get_llm_provider
from app.ai.prompts import CODE_REVIEW_SYSTEM_PROMPT

class SecureCodeReviewAgent:
    def __init__(self):
        self.name = "Secure Code Review Agent"
        self.agent_type = "code_review"
        self.provider = get_llm_provider()

    async def execute(self, repo_dir: str, file_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        start_time = time.time()
        review_issues: List[Dict[str, Any]] = []

        # Domain reviews using deterministic AST & context rules
        for rec in file_records:
            rel_path = rec.get("relative_path", "")
            ast_sum = rec.get("ast_summary", {})
            full_path = os.path.join(repo_dir, rel_path)
            
            try:
                with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    content = "".join(lines)
            except Exception:
                continue

            # 1. Error Handling & Stack Trace Leakage
            if "traceback.print_exc" in content or "res.status(500).send(err.stack)" in content or "e.printStackTrace()" in content:
                line_no = 1
                for idx, l in enumerate(lines):
                    if any(t in l for t in ["print_exc", "err.stack", "printStackTrace"]):
                        line_no = idx + 1
                        break
                review_issues.append({
                    "title": "Raw Exception Stack Trace Leakage in HTTP Response",
                    "domain": "Error handling",
                    "severity": "MEDIUM",
                    "file": rel_path,
                    "line": line_no,
                    "vulnerable_code": lines[line_no - 1].strip() if 0 <= line_no - 1 < len(lines) else "",
                    "why_insecure": "Printing raw exception stack traces exposes internal framework paths, database queries, and environment details to attackers.",
                    "recommended_fix": "Log internal exceptions server-side in structured logs and return generic, sanitized error messages (e.g. {'error': 'Internal server error'}) to clients."
                })

            # 2. Insecure Randomness / Cryptography
            if "import random" in content and any(kw in content for kw in ["token", "key", "otp", "secret", "session"]):
                line_no = 1
                for idx, l in enumerate(lines):
                    if "import random" in l:
                        line_no = idx + 1
                        break
                review_issues.append({
                    "title": "Use of Cryptographically Insecure Pseudo-Random Number Generator",
                    "domain": "Cryptography",
                    "severity": "HIGH",
                    "file": rel_path,
                    "line": line_no,
                    "vulnerable_code": lines[line_no - 1].strip() if 0 <= line_no - 1 < len(lines) else "import random",
                    "why_insecure": "Standard `random` uses the Mersenne Twister PRNG which is fully predictable after observing 624 outputs.",
                    "recommended_fix": "Use cryptographically secure PRNG modules such as `secrets` (Python) or `crypto.randomBytes` (Node.js)."
                })

            # 3. Missing Input Validation on Endpoints
            if ast_sum.get("endpoints") and not ast_sum.get("auth_checks"):
                for ep in ast_sum.get("endpoints", [])[:1]:
                    review_issues.append({
                        "title": f"Unauthenticated Endpoint Lacking Schema Validation: {ep.get('name')}",
                        "domain": "Input validation",
                        "severity": "MEDIUM",
                        "file": rel_path,
                        "line": ep.get("line", 1),
                        "vulnerable_code": ep.get("name"),
                        "why_insecure": "Public API route accepts untyped incoming parameters without boundary or format validation.",
                        "recommended_fix": "Enforce explicit Pydantic request models or input schema sanitization before processing payload."
                    })

            # 4. Security Logging / Auditing
            if ast_sum.get("sensitive_data") and "logger" not in content and "logging" not in content:
                review_issues.append({
                    "title": "Missing Security Audit Logging on Sensitive Operations",
                    "domain": "Logging",
                    "severity": "LOW",
                    "file": rel_path,
                    "line": 1,
                    "vulnerable_code": "# File manipulating sensitive entities without security logging",
                    "why_insecure": "Security events cannot be reconstructed during forensic incident response without adequate audit trails.",
                    "recommended_fix": "Implement structured security logging recording user identity, timestamp, and action outcome."
                })

        duration = round(time.time() - start_time, 2)
        return {
            "status": "COMPLETED",
            "duration_seconds": duration,
            "issues_count": len(review_issues),
            "issues": review_issues
        }
