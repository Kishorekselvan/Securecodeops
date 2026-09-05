import uuid
from typing import List, Dict, Any

class FindingNormalizer:
    
    @staticmethod
    def normalize_findings(raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        dedup_map: Dict[str, Dict[str, Any]] = {}
        
        for f in raw_findings:
            file_path = f.get("file_path", "").replace("\\", "/")
            line_no = f.get("line_number") or 1
            cat = f.get("category", "General Vulnerability")
            
            # Key for deduplication
            dedup_key = f"{file_path}:{line_no}:{cat.lower()}"
            
            # Severity normalization
            sev = str(f.get("severity", "MEDIUM")).upper()
            if sev not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                if sev in ["ERROR", "FATAL"]:
                    sev = "HIGH"
                elif sev in ["WARN", "WARNING"]:
                    sev = "MEDIUM"
                else:
                    sev = "LOW"

            finding_id = f.get("id") or str(uuid.uuid4())

            normalized = {
                "id": finding_id,
                "title": f.get("title", "Security Finding"),
                "description": f.get("description", "Potential security weakness identified."),
                "severity": sev,
                "confidence": float(f.get("confidence", 0.8)),
                "category": cat,
                "cwe": f.get("cwe") or "CWE-699",
                "owasp": f.get("owasp") or "A03:2021-Injection",
                "file_path": file_path,
                "line_number": line_no,
                "end_line_number": f.get("end_line_number") or line_no,
                "code_snippet": f.get("code_snippet") or "",
                "evidence": f.get("evidence") or {},
                "scanner": f.get("scanner", "unknown"),
                "status": "OPEN",
                "ai_validation_status": "PENDING"
            }

            if dedup_key in dedup_map:
                # Merge if higher severity
                existing = dedup_map[dedup_key]
                sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                if sev_order.get(sev, 0) > sev_order.get(existing["severity"], 0):
                    # Preserve existing ID so foreign keys stay stable
                    normalized["id"] = existing["id"]
                    dedup_map[dedup_key] = normalized
            else:
                dedup_map[dedup_key] = normalized

        # Return sorted by severity
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return sorted(list(dedup_map.values()), key=lambda x: order.get(x["severity"], 5))
