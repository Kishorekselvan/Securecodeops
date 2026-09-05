import os
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime
from app.core.config import settings

logger = logging.getLogger("securecodeops.learning")

class ContinuousLearningEngine:
    """
    Continuous Learning Module (Paper Section II-B & III-A)
    Maintains a local knowledge base of verified findings, false positives,
    and developer feedback to calibrate confidence scores and suppress
    recurring false positives across scans.
    """
    def __init__(self, kb_path: Optional[str] = None):
        self.kb_dir = settings.KNOWLEDGE_BASE_DIR
        self.kb_file = kb_path or os.path.join(self.kb_dir, "feedback_knowledge_base.json")
        self._ensure_kb_file()

    def _ensure_kb_file(self):
        os.makedirs(os.path.dirname(self.kb_file), exist_ok=True)
        if not os.path.exists(self.kb_file):
            initial_data = {
                "version": "1.0",
                "last_updated": datetime.utcnow().isoformat(),
                "suppressed_patterns": [],
                "confirmed_patterns": [],
                "feedback_records": []
            }
            try:
                with open(self.kb_file, "w", encoding="utf-8") as f:
                    json.dump(initial_data, f, indent=2)
            except Exception as e:
                logger.error(f"Failed to initialize knowledge base file: {e}")

    def _load_kb(self) -> Dict[str, Any]:
        try:
            with open(self.kb_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {"suppressed_patterns": [], "confirmed_patterns": [], "feedback_records": []}

    def _save_kb(self, data: Dict[str, Any]):
        data["last_updated"] = datetime.utcnow().isoformat()
        try:
            with open(self.kb_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to persist knowledge base: {e}")

    def record_feedback(
        self,
        finding_id: str,
        category: str,
        rule_id: Optional[str],
        file_path: str,
        feedback_type: str,
        developer_notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Records developer feedback and updates the local knowledge base.
        feedback_type: 'FALSE_POSITIVE', 'CONFIRMED_TRUE_POSITIVE', 'SUPPRESSED'
        """
        kb = self._load_kb()
        
        record = {
            "finding_id": finding_id,
            "category": category,
            "rule_id": rule_id or "generic",
            "file_path": file_path,
            "feedback_type": feedback_type,
            "developer_notes": developer_notes or "",
            "timestamp": datetime.utcnow().isoformat()
        }
        kb.setdefault("feedback_records", []).append(record)

        # Pattern key for matching
        pattern_entry = {
            "category": category.lower(),
            "rule_id": (rule_id or "").lower(),
            "file_name": os.path.basename(file_path).lower(),
            "feedback_type": feedback_type,
            "count": 1
        }

        if feedback_type in ["FALSE_POSITIVE", "SUPPRESSED"]:
            existing = next((p for p in kb.get("suppressed_patterns", []) 
                             if p.get("category") == pattern_entry["category"] 
                             and p.get("rule_id") == pattern_entry["rule_id"]), None)
            if existing:
                existing["count"] = existing.get("count", 1) + 1
            else:
                kb.setdefault("suppressed_patterns", []).append(pattern_entry)
        elif feedback_type == "CONFIRMED_TRUE_POSITIVE":
            existing = next((p for p in kb.get("confirmed_patterns", []) 
                             if p.get("category") == pattern_entry["category"] 
                             and p.get("rule_id") == pattern_entry["rule_id"]), None)
            if existing:
                existing["count"] = existing.get("count", 1) + 1
            else:
                kb.setdefault("confirmed_patterns", []).append(pattern_entry)

        self._save_kb(kb)
        return record

    def check_learned_patterns(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Evaluates finding against the local knowledge base.
        Returns calibration recommendation if pattern matches prior developer feedback.
        """
        kb = self._load_kb()
        cat = (finding.get("category") or "").lower()
        rule_id = (finding.get("cwe") or finding.get("title") or "").lower()
        file_path = (finding.get("file_path") or "").lower()
        file_name = os.path.basename(file_path)

        # 1. Check if known false positive / suppressed pattern
        for sp in kb.get("suppressed_patterns", []):
            sp_cat = sp.get("category", "")
            sp_rule = sp.get("rule_id", "")
            if (sp_cat and sp_cat in cat) or (sp_rule and sp_rule in rule_id):
                return {
                    "is_learned": True,
                    "action": "SUPPRESS_FALSE_POSITIVE",
                    "validation_status": "FALSE_POSITIVE",
                    "confidence": 0.95,
                    "reasoning": f"Calibrated by Continuous Learning Module: Rule '{rule_id}' in category '{cat}' was previously marked as False Positive by developers.",
                    "developer_notes": "Suppressed based on prior team feedback in local knowledge base."
                }

        # 2. Check if known verified true positive pattern
        for cp in kb.get("confirmed_patterns", []):
            cp_cat = cp.get("category", "")
            cp_rule = cp.get("rule_id", "")
            if (cp_cat and cp_cat in cat) or (cp_rule and cp_rule in rule_id):
                return {
                    "is_learned": True,
                    "action": "BOOST_TRUE_POSITIVE",
                    "validation_status": "VALIDATED",
                    "confidence": 0.98,
                    "reasoning": f"Reinforced by Continuous Learning Module: Pattern '{rule_id}' in '{cat}' was previously verified by developers as high-risk exploit.",
                    "developer_notes": "High confidence true positive based on confirmed history."
                }

        return None

    def get_stats(self) -> Dict[str, Any]:
        kb = self._load_kb()
        records = kb.get("feedback_records", [])
        fp_count = sum(1 for r in records if r.get("feedback_type") in ["FALSE_POSITIVE", "SUPPRESSED"])
        tp_count = sum(1 for r in records if r.get("feedback_type") == "CONFIRMED_TRUE_POSITIVE")
        return {
            "total_feedbacks": len(records),
            "false_positives_learned": fp_count,
            "confirmed_exploits_learned": tp_count,
            "suppressed_pattern_count": len(kb.get("suppressed_patterns", [])),
            "confirmed_pattern_count": len(kb.get("confirmed_patterns", []))
        }

# Global singleton
learning_engine = ContinuousLearningEngine()
