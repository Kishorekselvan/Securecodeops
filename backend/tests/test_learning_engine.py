import os
import pytest
import tempfile
from app.analysis.learning_engine import ContinuousLearningEngine

def test_continuous_learning_engine():
    with tempfile.TemporaryDirectory() as tmpdir:
        kb_file = os.path.join(tmpdir, "test_kb.json")
        engine = ContinuousLearningEngine(kb_path=kb_file)
        
        # Initially empty
        stats = engine.get_stats()
        assert stats["total_feedbacks"] == 0
        assert stats["false_positives_learned"] == 0

        # Record a False Positive feedback
        record = engine.record_feedback(
            finding_id="f-100",
            category="SQL Injection",
            rule_id="CWE-89",
            file_path="app/routes/test_mock.py",
            feedback_type="FALSE_POSITIVE",
            developer_notes="Test fixture, safe dummy string"
        )
        assert record["feedback_type"] == "FALSE_POSITIVE"

        # Check stats updated
        stats = engine.get_stats()
        assert stats["total_feedbacks"] == 1
        assert stats["false_positives_learned"] == 1

        # Query finding that matches this learned pattern
        match = engine.check_learned_patterns({
            "category": "SQL Injection",
            "cwe": "CWE-89",
            "file_path": "app/routes/test_mock.py"
        })
        assert match is not None
        assert match["validation_status"] == "FALSE_POSITIVE"
        assert match["confidence"] >= 0.90
        assert "Continuous Learning Module" in match["reasoning"]

        # Record a Confirmed True Positive
        engine.record_feedback(
            finding_id="f-200",
            category="Hardcoded Secret",
            rule_id="CWE-798",
            file_path="app/config.py",
            feedback_type="CONFIRMED_TRUE_POSITIVE",
            developer_notes="Real AWS token exposed in repository"
        )

        match_tp = engine.check_learned_patterns({
            "category": "Hardcoded Secret",
            "cwe": "CWE-798",
            "file_path": "app/config.py"
        })
        assert match_tp is not None
        assert match_tp["validation_status"] == "VALIDATED"
        assert match_tp["confidence"] >= 0.95
