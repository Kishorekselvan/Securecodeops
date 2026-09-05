import os
import pytest
from app.scanners.semgrep import SemgrepScanner
from app.scanners.bandit import BanditScanner
from app.scanners.gitleaks import GitLeaksScanner
from app.scanners.trivy import TrivyScanner
from app.scanners.normalizer import FindingNormalizer

def test_semgrep_scanner_demo_repo():
    scanner = SemgrepScanner()
    demo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../demo_repo"))
    res = scanner.scan(demo_dir)
    assert res["executed"] is True
    assert len(res["findings"]) > 0
    
    # Check for SQL injection finding
    categories = [f["category"].lower() for f in res["findings"]]
    assert any("sql injection" in c for c in categories)

def test_gitleaks_scanner_demo_repo():
    scanner = GitLeaksScanner()
    demo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../demo_repo"))
    res = scanner.scan(demo_dir)
    assert res["executed"] is True
    assert len(res["findings"]) > 0
    
    # Check for secret findings
    titles = [f["title"].lower() for f in res["findings"]]
    assert any("secret" in t for t in titles)

def test_trivy_scanner_demo_repo():
    scanner = TrivyScanner()
    demo_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../demo_repo"))
    res = scanner.scan(demo_dir)
    assert res["executed"] is True
    assert len(res["findings"]) > 0

def test_finding_normalizer():
    raw = [
        {"title": "Issue 1", "severity": "HIGH", "category": "SQL Injection", "file_path": "a.py", "line_number": 10},
        {"title": "Issue 1 duplicate", "severity": "CRITICAL", "category": "SQL Injection", "file_path": "a.py", "line_number": 10},
        {"title": "Issue 2", "severity": "LOW", "category": "XSS", "file_path": "b.js", "line_number": 5}
    ]
    normalized = FindingNormalizer.normalize_findings(raw)
    assert len(normalized) == 2
    assert normalized[0]["severity"] == "CRITICAL"  # Highest severity deduplicated to top
