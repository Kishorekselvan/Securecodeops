# SecureCodeOps AI — Multi-Agent System Specification

## 1. Supervisor Agent (`supervisor.py`)
- Coordinates the lifecycle and dependencies of all specialized agents.
- Emits real-time SSE & WebSocket events.
- Performs finding deduplication, prioritization, and score aggregation.

## 2. Repository Analysis Agent (`repository_agent.py`)
- Multi-language AST inspection (Python, JS/TS, Java).
- Identifies API routes/endpoints, database queries, authentication checks, and sensitive literals.
- Generates the NetworkX Knowledge Graph.

## 3. Vulnerability Detection Agent (`vulnerability_agent.py`)
- Executes Semgrep, Bandit, Trivy, GitLeaks with fallback rule engines.
- Normalizes findings into standard CWE & OWASP Top 10 schemas.
- Triggers AI Exploitability Validation.

## 4. AI Validation Engine (`validation.py`)
- Evaluates true exploitability vs false positive indicators.
- Calibrates confidence and suggests actionable remediation.

## 5. Dependency Scanner Agent (`dependency_agent.py`)
- Parses `requirements.txt`, `package.json`, `pom.xml`, `pyproject.toml`.
- Computes `Dependency Risk = sum(CVSS * Exposure Factor)` based on code import reachability.

## 6. STRIDE Threat Modeling Agent (`threat_model_agent.py`)
- Evaluates Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege.
- Calculates `Risk Score = Impact (1-5) * Probability (1-5)` mapped to Low (1-4), Medium (5-9), High (10-16), Critical (17-25).
- Generates step-by-step Attack Paths (Source -> Entry Point -> Vulnerable Sink -> Asset).

## 7. Secure Code Review Agent (`code_review_agent.py`)
- Contextual review across 13 core security domains.

## 8. Compliance Agent (`compliance_agent.py`)
- Control evaluation against OWASP Top 10 2021, GDPR Article 32, ISO 27001, NIST SP 800-53, and PCI-DSS.

## 9. Patch Recommendation & Validation Agent (`patch_agent.py`)
- Synthesizes context-aware diffs.
- Applies patch to isolated sandbox and runs deterministic re-scans to verify Before vs After vulnerability resolution.

## 10. Report Generation Agent (`report_agent.py`)
- Formulates transparent security score.
- Compiles executive summary, downloadable PDF (ReportLab), and JSON/CSV exports.
