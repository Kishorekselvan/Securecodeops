# SecureCodeOps AI — Multi-Agent DevSecOps Platform

**SecureCodeOps AI** is an AI-powered autonomous multi-agent DevSecOps platform that analyzes software repositories for security vulnerabilities, constructs repository knowledge graphs, executes STRIDE threat modeling, audits package dependencies against CVE advisories, performs 13-domain secure code reviews, checks multi-framework compliance (OWASP Top 10, GDPR Art 32, ISO 27001, NIST SP 800-53, PCI-DSS), recommends verified context-aware patches via sandbox re-scanning, and generates downloadable PDF and JSON security reports.

---

## Key Features

1. **Deterministic-First Architecture**:
   - Native integration with **Semgrep**, **Bandit**, **Trivy**, and **GitLeaks** with robust built-in fallback deterministic rule engines when external binaries are not installed.
2. **Supervisor-Coordinated Multi-Agent Pipeline**:
   - **Repository Analysis Agent**: Multi-language AST parsing (Python, JS/TS, Java) discovering routes, DB sinks, auth checks, and building the Knowledge Graph.
   - **Vulnerability Detection Agent**: Hybrid scanning with CWE/OWASP normalization.
   - **AI Validation Engine**: Contextual exploitability validation (Validated, False Positive, Uncertain) with LLM provider abstraction (OpenAI, Gemini, Anthropic, Offline Rule Engine).
   - **STRIDE Threat Modeling Agent**: Impact (1–5) &times; Probability (1–5) risk matrix and step-by-step Attack Path graphs.
   - **Dependency Scanner Agent**: Package manifest analysis (NPM, PyPI, Maven), CVE mapping, CVSS scoring, and reachability exposure factor calculation.
   - **Secure Code Review Agent**: 13 OWASP/CWE security domains.
   - **Compliance Agent**: Control scoring and evidence mapping across OWASP Top 10, GDPR, ISO 27001, NIST, and PCI-DSS.
   - **Patch Recommendation & Validation Agent**: Generates context-aware diffs and executes isolated sandbox re-scans to measure Before vs After vulnerability resolution.
   - **Report Generation Agent**: Transparent mathematical security scoring, executive summaries, downloadable PDF reports (ReportLab), and JSON/CSV exports.
3. **Real-Time Observability**:
   - Live Server-Sent Events (SSE) and WebSocket streaming of agent progress and execution logs.
4. **Built-in Educational Demo Mode**:
   - Instant 1-click testbed containing real-world vulnerabilities (SQL Injection, Command Injection, Hardcoded JWT Secret, Insecure Deserialization, XSS, Path Traversal, Vulnerable Dependencies).

---

## Quick Start (Local Run)

### 1. Backend Setup
```bash
# Navigate to backend and install requirements
pip install -r backend/requirements.txt

# Run backend API server
uvicorn backend.app.main:app --reload --port 8000
```
Backend API will be available at: `http://localhost:8000`  
Swagger API Docs: `http://localhost:8000/docs`

### 2. Frontend Setup
```bash
# Navigate to frontend and install dependencies
cd frontend
npm install

# Run Vite development server
npm run dev
```
Frontend Web UI will be available at: `http://localhost:5173`

---

## Running with Docker Compose

```bash
docker compose up --build
```
- Frontend: `http://localhost:5173`
- Backend API: `http://localhost:8000`

---

## Running Automated Tests

```bash
python -m pytest backend/tests -v
```

---

## Environment Variables Configuration

Copy `.env.example` to `.env`:
```env
DATABASE_URL=sqlite+aiosqlite:///./securecodeops.db
LLM_PROVIDER=offline # "offline", "openai", "gemini", "anthropic"
MODEL_NAME=offline-rule-engine-v1
OPENAI_API_KEY=
GOOGLE_API_KEY=
ANTHROPIC_API_KEY=
```

---

## Documentation Links

- [ARCHITECTURE.md](ARCHITECTURE.md): System architecture and data flow diagrams.
- [AGENTS.md](AGENTS.md): Detailed multi-agent specifications and orchestration contracts.
- [SECURITY.md](SECURITY.md): Security practices, sandbox isolation, and zip bomb / path traversal protections.
- [API.md](API.md): REST API endpoints and data schemas.
