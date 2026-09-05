# SecureCodeOps AI — REST API Documentation

Base URL: `http://localhost:8000/api`

## Endpoints

### Repositories
- `GET /repositories`: List all repositories
- `GET /repositories/{id}`: Get repository details
- `POST /repositories/upload`: Upload repository ZIP archive
- `POST /repositories/demo`: Initialize or fetch built-in Demo Repository

### Scans
- `POST /scans`: Start a new multi-agent scan (`{ "repository_id": "<id>" }`)
- `GET /scans`: List all scan summaries
- `GET /scans/{scan_id}`: Full scan details with agents, findings, threats, dependencies, and report
- `GET /scans/{scan_id}/status`: Fast status check
- `GET /scans/{scan_id}/events`: Server-Sent Events (SSE) live progress and log stream
- `WebSocket /ws/scans/{scan_id}`: WebSocket progress stream

### Findings
- `GET /findings`: Query findings with query parameters (`severity`, `category`, `scanner`, `status`, `ai_status`)
- `GET /findings/{id}`: Detailed finding record
- `PATCH /findings/{id}/status`: Update finding status (`OPEN`, `RESOLVED`, `FALSE_POSITIVE`, `SUPPRESSED`)

### Threats
- `GET /threats`: List STRIDE threats with risk scores (`category`, `risk_level`)
- `GET /threats/{id}`: Threat details with attack path step nodes

### Dependencies
- `GET /dependencies`: List SBOM dependencies (`vulnerable_only`, `ecosystem`)
- `GET /dependencies/{id}`: Dependency record with CVSS and CVE details

### Compliance
- `GET /compliance`: List compliance checks (`framework`, `status`)
- `GET /compliance/framework-summary`: Aggregated framework scores

### Patches
- `GET /patches`: List proposed patches (`status`, `validated_only`)
- `GET /patches/{id}`: Patch details with before/after code and re-scan validation counts
- `GET /patches/{id}/download`: Download raw `.patch` diff file
- `POST /patches/{id}/apply`: Apply patch to working repository copy
- `POST /patches/{id}/reject`: Reject patch

### Reports
- `GET /reports/{scan_id}`: Executive report JSON
- `GET /reports/{scan_id}/pdf`: Download styled ReportLab PDF
- `GET /reports/{scan_id}/export-json`: Export raw scan JSON
- `GET /reports/{scan_id}/export-csv`: Export findings CSV

### Knowledge Graph & Logs
- `GET /knowledge-graph/{scan_id}`: Graph nodes, edges, and category statistics
- `GET /agent-logs?scan_id={id}`: Agent execution log entries
- `GET /settings/status`: System health and scanner availability
