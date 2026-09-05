import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

# --- User Schemas ---
class UserBase(BaseModel):
    email: str
    username: str

class UserCreate(UserBase):
    password: Optional[str] = None

class UserOut(UserBase):
    id: str
    is_active: bool
    created_at: datetime.datetime

    class Config:
        from_attributes = True

# --- Repository Schemas ---
class RepositoryBase(BaseModel):
    name: str
    description: Optional[str] = None

class RepositoryCreate(RepositoryBase):
    pass

class RepositoryOut(RepositoryBase):
    id: str
    owner_id: Optional[str] = None
    storage_path: str
    languages: List[str] = []
    frameworks: List[str] = []
    file_count: int = 0
    lines_of_code: int = 0
    is_demo: bool = False
    created_at: datetime.datetime
    updated_at: datetime.datetime

    class Config:
        from_attributes = True

# --- Scan Agent Schemas ---
class ScanAgentOut(BaseModel):
    id: str
    scan_id: str
    name: str
    agent_type: str
    status: str
    started_at: Optional[datetime.datetime] = None
    completed_at: Optional[datetime.datetime] = None
    duration_seconds: float = 0.0
    findings_count: int = 0
    error_message: Optional[str] = None
    input_summary: Dict[str, Any] = {}
    output_summary: Dict[str, Any] = {}

    class Config:
        from_attributes = True

# --- Finding Schemas ---
class FindingBase(BaseModel):
    title: str
    description: str
    severity: str
    confidence: float = 0.8
    category: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    file_path: str
    line_number: Optional[int] = None
    end_line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    evidence: Dict[str, Any] = {}
    scanner: str

class FindingCreate(FindingBase):
    scan_id: str

class FindingOut(FindingBase):
    id: str
    scan_id: str
    status: str
    ai_validation_status: str
    ai_reasoning: Optional[str] = None
    ai_confidence: Optional[float] = None
    ai_severity_adjustment: Optional[str] = None
    ai_attack_scenario: Optional[str] = None
    ai_remediation: Optional[str] = None
    created_at: datetime.datetime

    class Config:
        from_attributes = True

# --- Threat Schemas ---
class ThreatBase(BaseModel):
    category: str
    title: str
    description: str
    affected_component: str
    attack_vector: str
    impacted_assets: List[str] = []
    impact: int
    probability: int
    risk_score: int
    risk_level: str
    existing_controls: List[str] = []
    recommended_controls: List[str] = []
    attack_path: List[Dict[str, Any]] = []

class ThreatOut(ThreatBase):
    id: str
    scan_id: str

    class Config:
        from_attributes = True

# --- Dependency Schemas ---
class DependencyBase(BaseModel):
    package_name: str
    installed_version: str
    ecosystem: str
    manifest_file: str
    is_direct: bool = True
    is_vulnerable: bool = False
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    affected_versions: Optional[str] = None
    fixed_version: Optional[str] = None
    exposure_factor: float = 1.0
    risk_contribution: float = 0.0
    recommendation: Optional[str] = None

class DependencyOut(DependencyBase):
    id: str
    scan_id: str

    class Config:
        from_attributes = True

# --- Compliance Schemas ---
class ComplianceCheckBase(BaseModel):
    framework: str
    control_id: str
    control_name: str
    status: str
    score: float = 100.0
    evidence: List[str] = []
    affected_files: List[str] = []
    recommendation: Optional[str] = None

class ComplianceCheckOut(ComplianceCheckBase):
    id: str
    scan_id: str

    class Config:
        from_attributes = True

# --- Patch Schemas ---
class PatchBase(BaseModel):
    file_path: str
    original_code: str
    patched_code: str
    diff: str
    explanation: str
    confidence: float = 0.9

class PatchOut(PatchBase):
    id: str
    scan_id: str
    finding_id: str
    status: str
    is_validated: bool
    vulnerabilities_before: int = 0
    vulnerabilities_after: int = 0
    vulnerabilities_resolved: int = 0
    vulnerabilities_introduced: int = 0
    validation_output: Optional[str] = None
    created_at: datetime.datetime

    class Config:
        from_attributes = True

# --- Report Schemas ---
class ReportOut(BaseModel):
    id: str
    scan_id: str
    title: str
    executive_summary: str
    score_breakdown: Dict[str, Any] = {}
    pdf_path: Optional[str] = None
    json_data: Dict[str, Any] = {}
    created_at: datetime.datetime

    class Config:
        from_attributes = True

# --- Agent Log Schemas ---
class AgentLogOut(BaseModel):
    id: str
    scan_id: str
    agent_name: str
    level: str
    message: str
    details: Dict[str, Any] = {}
    timestamp: datetime.datetime

    class Config:
        from_attributes = True

# --- Scan Schemas ---
class ScanCreate(BaseModel):
    repository_id: str

class ScanSummary(BaseModel):
    id: str
    repository_id: str
    repository_name: Optional[str] = None
    status: str
    progress: float
    current_stage: str
    security_score: float
    compliance_score: float
    dependency_risk: float
    false_positive_reduction_rate: float
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    dependency_vulnerabilities: int
    started_at: Optional[datetime.datetime] = None
    completed_at: Optional[datetime.datetime] = None
    duration_seconds: float
    error_message: Optional[str] = None

    class Config:
        from_attributes = True

class ScanDetailsOut(ScanSummary):
    agents: List[ScanAgentOut] = []
    findings: List[FindingOut] = []
    threats: List[ThreatOut] = []
    dependencies: List[DependencyOut] = []
    compliance_checks: List[ComplianceCheckOut] = []
    patches: List[PatchOut] = []
    report: Optional[ReportOut] = None

# --- Knowledge Graph Schemas ---
class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # File, Function, Class, API_Endpoint, Database, User_Input, Auth, Dependency, Sensitive_Data, Threat, Finding
    properties: Dict[str, Any] = {}

class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str  # CALLS, IMPORTS, CONTAINS, EXPOSES, FLOWS_TO, AFFECTS, MITIGATES
    properties: Dict[str, Any] = {}

class KnowledgeGraphOut(BaseModel):
    scan_id: str
    nodes: List[GraphNode] = []
    edges: List[GraphEdge] = []
    stats: Dict[str, int] = {}
