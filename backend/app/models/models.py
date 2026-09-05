import datetime
import uuid
from sqlalchemy import (
    Column, String, Integer, Float, Text, Boolean, DateTime, ForeignKey, JSON
)
from sqlalchemy.orm import relationship
from app.db.session import Base

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    repositories = relationship("Repository", back_populates="owner", cascade="all, delete-orphan")


class Repository(Base):
    __tablename__ = "repositories"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    owner_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    storage_path = Column(String(512), nullable=False)
    languages = Column(JSON, default=list)  # ["Python", "JavaScript", etc.]
    frameworks = Column(JSON, default=list)
    file_count = Column(Integer, default=0)
    lines_of_code = Column(Integer, default=0)
    is_demo = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    owner = relationship("User", back_populates="repositories")
    scans = relationship("Scan", back_populates="repository", cascade="all, delete-orphan")
    files = relationship("FileRecord", back_populates="repository", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    repository_id = Column(String(36), ForeignKey("repositories.id"), nullable=False)
    status = Column(String(50), default="QUEUED")  # QUEUED, RUNNING, COMPLETED, FAILED
    progress = Column(Float, default=0.0)  # 0.0 to 100.0
    current_stage = Column(String(100), default="Initializing")
    
    # Calculated Scores
    security_score = Column(Float, default=100.0)
    compliance_score = Column(Float, default=100.0)
    dependency_risk = Column(Float, default=0.0)
    false_positive_reduction_rate = Column(Float, default=0.0)
    
    # Counts
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    dependency_vulnerabilities = Column(Integer, default=0)
    
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, default=0.0)
    error_message = Column(Text, nullable=True)
    
    repository = relationship("Repository", back_populates="scans")
    agents = relationship("ScanAgent", back_populates="scan", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    threats = relationship("Threat", back_populates="scan", cascade="all, delete-orphan")
    dependencies = relationship("Dependency", back_populates="scan", cascade="all, delete-orphan")
    compliance_checks = relationship("ComplianceCheck", back_populates="scan", cascade="all, delete-orphan")
    patches = relationship("Patch", back_populates="scan", cascade="all, delete-orphan")
    report = relationship("Report", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    agent_logs = relationship("AgentLog", back_populates="scan", cascade="all, delete-orphan")


class ScanAgent(Base):
    __tablename__ = "scan_agents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    name = Column(String(100), nullable=False)  # e.g., "Repository Analysis Agent"
    agent_type = Column(String(50), nullable=False)
    status = Column(String(50), default="QUEUED")  # QUEUED, RUNNING, COMPLETED, FAILED, SKIPPED
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Float, default=0.0)
    findings_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    input_summary = Column(JSON, default=dict)
    output_summary = Column(JSON, default=dict)

    scan = relationship("Scan", back_populates="agents")


class FileRecord(Base):
    __tablename__ = "files"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    repository_id = Column(String(36), ForeignKey("repositories.id"), nullable=False)
    relative_path = Column(String(512), nullable=False)
    language = Column(String(50), nullable=True)
    size_bytes = Column(Integer, default=0)
    line_count = Column(Integer, default=0)
    ast_summary = Column(JSON, default=dict)  # functions, classes, imports, routes
    is_sensitive = Column(Boolean, default=False)
    
    repository = relationship("Repository", back_populates="files")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence = Column(Float, default=0.8)  # 0.0 to 1.0
    category = Column(String(100), nullable=False)  # SQL Injection, XSS, etc.
    cwe = Column(String(50), nullable=True)  # e.g. CWE-89
    owasp = Column(String(50), nullable=True)  # e.g. A03:2021-Injection
    file_path = Column(String(512), nullable=False)
    line_number = Column(Integer, nullable=True)
    end_line_number = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    evidence = Column(JSON, default=dict)
    scanner = Column(String(50), nullable=False)  # semgrep, bandit, trivy, gitleaks, ast, code_review
    status = Column(String(50), default="OPEN")  # OPEN, RESOLVED, FALSE_POSITIVE, SUPPRESSED
    
    # AI Validation Details
    ai_validation_status = Column(String(50), default="PENDING")  # VALIDATED, FALSE_POSITIVE, UNCERTAIN, UNAVAILABLE, PENDING
    ai_reasoning = Column(Text, nullable=True)
    ai_confidence = Column(Float, nullable=True)
    ai_severity_adjustment = Column(String(20), nullable=True)
    ai_attack_scenario = Column(Text, nullable=True)
    ai_remediation = Column(Text, nullable=True)
    
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")
    patches = relationship("Patch", back_populates="finding", cascade="all, delete-orphan")
    feedbacks = relationship("DeveloperFeedback", back_populates="finding", cascade="all, delete-orphan")


class Threat(Base):
    __tablename__ = "threats"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    category = Column(String(50), nullable=False)  # Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    affected_component = Column(String(255), nullable=False)
    attack_vector = Column(String(255), nullable=False)
    impacted_assets = Column(JSON, default=list)
    impact = Column(Integer, nullable=False)  # 1 to 5
    probability = Column(Integer, nullable=False)  # 1 to 5
    risk_score = Column(Integer, nullable=False)  # Impact * Probability (1 to 25)
    risk_level = Column(String(20), nullable=False)  # Low (1-4), Medium (5-9), High (10-16), Critical (17-25)
    existing_controls = Column(JSON, default=list)
    recommended_controls = Column(JSON, default=list)
    attack_path = Column(JSON, default=list)  # list of node steps

    scan = relationship("Scan", back_populates="threats")


class Dependency(Base):
    __tablename__ = "dependencies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    package_name = Column(String(255), nullable=False)
    installed_version = Column(String(100), nullable=False)
    ecosystem = Column(String(50), nullable=False)  # npm, pypi, maven, etc.
    manifest_file = Column(String(512), nullable=False)
    is_direct = Column(Boolean, default=True)
    is_vulnerable = Column(Boolean, default=False)
    cve_id = Column(String(100), nullable=True)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String(20), nullable=True)
    affected_versions = Column(String(255), nullable=True)
    fixed_version = Column(String(100), nullable=True)
    exposure_factor = Column(Float, default=1.0)  # 0.0 to 1.0 based on reachability in codebase
    risk_contribution = Column(Float, default=0.0)  # cvss * exposure
    recommendation = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="dependencies")


class ComplianceCheck(Base):
    __tablename__ = "compliance_checks"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    framework = Column(String(50), nullable=False)  # OWASP_TOP_10, GDPR, ISO_27001, NIST_SP_800_53, PCI_DSS
    control_id = Column(String(50), nullable=False)  # e.g., "A01:2021", "Art-32-1-b"
    control_name = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False)  # PASS, FAIL, PARTIAL, NOT_APPLICABLE
    score = Column(Float, default=100.0)  # 0 to 100
    evidence = Column(JSON, default=list)
    affected_files = Column(JSON, default=list)
    recommendation = Column(Text, nullable=True)

    scan = relationship("Scan", back_populates="compliance_checks")


class Patch(Base):
    __tablename__ = "patches"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False)
    file_path = Column(String(512), nullable=False)
    original_code = Column(Text, nullable=False)
    patched_code = Column(Text, nullable=False)
    diff = Column(Text, nullable=False)
    explanation = Column(Text, nullable=False)
    confidence = Column(Float, default=0.9)
    status = Column(String(50), default="PROPOSED")  # PROPOSED, VALIDATED, APPLIED, REJECTED
    
    # Validation results from re-scanning
    is_validated = Column(Boolean, default=False)
    vulnerabilities_before = Column(Integer, default=0)
    vulnerabilities_after = Column(Integer, default=0)
    vulnerabilities_resolved = Column(Integer, default=0)
    vulnerabilities_introduced = Column(Integer, default=0)
    validation_output = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="patches")
    finding = relationship("Finding", back_populates="patches")


class Report(Base):
    __tablename__ = "reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), unique=True, nullable=False)
    title = Column(String(255), nullable=False)
    executive_summary = Column(Text, nullable=False)
    score_breakdown = Column(JSON, default=dict)
    pdf_path = Column(String(512), nullable=True)
    json_data = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="report")


class AgentLog(Base):
    __tablename__ = "agent_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False)
    agent_name = Column(String(100), nullable=False)
    level = Column(String(20), default="INFO")  # INFO, WARNING, ERROR, SUCCESS
    message = Column(Text, nullable=False)
    details = Column(JSON, default=dict)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    scan = relationship("Scan", back_populates="agent_logs")


class DeveloperFeedback(Base):
    __tablename__ = "developer_feedbacks"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("findings.id", ondelete="CASCADE"), nullable=True)
    rule_id = Column(String(200), nullable=True)
    category = Column(String(100), nullable=False)
    file_pattern = Column(String(255), nullable=True)
    feedback_type = Column(String(50), nullable=False)  # CONFIRMED_TRUE_POSITIVE, FALSE_POSITIVE, SUPPRESSED
    developer_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    finding = relationship("Finding", back_populates="feedbacks")

