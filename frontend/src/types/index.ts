export interface Repository {
  id: string;
  name: string;
  description?: string;
  storage_path: string;
  languages: string[];
  frameworks: string[];
  file_count: number;
  lines_of_code: number;
  is_demo: boolean;
  created_at: string;
  updated_at: string;
}

export interface ScanAgent {
  id: string;
  scan_id: string;
  name: string;
  agent_type: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'SKIPPED';
  started_at?: string;
  completed_at?: string;
  duration_seconds: number;
  findings_count: number;
  error_message?: string;
  input_summary: Record<string, any>;
  output_summary: Record<string, any>;
}

export interface Finding {
  id: string;
  scan_id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: number;
  category: string;
  cwe?: string;
  owasp?: string;
  file_path: string;
  line_number?: number;
  end_line_number?: number;
  code_snippet?: string;
  evidence: Record<string, any>;
  scanner: string;
  status: 'OPEN' | 'RESOLVED' | 'FALSE_POSITIVE' | 'SUPPRESSED';
  ai_validation_status: 'VALIDATED' | 'FALSE_POSITIVE' | 'UNCERTAIN' | 'UNAVAILABLE' | 'PENDING';
  ai_reasoning?: string;
  ai_confidence?: number;
  ai_severity_adjustment?: string;
  ai_attack_scenario?: string;
  ai_remediation?: string;
  created_at: string;
}

export interface Threat {
  id: string;
  scan_id: string;
  category: 'Spoofing' | 'Tampering' | 'Repudiation' | 'Information Disclosure' | 'Denial of Service' | 'Elevation of Privilege';
  title: string;
  description: string;
  affected_component: string;
  attack_vector: string;
  impacted_assets: string[];
  impact: number;
  probability: number;
  risk_score: number;
  risk_level: 'Critical' | 'High' | 'Medium' | 'Low';
  existing_controls: string[];
  recommended_controls: string[];
  attack_path: Array<{
    step: number;
    name: string;
    type: string;
    description: string;
    file?: string;
    line?: number;
    code_snippet?: string;
  }>;
}

export interface Dependency {
  id: string;
  scan_id: string;
  package_name: string;
  installed_version: string;
  ecosystem: string;
  manifest_file: string;
  is_direct: boolean;
  is_vulnerable: boolean;
  cve_id?: string;
  cvss_score?: number;
  severity?: string;
  affected_versions?: string;
  fixed_version?: string;
  exposure_factor: number;
  risk_contribution: number;
  recommendation?: string;
}

export interface ComplianceCheck {
  id: string;
  scan_id: string;
  framework: string;
  control_id: string;
  control_name: string;
  status: 'PASS' | 'FAIL' | 'PARTIAL' | 'NOT_APPLICABLE';
  score: number;
  evidence: string[];
  affected_files: string[];
  recommendation?: string;
}

export interface Patch {
  id: string;
  scan_id: string;
  finding_id: string;
  file_path: string;
  original_code: string;
  patched_code: string;
  diff: string;
  explanation: string;
  confidence: number;
  status: 'PROPOSED' | 'VALIDATED' | 'APPLIED' | 'REJECTED';
  is_validated: boolean;
  vulnerabilities_before: number;
  vulnerabilities_after: number;
  vulnerabilities_resolved: number;
  vulnerabilities_introduced: number;
  validation_output?: string;
  created_at: string;
}

export interface Report {
  id: string;
  scan_id: string;
  title: string;
  executive_summary: string;
  score_breakdown: {
    security_score: number;
    base_score: number;
    penalties: Record<string, number>;
    formula: string;
  };
  pdf_path?: string;
  json_data: Record<string, any>;
  created_at: string;
}

export interface ScanSummary {
  id: string;
  repository_id: string;
  repository_name?: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  progress: number;
  current_stage: string;
  security_score: number;
  compliance_score: number;
  dependency_risk: number;
  false_positive_reduction_rate: number;
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  dependency_vulnerabilities: number;
  started_at?: string;
  completed_at?: string;
  duration_seconds: number;
  error_message?: string;
}

export interface ScanDetails extends ScanSummary {
  agents: ScanAgent[];
  findings: Finding[];
  threats: Threat[];
  dependencies: Dependency[];
  compliance_checks: ComplianceCheck[];
  patches: Patch[];
  report?: Report;
}

export interface AgentLog {
  id: string;
  scan_id: string;
  agent_name: string;
  level: 'INFO' | 'WARNING' | 'ERROR' | 'SUCCESS';
  message: string;
  details: Record<string, any>;
  timestamp: string;
}

export interface KnowledgeGraph {
  scan_id: string;
  nodes: Array<{
    id: string;
    label: string;
    type: string;
    properties: Record<string, any>;
  }>;
  edges: Array<{
    id: string;
    source: string;
    target: string;
    label: string;
    properties: Record<string, any>;
  }>;
  stats: Record<string, number>;
}
