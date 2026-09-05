import re
from typing import List, Dict, Any, Optional

class AttackPathStep:
    def __init__(self, step_number: int, name: str, node_type: str, description: str, file_path: Optional[str] = None, line: Optional[int] = None, code_snippet: Optional[str] = None):
        self.step_number = step_number
        self.name = name
        self.node_type = node_type  # User_Input, Entry_Point, Sanitization_Bypass, Vulnerable_Sink, Impacted_Asset
        self.description = description
        self.file_path = file_path
        self.line = line
        self.code_snippet = code_snippet

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step_number,
            "name": self.name,
            "type": self.node_type,
            "description": self.description,
            "file": self.file_path,
            "line": self.line,
            "code_snippet": self.code_snippet
        }

class DataFlowAnalyzer:
    """Analyzes data flow from untrusted sources to security-critical sinks."""

    @staticmethod
    def generate_attack_path_for_finding(finding: Dict[str, Any], endpoints: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        category = finding.get("category", "").lower()
        file_path = finding.get("file_path", "")
        line = finding.get("line_number", 1)
        snippet = finding.get("code_snippet", "")
        
        # Find matching endpoint in the same file or default
        matched_endpoint = None
        for ep in endpoints:
            if ep.get("file") == file_path:
                matched_endpoint = ep
                break

        steps = []
        
        if "sql injection" in category or "sqli" in category:
            steps.append(AttackPathStep(
                step_number=1,
                name="Untrusted User Input",
                node_type="User_Input",
                description="Attacker sends malicious input payload (e.g. `' OR '1'='1`) via HTTP parameter or request body.",
                file_path=file_path,
                line=line
            ))
            steps.append(AttackPathStep(
                step_number=2,
                name=f"API Handler: {matched_endpoint.get('name', 'HTTP Route') if matched_endpoint else 'Route Handler'}",
                node_type="Entry_Point",
                description="Application receives request and extracts raw parameter without strict type validation.",
                file_path=file_path,
                line=matched_endpoint.get("line", line) if matched_endpoint else line
            ))
            steps.append(AttackPathStep(
                step_number=3,
                name="Missing Input Sanitization",
                node_type="Sanitization_Bypass",
                description="String concatenation or unescaped format string combines user payload into dynamic SQL statement.",
                file_path=file_path,
                line=line,
                code_snippet=snippet
            ))
            steps.append(AttackPathStep(
                step_number=4,
                name="Vulnerable Database Sink",
                node_type="Vulnerable_Sink",
                description="Database engine executes modified SQL query structure under application database credentials.",
                file_path=file_path,
                line=line,
                code_snippet=snippet
            ))
            steps.append(AttackPathStep(
                step_number=5,
                name="Data Exfiltration / Tampering",
                node_type="Impacted_Asset",
                description="Attacker achieves unauthorized data disclosure, authentication bypass, or data modification.",
                file_path=file_path
            ))
            
        elif "xss" in category or "cross-site scripting" in category:
            steps.append(AttackPathStep(
                step_number=1,
                name="Malicious Script Input",
                node_type="User_Input",
                description="Attacker crafts input containing executable JavaScript markup `<script>alert(1)</script>`."
            ))
            steps.append(AttackPathStep(
                step_number=2,
                name="Endpoint Processing",
                node_type="Entry_Point",
                description="Server stores or reflects input parameter without HTML context-aware output encoding.",
                file_path=file_path,
                line=line
            ))
            steps.append(AttackPathStep(
                step_number=3,
                name="Unescaped Reflection Sink",
                node_type="Vulnerable_Sink",
                description="Application renders untrusted data directly in DOM / HTML body without escaping.",
                file_path=file_path,
                line=line,
                code_snippet=snippet
            ))
            steps.append(AttackPathStep(
                step_number=4,
                name="Victim Browser Execution",
                node_type="Impacted_Asset",
                description="Victim's browser executes injected JavaScript, leading to session hijacking or credential theft."
            ))
            
        elif "command injection" in category or "subprocess" in category or "exec" in category:
            steps.append(AttackPathStep(
                step_number=1,
                name="Shell Metacharacter Payload",
                node_type="User_Input",
                description="Attacker submits shell separator payload (e.g. `; cat /etc/passwd` or `| whoami`)."
            ))
            steps.append(AttackPathStep(
                step_number=2,
                name="Host System Command Sink",
                node_type="Vulnerable_Sink",
                description="Runtime executes system shell (`os.system` / `subprocess` with shell=True) with unvalidated input.",
                file_path=file_path,
                line=line,
                code_snippet=snippet
            ))
            steps.append(AttackPathStep(
                step_number=3,
                name="Remote Code Execution (RCE)",
                node_type="Impacted_Asset",
                description="Attacker achieves arbitrary OS command execution with application server privileges."
            ))
            
        elif "secret" in category or "hardcoded" in category:
            steps.append(AttackPathStep(
                step_number=1,
                name="Exposed Credential in Source",
                node_type="User_Input",
                description="Static token, private key, or password embedded in source code.",
                file_path=file_path,
                line=line,
                code_snippet=snippet
            ))
            steps.append(AttackPathStep(
                step_number=2,
                name="Source Repository Exposure",
                node_type="Vulnerable_Sink",
                description="Credential accessible via repository history, artifact bundling, or public repository leaks.",
                file_path=file_path,
                line=line
            ))
            steps.append(AttackPathStep(
                step_number=3,
                name="Unauthorized Resource Compromise",
                node_type="Impacted_Asset",
                description="Attacker leverages credentials to authenticate directly against internal APIs or cloud providers."
            ))
            
        else:
            steps.append(AttackPathStep(
                step_number=1,
                name="Untrusted Input Vector",
                node_type="User_Input",
                description="Attacker interacts with application component using crafted input.",
                file_path=file_path,
                line=line
            ))
            steps.append(AttackPathStep(
                step_number=2,
                name="Vulnerable Processing Logic",
                node_type="Vulnerable_Sink",
                description=finding.get("description", "Security weakness in code execution."),
                file_path=file_path,
                line=line,
                code_snippet=snippet
            ))
            steps.append(AttackPathStep(
                step_number=3,
                name="Security Impact",
                node_type="Impacted_Asset",
                description=f"Compromise of confidentiality, integrity, or availability ({finding.get('severity', 'HIGH')} severity)."
            ))

        return [s.to_dict() for s in steps]
