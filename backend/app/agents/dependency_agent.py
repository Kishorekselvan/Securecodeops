import os
import time
from typing import Dict, Any, List
from app.analysis.dependency_parser import DependencyParser

class DependencyScannerAgent:
    def __init__(self):
        self.name = "Dependency Scanner Agent"
        self.agent_type = "dependency_scanner"

    async def execute(self, repo_dir: str, file_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        start_time = time.time()
        dependencies: List[Dict[str, Any]] = []
        
        manifest_files = ["requirements.txt", "package.json", "pyproject.toml", "pom.xml", "go.mod"]
        
        for root, _, files in os.walk(repo_dir):
            if any(ignore in root for ignore in ['.git', 'node_modules', '__pycache__', '.venv']):
                continue
            for file in files:
                if file.lower() in manifest_files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, repo_dir).replace("\\", "/")
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        parsed_deps = DependencyParser.parse_manifest(rel_path, content)
                        
                        # Calculate exposure factor: check if package name appears in repository source code imports
                        for dep in parsed_deps:
                            pkg = dep["package_name"].lower()
                            is_used_in_code = False
                            for rec in file_records:
                                ast_summary = rec.get("ast_summary", {})
                                imports = [i.lower() for i in ast_summary.get("imports", [])]
                                if any(pkg in imp for imp in imports):
                                    is_used_in_code = True
                                    break
                            
                            # If directly imported, exposure factor is 1.0; if not directly imported (e.g. CLI tool or transitive), 0.6
                            dep["exposure_factor"] = 1.0 if is_used_in_code else 0.6
                            if dep["is_vulnerable"] and dep["cvss_score"]:
                                dep["risk_contribution"] = round(dep["cvss_score"] * dep["exposure_factor"], 2)
                            
                            dependencies.append(dep)
                    except Exception:
                        continue

        # Calculate Total Dependency Risk = sum(CVSS * Exposure Factor)
        total_risk = sum(d.get("risk_contribution", 0.0) for d in dependencies)
        vulnerable_count = sum(1 for d in dependencies if d.get("is_vulnerable"))

        duration = round(time.time() - start_time, 2)
        return {
            "status": "COMPLETED",
            "duration_seconds": duration,
            "total_dependencies": len(dependencies),
            "vulnerable_dependencies": vulnerable_count,
            "dependency_risk_score": round(total_risk, 2),
            "dependencies": dependencies
        }
