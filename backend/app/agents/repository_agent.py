import os
import time
from typing import Dict, Any, List
from app.analysis.ast_parser import CodeParser
from app.analysis.knowledge_graph import KnowledgeGraphBuilder

class RepositoryAnalysisAgent:
    def __init__(self):
        self.name = "Repository Analysis Agent"
        self.agent_type = "repository_analysis"

    async def execute(self, repo_dir: str, scan_id: str) -> Dict[str, Any]:
        start_time = time.time()
        file_records = []
        languages = set()
        frameworks = set()
        total_loc = 0
        
        kg_builder = KnowledgeGraphBuilder(scan_id)
        
        all_endpoints = []
        all_db_ops = []
        all_auth_checks = []
        all_sensitive_data = []

        for root, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv', 'dist', 'build']]
            for file in files:
                ext = os.path.splitext(file)[1].lower()
                if ext in ['.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.tar', '.gz', '.db', '.sqlite', '.pyc']:
                    continue

                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, repo_dir).replace("\\", "/")
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                except Exception:
                    continue

                # Language detection
                lang = "Unknown"
                if ext == '.py':
                    lang = "Python"
                elif ext in ['.js', '.jsx']:
                    lang = "JavaScript"
                elif ext in ['.ts', '.tsx']:
                    lang = "TypeScript"
                elif ext == '.java':
                    lang = "Java"
                elif ext in ['.json', '.yaml', '.yml', '.toml']:
                    lang = "Config"
                elif ext == '.html':
                    lang = "HTML"
                elif ext == '.css':
                    lang = "CSS"
                
                if lang != "Unknown":
                    languages.add(lang)

                # Parse AST/Symbols
                parsed_data = CodeParser.parse_file(rel_path, content)
                loc = parsed_data.get("lines_of_code", len(content.splitlines()))
                total_loc += loc

                # Framework detection heuristics
                content_lower = content.lower()
                if "fastapi" in content_lower:
                    frameworks.add("FastAPI")
                if "flask" in content_lower:
                    frameworks.add("Flask")
                if "django" in content_lower:
                    frameworks.add("Django")
                if "express" in content_lower or "require('express')" in content_lower:
                    frameworks.add("Express.js")
                if "react" in content_lower:
                    frameworks.add("React")
                if "springframework" in content_lower or "@springbootapplication" in content_lower:
                    frameworks.add("Spring Boot")

                # Knowledge Graph nodes
                kg_builder.add_file_node(rel_path, lang, loc)
                
                for sym in parsed_data.get("symbols", []):
                    if sym.get("type") == "function":
                        kg_builder.add_function_node(rel_path, sym["name"], sym["line"], sym.get("details", {}).get("args"))

                for ep in parsed_data.get("endpoints", []):
                    ep["file"] = rel_path
                    all_endpoints.append(ep)
                    kg_builder.add_endpoint_node(
                        rel_path,
                        ep["name"],
                        ep.get("details", {}).get("method", "HTTP"),
                        ep.get("details", {}).get("path", ep["name"]),
                        ep["line"]
                    )

                for db in parsed_data.get("db_operations", []):
                    db["file"] = rel_path
                    all_db_ops.append(db)
                    kg_builder.add_database_node(rel_path, db["name"], db["line"])

                for auth in parsed_data.get("auth_checks", []):
                    auth["file"] = rel_path
                    all_auth_checks.append(auth)
                    kg_builder.add_auth_node(rel_path, auth["name"], auth["line"])

                for sec in parsed_data.get("sensitive_data", []):
                    sec["file"] = rel_path
                    all_sensitive_data.append(sec)
                    kg_builder.add_sensitive_data_node(rel_path, sec["name"], sec["line"])

                file_records.append({
                    "relative_path": rel_path,
                    "language": lang,
                    "size_bytes": len(content.encode('utf-8')),
                    "line_count": loc,
                    "ast_summary": parsed_data,
                    "is_sensitive": bool(parsed_data.get("sensitive_data"))
                })

        duration = round(time.time() - start_time, 2)
        kg_dict = kg_builder.to_dict()

        return {
            "status": "COMPLETED",
            "duration_seconds": duration,
            "languages": list(languages),
            "frameworks": list(frameworks),
            "file_count": len(file_records),
            "lines_of_code": total_loc,
            "files": file_records,
            "endpoints": all_endpoints,
            "db_operations": all_db_ops,
            "auth_checks": all_auth_checks,
            "sensitive_data": all_sensitive_data,
            "knowledge_graph": kg_dict
        }
