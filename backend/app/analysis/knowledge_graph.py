import os
import networkx as nx
from typing import Dict, List, Any, Optional

class KnowledgeGraphBuilder:
    def __init__(self, scan_id: str):
        self.scan_id = scan_id
        self.graph = nx.DiGraph()

    def add_file_node(self, file_path: str, language: str, line_count: int):
        node_id = f"file:{file_path}"
        self.graph.add_node(
            node_id,
            id=node_id,
            label=os.path.basename(file_path),
            type="File",
            properties={
                "path": file_path,
                "language": language,
                "lines": line_count
            }
        )
        return node_id

    def add_function_node(self, file_path: str, func_name: str, line: int, args: List[str] = None):
        node_id = f"func:{file_path}:{func_name}"
        self.graph.add_node(
            node_id,
            id=node_id,
            label=f"{func_name}()",
            type="Function",
            properties={
                "file": file_path,
                "name": func_name,
                "line": line,
                "args": args or []
            }
        )
        # Connect File -> Function
        file_node_id = f"file:{file_path}"
        if self.graph.has_node(file_node_id):
            self.add_edge(file_node_id, node_id, "CONTAINS")
        return node_id

    def add_endpoint_node(self, file_path: str, endpoint_name: str, method: str, path: str, line: int):
        node_id = f"endpoint:{file_path}:{method}:{path}"
        self.graph.add_node(
            node_id,
            id=node_id,
            label=f"[{method}] {path}",
            type="API_Endpoint",
            properties={
                "file": file_path,
                "method": method,
                "path": path,
                "line": line
            }
        )
        file_node_id = f"file:{file_path}"
        if self.graph.has_node(file_node_id):
            self.add_edge(file_node_id, node_id, "EXPOSES")
        return node_id

    def add_database_node(self, file_path: str, db_op_name: str, line: int):
        node_id = f"db:{file_path}:{line}"
        self.graph.add_node(
            node_id,
            id=node_id,
            label="Database Sink",
            type="Database",
            properties={
                "file": file_path,
                "operation": db_op_name,
                "line": line
            }
        )
        file_node_id = f"file:{file_path}"
        if self.graph.has_node(file_node_id):
            self.add_edge(file_node_id, node_id, "CONTAINS")
        return node_id

    def add_auth_node(self, file_path: str, auth_name: str, line: int):
        node_id = f"auth:{file_path}:{line}"
        self.graph.add_node(
            node_id,
            id=node_id,
            label=auth_name,
            type="Auth",
            properties={
                "file": file_path,
                "name": auth_name,
                "line": line
            }
        )
        file_node_id = f"file:{file_path}"
        if self.graph.has_node(file_node_id):
            self.add_edge(file_node_id, node_id, "CONTAINS")
        return node_id

    def add_sensitive_data_node(self, file_path: str, secret_name: str, line: int):
        node_id = f"secret:{file_path}:{secret_name}:{line}"
        self.graph.add_node(
            node_id,
            id=node_id,
            label=f"Secret: {secret_name}",
            type="Sensitive_Data",
            properties={
                "file": file_path,
                "identifier": secret_name,
                "line": line
            }
        )
        file_node_id = f"file:{file_path}"
        if self.graph.has_node(file_node_id):
            self.add_edge(file_node_id, node_id, "CONTAINS")
        return node_id

    def add_dependency_node(self, package_name: str, version: str, is_vulnerable: bool, cve_id: Optional[str] = None):
        node_id = f"dep:{package_name}"
        self.graph.add_node(
            node_id,
            id=node_id,
            label=f"{package_name}@{version}",
            type="Dependency",
            properties={
                "package": package_name,
                "version": version,
                "is_vulnerable": is_vulnerable,
                "cve": cve_id
            }
        )
        return node_id

    def add_finding_node(self, finding_id: str, title: str, severity: str, file_path: str, line: Optional[int]):
        node_id = f"finding:{finding_id}"
        self.graph.add_node(
            node_id,
            id=node_id,
            label=f"[{severity}] {title}",
            type="Finding",
            properties={
                "id": finding_id,
                "title": title,
                "severity": severity,
                "file": file_path,
                "line": line
            }
        )
        file_node_id = f"file:{file_path}"
        if self.graph.has_node(file_node_id):
            self.add_edge(node_id, file_node_id, "AFFECTS")
        return node_id

    def add_threat_node(self, threat_id: str, title: str, category: str, risk_level: str, affected_component: str):
        node_id = f"threat:{threat_id}"
        self.graph.add_node(
            node_id,
            id=node_id,
            label=f"[{category}] {title}",
            type="Threat",
            properties={
                "id": threat_id,
                "title": title,
                "category": category,
                "risk_level": risk_level,
                "affected_component": affected_component
            }
        )
        return node_id

    def add_edge(self, source_id: str, target_id: str, label: str, properties: Dict[str, Any] = None):
        edge_id = f"{source_id}->{label}->{target_id}"
        self.graph.add_edge(
            source_id,
            target_id,
            id=edge_id,
            label=label,
            properties=properties or {}
        )

    def to_dict(self) -> Dict[str, Any]:
        nodes = []
        for n, data in self.graph.nodes(data=True):
            nodes.append({
                "id": n,
                "label": data.get("label", n),
                "type": data.get("type", "Generic"),
                "properties": data.get("properties", {})
            })

        edges = []
        for u, v, data in self.graph.edges(data=True):
            edges.append({
                "id": data.get("id", f"{u}->{v}"),
                "source": u,
                "target": v,
                "label": data.get("label", "CONNECTS"),
                "properties": data.get("properties", {})
            })

        stats = {}
        for n in nodes:
            t = n["type"]
            stats[t] = stats.get(t, 0) + 1

        return {
            "scan_id": self.scan_id,
            "nodes": nodes,
            "edges": edges,
            "stats": stats
        }
