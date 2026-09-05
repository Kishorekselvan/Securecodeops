import os
import ast
import re
from typing import Dict, List, Any, Optional

class CodeSymbol:
    def __init__(self, name: str, symbol_type: str, line: int, end_line: Optional[int] = None, details: Dict[str, Any] = None):
        self.name = name
        self.symbol_type = symbol_type  # function, class, endpoint, db_call, auth_check, user_input, sensitive_data
        self.line = line
        self.end_line = end_line or line
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.symbol_type,
            "line": self.line,
            "end_line": self.end_line,
            "details": self.details
        }

class PythonASTVisitor(ast.NodeVisitor):
    def __init__(self, source_code: str, file_path: str):
        self.source_lines = source_code.splitlines()
        self.file_path = file_path
        self.symbols: List[CodeSymbol] = []
        self.imports: List[str] = []
        self.endpoints: List[CodeSymbol] = []
        self.db_operations: List[CodeSymbol] = []
        self.auth_checks: List[CodeSymbol] = []
        self.user_inputs: List[CodeSymbol] = []
        self.sensitive_data: List[CodeSymbol] = []

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.imports.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        for alias in node.names:
            self.imports.append(f"{mod}.{alias.name}")
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        self.symbols.append(CodeSymbol(
            name=node.name,
            symbol_type="class",
            line=node.lineno,
            end_line=getattr(node, 'end_lineno', node.lineno),
            details={"bases": [ast.unparse(b) for b in node.bases]}
        ))
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._analyze_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._analyze_function(node, is_async=True)
        self.generic_visit(node)

    def _analyze_function(self, node: Any, is_async: bool = False):
        decorators = [ast.unparse(d) for d in node.decorator_list]
        args = [arg.arg for arg in node.args.args]
        
        # Check if function is a web endpoint
        is_endpoint = False
        http_method = "UNKNOWN"
        route_path = ""
        
        for d in decorators:
            if any(method in d.lower() for method in ['get', 'post', 'put', 'delete', 'patch', 'route', 'api_view']):
                is_endpoint = True
                match = re.search(r'["\'](/[^"\']*)["\']', d)
                if match:
                    route_path = match.group(1)
                for m in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    if m.lower() in d.lower():
                        http_method = m
                        break
            # Auth check decorator
            if any(auth_term in d.lower() for auth_term in ['auth', 'login_required', 'jwt', 'roles', 'permission', 'security']):
                self.auth_checks.append(CodeSymbol(
                    name=f"Auth: {d}",
                    symbol_type="auth_check",
                    line=node.lineno,
                    details={"decorator": d, "target_function": node.name}
                ))

        func_symbol = CodeSymbol(
            name=node.name,
            symbol_type="function",
            line=node.lineno,
            end_line=getattr(node, 'end_lineno', node.lineno),
            details={"args": args, "decorators": decorators, "is_async": is_async}
        )
        self.symbols.append(func_symbol)

        if is_endpoint:
            self.endpoints.append(CodeSymbol(
                name=f"{http_method} {route_path or '/' + node.name}",
                symbol_type="endpoint",
                line=node.lineno,
                end_line=getattr(node, 'end_lineno', node.lineno),
                details={"method": http_method, "path": route_path, "handler": node.name, "args": args}
            ))

    def visit_Call(self, node: ast.Call):
        func_name = ""
        try:
            func_name = ast.unparse(node.func)
        except Exception:
            pass

        # Check DB / ORM execution
        if any(term in func_name.lower() for term in ['execute', 'raw', 'cursor', 'objects.filter', 'query', 'session.add', 'find_one', 'aggregate']):
            self.db_operations.append(CodeSymbol(
                name=f"DB Operation: {func_name}",
                symbol_type="db_call",
                line=node.lineno,
                details={"expression": func_name}
            ))

        # Check raw exec / eval / subprocess
        if any(term in func_name for term in ['eval', 'exec', 'os.system', 'subprocess.Popen', 'subprocess.run', 'subprocess.call', 'pickle.loads', 'yaml.load']):
            self.symbols.append(CodeSymbol(
                name=f"Dangerous Sink: {func_name}",
                symbol_type="sensitive_sink",
                line=node.lineno,
                details={"call": func_name}
            ))

        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        # Detect references to sensitive data patterns
        name_lower = node.id.lower()
        if any(sec in name_lower for sec in ['secret', 'password', 'api_key', 'jwt_secret', 'private_key', 'access_token']):
            self.sensitive_data.append(CodeSymbol(
                name=node.id,
                symbol_type="sensitive_data",
                line=node.lineno,
                details={"identifier": node.id}
            ))
        self.generic_visit(node)


class CodeParser:
    """Multi-language parser supporting Python AST and JS/TS/Java/Go heuristic extraction."""

    @staticmethod
    def parse_python_file(file_path: str, content: str) -> Dict[str, Any]:
        try:
            tree = ast.parse(content, filename=file_path)
            visitor = PythonASTVisitor(content, file_path)
            visitor.visit(tree)
            return {
                "symbols": [s.to_dict() for s in visitor.symbols],
                "imports": visitor.imports,
                "endpoints": [e.to_dict() for e in visitor.endpoints],
                "db_operations": [d.to_dict() for d in visitor.db_operations],
                "auth_checks": [a.to_dict() for a in visitor.auth_checks],
                "sensitive_data": [s.to_dict() for s in visitor.sensitive_data],
                "lines_of_code": len(content.splitlines()),
                "status": "PARSED"
            }
        except SyntaxError as e:
            return CodeParser._fallback_regex_parse(file_path, content, language="python", error=str(e))
        except Exception as e:
            return CodeParser._fallback_regex_parse(file_path, content, language="python", error=str(e))

    @staticmethod
    def parse_javascript_file(file_path: str, content: str) -> Dict[str, Any]:
        return CodeParser._parse_js_ts(file_path, content, language="javascript")

    @staticmethod
    def parse_typescript_file(file_path: str, content: str) -> Dict[str, Any]:
        return CodeParser._parse_js_ts(file_path, content, language="typescript")

    @staticmethod
    def parse_java_file(file_path: str, content: str) -> Dict[str, Any]:
        return CodeParser._parse_java(file_path, content)

    @staticmethod
    def _parse_js_ts(file_path: str, content: str, language: str) -> Dict[str, Any]:
        lines = content.splitlines()
        symbols = []
        endpoints = []
        db_operations = []
        auth_checks = []
        sensitive_data = []
        imports = []

        # Import regex
        import_matches = re.finditer(r'(?:import\s+.*?\s+from\s+[\'"](.*?)[\'"]|require\([\'"](.*?)[\'"]\))', content)
        for m in import_matches:
            imp = m.group(1) or m.group(2)
            if imp:
                imports.append(imp)

        # Route / Endpoint regex (Express / Fastify / NestJS / Koa)
        # e.g., app.get('/users', ...), router.post('/login', ...)
        endpoint_matches = re.finditer(r'(?:app|router)\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', content, re.IGNORECASE)
        for m in endpoint_matches:
            line_no = content[:m.start()].count('\n') + 1
            method = m.group(1).upper()
            path = m.group(2)
            endpoints.append({
                "name": f"{method} {path}",
                "type": "endpoint",
                "line": line_no,
                "end_line": line_no,
                "details": {"method": method, "path": path}
            })

        # Function definitions
        fn_matches = re.finditer(r'(?:function\s+([a-zA-Z0-9_$]+)|(?:const|let|var)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|([a-zA-Z0-9_$]+)\s*\([^)]*\)\s*\{)', content)
        for m in fn_matches:
            name = m.group(1) or m.group(2) or m.group(3)
            if name and name not in ['if', 'for', 'while', 'switch', 'catch']:
                line_no = content[:m.start()].count('\n') + 1
                symbols.append({
                    "name": name,
                    "type": "function",
                    "line": line_no,
                    "end_line": line_no,
                    "details": {}
                })

        # DB operations (Sequelize, Prisma, Mongoose, TypeORM, raw query)
        db_matches = re.finditer(r'(\w+)\.(query|find|findOne|findById|create|update|destroy|save|aggregate|execute)\s*\(', content)
        for m in db_matches:
            line_no = content[:m.start()].count('\n') + 1
            db_operations.append({
                "name": f"DB: {m.group(0)}",
                "type": "db_call",
                "line": line_no,
                "end_line": line_no,
                "details": {"call": m.group(0)}
            })

        # Auth checks
        auth_matches = re.finditer(r'(passport\.authenticate|jwt\.verify|checkAuth|isAuthenticated|requireAuth|authMiddleware|verifyToken)', content, re.IGNORECASE)
        for m in auth_matches:
            line_no = content[:m.start()].count('\n') + 1
            auth_checks.append({
                "name": f"Auth: {m.group(1)}",
                "type": "auth_check",
                "line": line_no,
                "end_line": line_no,
                "details": {"token": m.group(1)}
            })

        # Sensitive variables
        sec_matches = re.finditer(r'(?:const|let|var)\s+([a-zA-Z0-9_$]*(?:secret|password|token|apikey|privatekey)[a-zA-Z0-9_$]*)\s*=', content, re.IGNORECASE)
        for m in sec_matches:
            line_no = content[:m.start()].count('\n') + 1
            sensitive_data.append({
                "name": m.group(1),
                "type": "sensitive_data",
                "line": line_no,
                "end_line": line_no,
                "details": {"variable": m.group(1)}
            })

        return {
            "symbols": symbols,
            "imports": list(set(imports)),
            "endpoints": endpoints,
            "db_operations": db_operations,
            "auth_checks": auth_checks,
            "sensitive_data": sensitive_data,
            "lines_of_code": len(lines),
            "status": "PARSED_HEURISTIC"
        }

    @staticmethod
    def _parse_java(file_path: str, content: str) -> Dict[str, Any]:
        lines = content.splitlines()
        symbols = []
        endpoints = []
        db_operations = []
        auth_checks = []
        sensitive_data = []
        imports = []

        # Spring Boot Mapping / JAX-RS
        endpoint_matches = re.finditer(r'@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']', content)
        for m in endpoint_matches:
            line_no = content[:m.start()].count('\n') + 1
            method = m.group(1).replace("Mapping", "").upper()
            if method == "REQUEST":
                method = "HTTP"
            path = m.group(2)
            endpoints.append({
                "name": f"{method} {path}",
                "type": "endpoint",
                "line": line_no,
                "end_line": line_no,
                "details": {"annotation": m.group(1), "path": path}
            })

        # Java Spring Security / Auth
        auth_matches = re.finditer(r'@(PreAuthorize|Secured|RolesAllowed|AuthenticationPrincipal)', content)
        for m in auth_matches:
            line_no = content[:m.start()].count('\n') + 1
            auth_checks.append({
                "name": f"Auth: {m.group(1)}",
                "type": "auth_check",
                "line": line_no,
                "end_line": line_no,
                "details": {"annotation": m.group(1)}
            })

        return {
            "symbols": symbols,
            "imports": imports,
            "endpoints": endpoints,
            "db_operations": db_operations,
            "auth_checks": auth_checks,
            "sensitive_data": sensitive_data,
            "lines_of_code": len(lines),
            "status": "PARSED_JAVA"
        }

    @staticmethod
    def _fallback_regex_parse(file_path: str, content: str, language: str, error: str = "") -> Dict[str, Any]:
        lines = content.splitlines()
        return {
            "symbols": [],
            "imports": [],
            "endpoints": [],
            "db_operations": [],
            "auth_checks": [],
            "sensitive_data": [],
            "lines_of_code": len(lines),
            "status": "FALLBACK_PARSED",
            "parse_error": error
        }

    @classmethod
    def parse_file(cls, file_path: str, content: str) -> Dict[str, Any]:
        ext = os.path.splitext(file_path)[1].lower()
        if ext == '.py':
            return cls.parse_python_file(file_path, content)
        elif ext in ['.js', '.jsx', '.mjs', '.cjs']:
            return cls.parse_javascript_file(file_path, content)
        elif ext in ['.ts', '.tsx']:
            return cls.parse_typescript_file(file_path, content)
        elif ext in ['.java']:
            return cls.parse_java_file(file_path, content)
        else:
            return cls._fallback_regex_parse(file_path, content, language=ext.replace('.', ''))
