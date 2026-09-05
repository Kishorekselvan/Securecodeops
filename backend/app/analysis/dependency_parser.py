import os
import json
import re
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Optional

# Embedded Known Vulnerability Advisory Database (OSV / NVD subset for offline verification)
KNOWN_VULNERABILITIES = [
    {
        "ecosystem": "pypi",
        "package": "requests",
        "vulnerable_below": "2.31.0",
        "cve": "CVE-2023-32681",
        "cvss": 6.1,
        "severity": "MEDIUM",
        "fixed": "2.31.0",
        "desc": "Requests Unintended leak of Proxy-Authorization header to destination"
    },
    {
        "ecosystem": "pypi",
        "package": "flask",
        "vulnerable_below": "2.2.5",
        "cve": "CVE-2023-30861",
        "cvss": 7.5,
        "severity": "HIGH",
        "fixed": "2.2.5",
        "desc": "Flask unexpected session cookie disclosure due to missing Vary: Cookie header"
    },
    {
        "ecosystem": "pypi",
        "package": "pyyaml",
        "vulnerable_below": "5.4.0",
        "cve": "CVE-2020-14343",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "fixed": "5.4.0",
        "desc": "PyYAML Arbitrary Code Execution through full_load and unsafe yaml.load"
    },
    {
        "ecosystem": "pypi",
        "package": "django",
        "vulnerable_below": "4.2.4",
        "cve": "CVE-2023-36053",
        "cvss": 7.5,
        "severity": "HIGH",
        "fixed": "4.2.4",
        "desc": "Django Potential Regular Expression Denial of Service (ReDoS) in EmailValidator"
    },
    {
        "ecosystem": "pypi",
        "package": "cryptography",
        "vulnerable_below": "41.0.6",
        "cve": "CVE-2023-49083",
        "cvss": 7.5,
        "severity": "HIGH",
        "fixed": "41.0.6",
        "desc": "cryptography NULL dereference when loading PKCS7 certificates"
    },
    {
        "ecosystem": "pypi",
        "package": "jinja2",
        "vulnerable_below": "3.1.3",
        "cve": "CVE-2024-22195",
        "cvss": 6.1,
        "severity": "MEDIUM",
        "fixed": "3.1.3",
        "desc": "Jinja2 HTML attribute injection flaw through xmlattr filter"
    },
    {
        "ecosystem": "npm",
        "package": "axios",
        "vulnerable_below": "1.6.0",
        "cve": "CVE-2023-45857",
        "cvss": 6.5,
        "severity": "MEDIUM",
        "fixed": "1.6.0",
        "desc": "Axios Cross-Site Request Forgery (CSRF) via unauthorized header exposure"
    },
    {
        "ecosystem": "npm",
        "package": "jsonwebtoken",
        "vulnerable_below": "9.0.0",
        "cve": "CVE-2022-23529",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "fixed": "9.0.0",
        "desc": "jsonwebtoken Remote Code Execution via insecure secret key algorithm verification"
    },
    {
        "ecosystem": "npm",
        "package": "express",
        "vulnerable_below": "4.19.2",
        "cve": "CVE-2024-29041",
        "cvss": 7.1,
        "severity": "HIGH",
        "fixed": "4.19.2",
        "desc": "Express Open Redirect via malformed path URL encoding"
    },
    {
        "ecosystem": "npm",
        "package": "lodash",
        "vulnerable_below": "4.17.21",
        "cve": "CVE-2020-8203",
        "cvss": 7.4,
        "severity": "HIGH",
        "fixed": "4.17.21",
        "desc": "Prototype Pollution in lodash via zipObjectDeep"
    },
    {
        "ecosystem": "maven",
        "package": "org.springframework.boot:spring-boot-starter-web",
        "vulnerable_below": "2.7.18",
        "cve": "CVE-2023-34055",
        "cvss": 7.5,
        "severity": "HIGH",
        "fixed": "2.7.18",
        "desc": "Spring Boot DoS via URL Path Parsing"
    },
    {
        "ecosystem": "maven",
        "package": "org.apache.logging.log4j:log4j-core",
        "vulnerable_below": "2.17.1",
        "cve": "CVE-2021-44228",
        "cvss": 10.0,
        "severity": "CRITICAL",
        "fixed": "2.17.1",
        "desc": "Log4Shell JNDI Remote Code Execution"
    }
]

def version_tuple(v: str) -> tuple:
    """Converts a semantic version string into a comparable tuple of integers."""
    clean = re.sub(r'[^0-9.]', '', v.split('-')[0].split('+')[0])
    parts = [int(p) if p.isdigit() else 0 for p in clean.split('.') if p]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])

class DependencyParser:

    @staticmethod
    def parse_manifest(file_path: str, content: str) -> List[Dict[str, Any]]:
        filename = os.path.basename(file_path).lower()
        if filename == "requirements.txt":
            return DependencyParser._parse_requirements_txt(file_path, content)
        elif filename == "package.json":
            return DependencyParser._parse_package_json(file_path, content)
        elif filename == "pyproject.toml":
            return DependencyParser._parse_pyproject_toml(file_path, content)
        elif filename == "pom.xml":
            return DependencyParser._parse_pom_xml(file_path, content)
        return []

    @staticmethod
    def _parse_requirements_txt(file_path: str, content: str) -> List[Dict[str, Any]]:
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            
            # e.g., flask==2.0.1 or requests>=2.25.0
            match = re.match(r'^([a-zA-Z0-9_\-\.]+)\s*([=><~^!]+)\s*([a-zA-Z0-9_\-\.]+)', line)
            if match:
                pkg, op, ver = match.groups()
                deps.append(DependencyParser._build_dep_info("pypi", pkg.lower(), ver, file_path, is_direct=True))
            else:
                pkg_match = re.match(r'^([a-zA-Z0-9_\-\.]+)', line)
                if pkg_match:
                    pkg = pkg_match.group(1).lower()
                    deps.append(DependencyParser._build_dep_info("pypi", pkg, "unknown", file_path, is_direct=True))
        return deps

    @staticmethod
    def _parse_package_json(file_path: str, content: str) -> List[Dict[str, Any]]:
        deps = []
        try:
            data = json.loads(content)
            for group, is_direct in [("dependencies", True), ("devDependencies", False)]:
                for pkg, ver_str in data.get(group, {}).items():
                    clean_ver = re.sub(r'[\^~>=<v]', '', ver_str).strip()
                    deps.append(DependencyParser._build_dep_info("npm", pkg.lower(), clean_ver, file_path, is_direct=is_direct))
        except Exception:
            pass
        return deps

    @staticmethod
    def _parse_pyproject_toml(file_path: str, content: str) -> List[Dict[str, Any]]:
        deps = []
        in_deps = False
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("[") and "dependencies" in line:
                in_deps = True
                continue
            if line.startswith("[") and in_deps:
                in_deps = False
                continue
            if in_deps and "=" in line:
                parts = line.split("=", 1)
                pkg = parts[0].strip().strip('"\'')
                ver = re.sub(r'[\^~>=<"\']', '', parts[1]).strip()
                deps.append(DependencyParser._build_dep_info("pypi", pkg.lower(), ver, file_path, is_direct=True))
        return deps

    @staticmethod
    def _parse_pom_xml(file_path: str, content: str) -> List[Dict[str, Any]]:
        deps = []
        try:
            root = ET.fromstring(content)
            # Find all <dependency> tags
            for dep in root.iter('{http://maven.apache.org/POM/4.0.0}dependency') or root.iter('dependency'):
                group_id = dep.find('{http://maven.apache.org/POM/4.0.0}groupId') or dep.find('groupId')
                artifact_id = dep.find('{http://maven.apache.org/POM/4.0.0}artifactId') or dep.find('artifactId')
                version = dep.find('{http://maven.apache.org/POM/4.0.0}version') or dep.find('version')
                if group_id is not None and artifact_id is not None:
                    pkg_name = f"{group_id.text.strip()}:{artifact_id.text.strip()}"
                    ver = version.text.strip() if version is not None and version.text else "unknown"
                    deps.append(DependencyParser._build_dep_info("maven", pkg_name, ver, file_path, is_direct=True))
        except Exception:
            pass
        return deps

    @staticmethod
    def _build_dep_info(ecosystem: str, package: str, version: str, manifest_path: str, is_direct: bool) -> Dict[str, Any]:
        dep_record = {
            "package_name": package,
            "installed_version": version,
            "ecosystem": ecosystem,
            "manifest_file": manifest_path,
            "is_direct": is_direct,
            "is_vulnerable": False,
            "cve_id": None,
            "cvss_score": None,
            "severity": None,
            "affected_versions": None,
            "fixed_version": None,
            "exposure_factor": 1.0,
            "risk_contribution": 0.0,
            "recommendation": f"Package {package}@{version} is up to date."
        }

        # Check vulnerability against known advisories
        for adv in KNOWN_VULNERABILITIES:
            if adv["ecosystem"] == ecosystem and adv["package"].lower() == package.lower():
                if version != "unknown":
                    if version_tuple(version) < version_tuple(adv["vulnerable_below"]):
                        dep_record["is_vulnerable"] = True
                        dep_record["cve_id"] = adv["cve"]
                        dep_record["cvss_score"] = adv["cvss"]
                        dep_record["severity"] = adv["severity"]
                        dep_record["affected_versions"] = f"<{adv['vulnerable_below']}"
                        dep_record["fixed_version"] = adv["fixed"]
                        dep_record["risk_contribution"] = round(adv["cvss"] * 1.0, 2)
                        dep_record["recommendation"] = f"Upgrade {package} to version {adv['fixed']} or higher to fix {adv['cve']} ({adv['desc']})."
                        break
        return dep_record
