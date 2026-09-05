#!/usr/bin/env python3
"""
Witch Hunter AST Security Scanner
Scans Python codebases for IDOR risks, shell injection, path traversal,
hardcoded credentials, and unsafe execution primitives.
Outputs findings directly to witch-report.json.
"""

import ast
import json
import re
import sys
from pathlib import Path

# High-entropy secret regex patterns
SECRET_PATTERNS = [
    (re.compile(r"eyJhbGciOiJ"), "JWT Token Leak"),
    (re.compile(r"sk_live_[0-9a-zA-Z]{24}"), "Stripe Live Secret Key"),
    (re.compile(r"ghp_[0-9a-zA-Z]{36}"), "GitHub Personal Access Token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS Access Key ID"),
]

class WitchHunterVisitor(ast.NodeVisitor):
    def __init__(self, filename):
        self.filename = str(filename)
        self.findings = []

    def add_finding(self, rule_id, severity, message, line_no):
        self.findings.append({
            "rule_id": rule_id,
            "severity": severity,
            "file": self.filename,
            "line": line_no,
            "message": message
        })

    def visit_Call(self, node):
        # WH-001: Shell Injection via subprocess(..., shell=True)
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("run", "Popen", "call", "check_output"):
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                for keyword in node.keywords:
                    if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        self.add_finding(
                            "WH-001", "HIGH",
                            f"subprocess.{node.func.attr}() executed with shell=True",
                            node.lineno
                        )

        # WH-002: Dynamic os.system or eval/exec execution
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            if node.func.value.id == "os" and node.func.attr == "system":
                self.add_finding("WH-002", "HIGH", "Use of os.system() command execution primitive", node.lineno)
        
        if isinstance(node.func, ast.Name) and node.func.id in ("eval", "exec"):
            self.add_finding("WH-002", "CRITICAL", f"Use of unsafe dynamic call '{node.func.id}()'", node.lineno)

        # WH-003: Unsanitized File Open (Path Traversal Risk)
        if isinstance(node.func, ast.Name) and node.func.id == "open":
            if node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
                self.add_finding(
                    "WH-003", "MEDIUM",
                    "Dynamic file path passed to open() without path resolution validation",
                    node.lineno
                )

        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        # WH-004: IDOR / Broken Object-Level Authorization Risk
        is_route = any(
            isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ("get", "post", "put", "delete", "patch")
            for d in node.decorator_list
        )
        if is_route:
            has_id_param = any("id" in arg.arg.lower() for arg in node.args.args)
            has_auth_dep = any(
                "auth" in arg.arg.lower() or "user" in arg.arg.lower() or "token" in arg.arg.lower()
                for arg in node.args.args
            )
            if has_id_param and not has_auth_dep:
                self.add_finding(
                    "WH-004", "HIGH",
                    f"Route handler '{node.name}' accepts resource ID parameter without explicit auth context dependency (IDOR risk)",
                    node.lineno
                )

        self.generic_visit(node)

    def visit_Assign(self, node):
        # WH-005: Hardcoded Credential / Secret Detection
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.upper()
                if any(k in var_name for k in ("SECRET", "API_KEY", "PASSWORD", "PRIVATE_KEY", "TOKEN")):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val = node.value.value
                        if len(val) > 4 and not val.startswith("ENV_") and not val.startswith("${"):
                            self.add_finding(
                                "WH-005", "HIGH",
                                f"Possible hardcoded secret in variable assignment '{target.id}'",
                                node.lineno
                            )
        self.generic_visit(node)


def scan_file(filepath):
    findings = []
    try:
        content = filepath.read_text(encoding="utf-8")
    except Exception:
        return findings

    # 1. Regex Secret Sweep
    for line_idx, line in enumerate(content.splitlines(), 1):
        for pattern, secret_type in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append({
                    "rule_id": "WH-005",
                    "severity": "CRITICAL",
                    "file": str(filepath),
                    "line": line_idx,
                    "message": f"Hardcoded credential detected: {secret_type}"
                })

    # 2. AST Parsing Sweep
    try:
        tree = ast.parse(content, filename=str(filepath))
        visitor = WitchHunterVisitor(filepath)
        visitor.visit(tree)
        findings.extend(visitor.findings)
    except SyntaxError:
        pass

    return findings


def main():
    root = Path(".")
    all_findings = []
    scanned_count = 0

    ignore_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__", "vendor"}

    for path in root.rglob("*.py"):
        if any(part in ignore_dirs for part in path.parts):
            continue
        scanned_count += 1
        all_findings.extend(scan_file(path))

    report = {
        "scanned_files": scanned_count,
        "vulnerabilities": all_findings
    }

    report_path = Path("witch-report.json")
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    high_or_crit = [f for f in all_findings if f["severity"] in ("HIGH", "CRITICAL")]
    
    print(f"=== Witch Hunter AST Scan Complete ===")
    print(f"Scanned files : {scanned_count}")
    print(f"Vulnerabilities: {len(all_findings)} (High/Critical: {len(high_or_crit)})")

    if high_or_crit:
        print("\n[FAIL] High-severity vulnerabilities detected:")
        for v in high_or_crit:
            print(f"  - [{v['rule_id']}] {v['file']}:{v['line']} -> {v['message']}")
        sys.exit(1)
    else:
        print("\n[PASS] No critical AST rule violations found.")
        sys.exit(0)


if __name__ == "__main__":
    main()
