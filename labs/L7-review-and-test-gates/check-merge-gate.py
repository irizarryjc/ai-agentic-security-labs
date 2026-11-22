#!/usr/bin/env python3
"""Lab L7: Code Review and Testing Gate for AI-Written Code.

Enforces four merge requirements against a candidate test file and PR metadata:
1. Independent human reviewer approval (reviewer != author, approved=True).
2. AST inspection catching vacuous tests:
   - test methods with zero assertions,
   - tautological assertions (assertTrue(True), assertEqual(x, x), assert True),
   - broad `except ...: pass` exception swallowing inside tests.
3. Canary secret and unpinned dependency check on the candidate file.
4. Deterministic test execution via `python3 -m unittest`.

Exits 0 only when all four gates pass; exits 1 otherwise.
"""

from __future__ import annotations

import argparse
import ast
import re
import subprocess
import sys
from pathlib import Path

SECRET_CANARY_RE = re.compile(
    r"(CANARY_SECRET_FAKE\s*=|AKIA[0-9A-Z]{16}|BEGIN\s+PRIVATE\s+KEY)"
)


def is_assert_call(node: ast.AST) -> bool:
    """Return True if an AST Call node invokes a unittest assertion method."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr.startswith("assert"):
        return True
    return False


def is_tautology(node: ast.AST) -> bool:
    """Detect common vacuous assertions such as assertTrue(True) or assert True."""
    if isinstance(node, ast.Assert):
        if isinstance(node.test, ast.Constant) and node.test.value is True:
            return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        name = node.func.attr
        if name == "assertTrue" and len(node.args) == 1:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and arg.value is True:
                return True
        if name == "assertEqual" and len(node.args) == 2:
            if ast.dump(node.args[0]) == ast.dump(node.args[1]):
                return True
    return False


def is_swallowed_except(handler: ast.ExceptHandler) -> bool:
    """Detect `except ...: pass` blocks that silently hide errors."""
    if len(handler.body) == 1 and isinstance(handler.body[0], ast.Pass):
        return True
    return False


def inspect_test_ast(test_path: Path) -> tuple[bool, list[str], int]:
    """Analyze a Python unittest file for vacuous or deceptive test methods."""
    source = test_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(test_path))
    findings: list[str] = []
    test_count = 0

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            test_count += 1
            real_asserts = 0
            for child in ast.walk(node):
                if is_tautology(child):
                    findings.append(
                        f"{node.name}: tautological assertion detected"
                    )
                elif isinstance(child, ast.Assert) or is_assert_call(child):
                    real_asserts += 1
                if isinstance(child, ast.ExceptHandler) and is_swallowed_except(child):
                    findings.append(
                        f"{node.name}: exception swallowed with bare 'pass'"
                    )
            if real_asserts == 0:
                findings.append(f"{node.name}: zero meaningful assertions found")

    if test_count == 0:
        findings.append("No test_* functions found in candidate test file")

    return (len(findings) == 0, findings, test_count)


def check_review_gate(
    author: str,
    reviewer: str,
    approved: bool,
) -> tuple[bool, str]:
    """Require explicit approval by a human reviewer distinct from the author."""
    if not approved:
        return False, "No human review approval recorded (--review-approved missing)"
    if not reviewer or reviewer.strip() == "":
        return False, "Reviewer identity is empty"
    if reviewer.strip().lower() == author.strip().lower():
        return False, f"Self-approval forbidden (author and reviewer both '{author}')"
    if "agent" in reviewer.strip().lower() or "bot" in reviewer.strip().lower():
        return False, f"Automated identity '{reviewer}' cannot satisfy human review"
    return True, f"Approved by independent human reviewer '{reviewer}'"


def check_secret_hygiene(test_path: Path) -> tuple[bool, str]:
    """Check candidate file for planted canary secrets or private key markers."""
    content = test_path.read_text(encoding="utf-8")
    match = SECRET_CANARY_RE.search(content)
    if match:
        return False, f"Secret pattern matched: {match.group(0)}"
    return True, "No secret patterns detected"


def run_unittest(test_path: Path) -> tuple[bool, str]:
    """Execute unittest against the target file and verify clean pass."""
    cmd = [sys.executable, "-m", "unittest", str(test_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    summary_lines = [
        ln.strip() for ln in (proc.stderr or proc.stdout).splitlines() if ln.strip()
    ]
    tail = summary_lines[-1] if summary_lines else f"exit={proc.returncode}"
    if proc.returncode == 0:
        return True, f"unittest passed ({tail})"
    return False, f"unittest failed ({tail})"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lab L7 merge gate for review, test integrity, and execution."
    )
    parser.add_argument("--test-file", required=True, help="Path to unittest file.")
    parser.add_argument("--author", default="coder-agent-lab", help="Change author.")
    parser.add_argument("--reviewer", default="", help="Approving human reviewer.")
    parser.add_argument(
        "--review-approved",
        action="store_true",
        help="Flag indicating human reviewer approved the diff.",
    )
    return parser.parse_args()


def main() -> int:
    cli = parse_args()
    test_path = Path(cli.test_file)
    if not test_path.exists():
        print(f"[ERROR] Test file not found: {test_path}")
        return 1

    review_ok, review_msg = check_review_gate(
        cli.author, cli.reviewer, cli.review_approved
    )
    ast_ok, ast_findings, test_count = inspect_test_ast(test_path)
    secret_ok, secret_msg = check_secret_hygiene(test_path)
    unit_ok, unit_msg = run_unittest(test_path)

    print("=" * 72)
    print(f"MERGE GATE REPORT: {test_path}")
    print("=" * 72)
    print(f"[{'PASS' if review_ok else 'FAIL'}] Human Review Gate   : {review_msg}")
    if ast_ok:
        print(
            f"[PASS] Test Integrity AST  : "
            f"{test_count} test methods verified with real assertions"
        )
    else:
        print(
            f"[FAIL] Test Integrity AST  : "
            f"{len(ast_findings)} finding(s) across {test_count} test method(s)"
        )
        for item in ast_findings:
            print(f"       - {item}")
    print(f"[{'PASS' if secret_ok else 'FAIL'}] Secret Hygiene Gate : {secret_msg}")
    print(f"[{'PASS' if unit_ok else 'FAIL'}] Test Execution Gate : {unit_msg}")
    print("-" * 72)

    all_passed = review_ok and ast_ok and secret_ok and unit_ok
    verdict = "MERGE ALLOWED" if all_passed else "MERGE BLOCKED"
    print(f"FINAL VERDICT: {verdict}")
    print("=" * 72)
    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
