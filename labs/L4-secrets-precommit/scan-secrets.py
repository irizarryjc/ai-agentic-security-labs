#!/usr/bin/env python3
"""Lab L4: Defensive Pre-Commit and CI Secret Scanner.

Scans target files for forbidden credential filenames and secret-like patterns.
Matched values are always redacted in output so secrets never leak into logs.
Returns exit code 0 if clean, 1 if findings are detected.
"""

from __future__ import annotations

import argparse
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Pattern, Tuple

FORBIDDEN_FILENAMES = {
    ".env",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "credentials.json",
}

FORBIDDEN_SUFFIXES = (".env", ".pem", ".key", ".p12")

SECRET_PATTERNS: List[Tuple[str, Pattern[str]]] = [
    (
        "CANARY_SECRET_MARKER",
        re.compile(r"(CANARY_SECRET_FAKE|LAB_CANARY_TOKEN|FAKE_LAB_DB_PASSWORD)\S*"),
    ),
    (
        "PRIVATE_KEY_HEADER",
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    ),
    (
        "CLOUD_ACCESS_KEY_ID",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    (
        "CREDENTIAL_URL",
        re.compile(r"(postgresql|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@"),
    ),
    (
        "GENERIC_SECRET_ASSIGNMENT",
        re.compile(
            r"(?i)\b[A-Z0-9_]*(API_TOKEN|API_KEY|SIGNING_SECRET|DB_PASS(?:WORD)?|"
            r"SECRET_KEY)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{12,})['\"]?"
        ),
    ),
]

SAFE_PLACEHOLDERS = {
    "<token>",
    "REDACTED",
    "CHANGE_ME",
    "REPLACE_WITH_VAULT_REF",
}


def scan_file(path: Path) -> List[Dict[str, object]]:
    """Return a list of redacted findings for one file."""
    findings: List[Dict[str, object]] = []
    name = path.name.lower()

    if name in FORBIDDEN_FILENAMES or any(name.endswith(s) for s in FORBIDDEN_SUFFIXES):
        findings.append(
            {
                "file": str(path),
                "line": 0,
                "rule": "FORBIDDEN_CREDENTIAL_FILENAME",
                "match": f"<REDACTED_FILE:{path.name}>",
            }
        )

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        findings.append(
            {
                "file": str(path),
                "line": 0,
                "rule": "UNREADABLE_FILE",
                "match": str(exc),
            }
        )
        return findings

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for rule_name, pattern in SECRET_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            token_val = match.group(match.lastindex or 0)
            if token_val in SAFE_PLACEHOLDERS:
                continue
            findings.append(
                {
                    "file": str(path),
                    "line": line_no,
                    "rule": rule_name,
                    "match": f"<REDACTED:len={len(match.group(0))}>",
                }
            )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan files for synthetic canary secrets and credential patterns."
    )
    parser.add_argument("paths", nargs="+", help="One or more file paths to scan.")
    args = parser.parse_args()

    started = time.monotonic()
    all_findings: List[Dict[str, object]] = []
    scanned = 0

    print("=== Lab L4 Secret Scanner ===")
    for raw in args.paths:
        target = Path(raw)
        if not target.is_file():
            print(f"[SKIP] Not a regular file: {raw}")
            continue
        scanned += 1
        all_findings.extend(scan_file(target))

    elapsed = time.monotonic() - started
    for item in all_findings:
        print(
            f"[T+{elapsed:05.2f}s] BLOCK {item['file']}:{item['line']} "
            f"rule={item['rule']}"
        )
        print(f"           redacted={item['match']}")

    if all_findings:
        print(
            f"Result: FAILED ({len(all_findings)} findings across {scanned} file(s); "
            "commit blocked)"
        )
        return 1

    print(f"Result: PASSED (0 findings across {scanned} file(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
