#!/usr/bin/env python3
"""Lab L5: Hallucinated Package, Slopsquatting, and Pinning Verifier.

Parses a pip-style requirements file and checks every entry against a vetted
JSON allowlist registry. Rejects unknown names, unpinned versions, missing
SHA-256 hashes, and hash mismatches. Defensive offline check only.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

PIN_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)$")
NAME_RE = re.compile(r"^([A-Za-z0-9_.\-]+)")
HASH_RE = re.compile(r"--hash=sha256:([0-9a-fA-F]{64})")


def parse_logical_lines(req_path: Path) -> List[Tuple[int, str]]:
    """Collapse backslash line continuations and strip comments."""
    raw_lines = req_path.read_text(encoding="utf-8").splitlines()
    entries: List[Tuple[int, str]] = []
    buf = ""
    start_line = 0

    for idx, raw in enumerate(raw_lines, start=1):
        cleaned = raw.split("#", 1)[0].strip()
        if not cleaned:
            continue
        if not buf:
            start_line = idx
        if cleaned.endswith("\\"):
            buf += cleaned[:-1].strip() + " "
        else:
            buf += cleaned
            entries.append((start_line, buf.strip()))
            buf = ""
    if buf:
        entries.append((start_line, buf.strip()))
    return entries


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify package allowlist membership, exact pins, and SHA-256 hashes."
    )
    parser.add_argument("--requirements", required=True, help="Requirements file path.")
    parser.add_argument("--registry", required=True, help="Vetted JSON catalog path.")
    args = parser.parse_args()

    req_path = Path(args.requirements)
    reg_path = Path(args.registry)
    catalog: Dict[str, Dict[str, object]] = json.loads(
        reg_path.read_text(encoding="utf-8")
    ).get("packages", {})
    norm_catalog = {normalize_name(k): v for k, v in catalog.items()}

    started = time.monotonic()
    entries = parse_logical_lines(req_path)
    violations: List[str] = []
    verified = 0

    print(f"=== Lab L5 Dependency Pin & Allowlist Gate ({req_path}) ===")
    for line_no, entry in entries:
        hashes = [h.lower() for h in HASH_RE.findall(entry)]
        spec_part = HASH_RE.sub("", entry).strip()

        pin_match = PIN_RE.match(spec_part)
        elapsed = time.monotonic() - started
        if not pin_match:
            name_m = NAME_RE.match(spec_part)
            pkg_guess = name_m.group(1) if name_m else spec_part
            norm_guess = normalize_name(pkg_guess)
            if norm_guess not in norm_catalog:
                msg = (
                    f"[T+{elapsed:05.2f}s] REJECT L{line_no} {pkg_guess} "
                    "reason=UNKNOWN_HALLUCINATED_PKG"
                )
            else:
                msg = (
                    f"[T+{elapsed:05.2f}s] REJECT L{line_no} {pkg_guess} "
                    "reason=UNPINNED_VERSION"
                )
            print(msg)
            violations.append(msg)
            continue

        pkg_name, version = pin_match.group(1), pin_match.group(2)
        norm_pkg = normalize_name(pkg_name)
        meta = norm_catalog.get(norm_pkg)

        if meta is None:
            msg = (
                f"[T+{elapsed:05.2f}s] REJECT line={line_no} pkg={pkg_name}=={version} "
                "reason=UNKNOWN_OR_HALLUCINATED_PACKAGE"
            )
            print(msg)
            violations.append(msg)
            continue

        if str(meta.get("version")) != version:
            msg = (
                f"[T+{elapsed:05.2f}s] REJECT line={line_no} pkg={pkg_name}=={version} "
                f"reason=UNAPPROVED_VERSION expected={meta.get('version')}"
            )
            print(msg)
            violations.append(msg)
            continue

        expected_hash = str(meta.get("sha256", "")).lower()
        if not hashes:
            msg = (
                f"[T+{elapsed:05.2f}s] REJECT line={line_no} pkg={pkg_name}=={version} "
                "reason=MISSING_SHA256_HASH"
            )
            print(msg)
            violations.append(msg)
            continue

        if expected_hash not in hashes:
            msg = (
                f"[T+{elapsed:05.2f}s] REJECT line={line_no} pkg={pkg_name}=={version} "
                "reason=SHA256_MISMATCH"
            )
            print(msg)
            violations.append(msg)
            continue

        verified += 1
        print(
            f"[T+{elapsed:05.2f}s] ALLOW  L{line_no:02d} {pkg_name}=={version} "
            f"sha256={expected_hash[:12]}.. ({meta.get('provenance')})"
        )

    if violations:
        print(
            f"Result: REJECTED ({len(violations)} violation(s), {verified} verified; "
            "install blocked)"
        )
        return 1

    print(f"Result: PASSED ({verified}/{len(entries)} dependencies verified)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
