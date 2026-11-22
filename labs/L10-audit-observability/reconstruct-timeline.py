#!/usr/bin/env python3
"""Lab L10: Audit-Log Reconstruction and Hash-Chain Verifier.

Reconstructs an agent tool-call sequence from a hash-chained JSONL audit log:
1. Verifies SHA-256 hash-chain continuity across all records (`prev_hash` -> `entry_hash`).
2. Scans redacted arguments for accidental secret or PII leakage patterns.
3. Correlates HITL approval prompts (`ASK_HITL`) with human decisions via `action_digest`.
4. Prints a forensic timeline table and summary metrics suitable for Appendix A.

Exit codes:
  0 - Log parsed, hash chain valid, and redaction hygiene clean.
  1 - CLI or file error, or unredacted secret/PII leakage found.
  2 - Hash-chain tamper or sequence break detected.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64

LEAK_PATTERNS = (
    ("canary_secret", re.compile(r"CANARY_SECRET_FAKE|not-a-real-secret")),
    ("email_pii", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("ssn_pattern", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("private_key", re.compile(r"BEGIN\s+PRIVATE\s+KEY")),
)


def compute_entry_hash(record: dict[str, Any]) -> str:
    """Compute canonical SHA-256 hash of an audit record excluding `entry_hash`."""
    body = {k: v for k, v in record.items() if k != "entry_hash"}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def load_records(log_path: Path) -> list[dict[str, Any]]:
    """Read non-empty JSONL lines from disk."""
    records: list[dict[str, Any]] = []
    for lineno, raw_line in enumerate(
        log_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON at line {lineno}: {exc}") from exc
    return records


def verify_chain(records: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    """Verify hash-chain links and monotonic sequence numbers."""
    errors: list[str] = []
    expected_prev = GENESIS_HASH

    for idx, rec in enumerate(records, start=1):
        seq = rec.get("seq")
        if seq != idx:
            errors.append(f"Sequence gap at line {idx}: found seq={seq}")

        prev_hash = rec.get("prev_hash", "")
        if prev_hash != expected_prev:
            errors.append(
                f"Chain link broken at seq={seq}: prev_hash does not match prior entry"
            )

        actual_hash = compute_entry_hash(rec)
        stored_hash = rec.get("entry_hash", "")
        if actual_hash != stored_hash:
            errors.append(
                f"Tampering detected at seq={seq}: stored hash differs from recomputed hash"
            )

        expected_prev = stored_hash

    return (len(errors) == 0, errors)


def check_redaction_hygiene(records: list[dict[str, Any]]) -> list[str]:
    """Scan serialized audit records for unredacted secret or PII patterns."""
    findings: list[str] = []
    for rec in records:
        seq = rec.get("seq", "?")
        serialized = json.dumps(rec.get("args_redacted", {}), sort_keys=True)
        for label, pattern in LEAK_PATTERNS:
            if pattern.search(serialized):
                findings.append(f"seq={seq}: unredacted {label} pattern in args_redacted")
    return findings


def correlate_hitl(records: list[dict[str, Any]]) -> list[str]:
    """Match ASK_HITL requests with their bound human decisions by action_digest."""
    prompts: dict[str, int] = {}
    notes: list[str] = []
    for rec in records:
        digest = str(rec.get("action_digest", ""))
        decision = str(rec.get("decision", ""))
        seq = int(rec.get("seq", 0))
        if decision == "ASK_HITL" and digest:
            prompts[digest] = seq
        elif decision in ("APPROVE_HUMAN", "DENY_HUMAN") and digest:
            origin = prompts.get(digest)
            if origin is not None:
                notes.append(
                    f"seq {origin} (ASK_HITL) -> seq {seq} "
                    f"({decision} by {rec.get('approver')}) "
                    f"digest={digest[:19]}..."
                )
            else:
                notes.append(
                    f"Unmatched HITL decision at seq {seq} for digest={digest[:19]}..."
                )
    return notes


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Reconstruct timeline and verify hash chain of JSONL audit logs."
    )
    parser.add_argument(
        "--log",
        default="labs/L10-audit-observability/sample-audit.jsonl",
        help="Path to JSONL audit log file.",
    )
    parser.add_argument(
        "--session",
        default="",
        help="Optional session_id filter for timeline display.",
    )
    parser.add_argument(
        "--decision",
        default="",
        help="Optional decision prefix filter (e.g., DENY).",
    )
    return parser.parse_args()


def main() -> int:
    cli = parse_args()
    log_path = Path(cli.log)
    if not log_path.exists():
        print(f"[ERROR] Audit log not found: {log_path}")
        return 1

    try:
        records = load_records(log_path)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        return 1

    if not records:
        print(f"[ERROR] Audit log is empty (0 records): {log_path}")
        return 1

    chain_ok, chain_errors = verify_chain(records)
    leak_findings = check_redaction_hygiene(records)
    hitl_notes = correlate_hitl(records)

    filtered = records
    if cli.session:
        filtered = [r for r in filtered if r.get("session_id") == cli.session]
    if cli.decision:
        pref = cli.decision.upper()
        filtered = [
            r
            for r in filtered
            if str(r.get("decision", "")).upper().startswith(pref)
        ]

    print("=" * 84)
    print(f"AUDIT TIMELINE RECONSTRUCTION: {log_path}")
    print("=" * 84)
    header = (
        f"{'Seq':<4} {'RelT':<6} {'Actor/Agent':<16} {'Tool':<15} "
        f"{'Decision':<13} {'Outcome':<18}"
    )
    print(header)
    print("-" * 84)

    for rec in filtered:
        actor = (
            rec.get("approver")
            if rec.get("tool") == "hitl_decision"
            else rec.get("agent_id")
        )
        print(
            f"{str(rec.get('seq', '')):<4} "
            f"{str(rec.get('ts_rel', '')):<6} "
            f"{str(actor):<16} "
            f"{str(rec.get('tool', '')):<15} "
            f"{str(rec.get('decision', '')):<13} "
            f"{str(rec.get('outcome', '')):<18}"
        )

    print("-" * 84)
    decisions: dict[str, int] = {}
    for rec in records:
        dec = str(rec.get("decision", "UNKNOWN"))
        decisions[dec] = decisions.get(dec, 0) + 1

    print(f"TOTAL RECORDS   : {len(records)} (displayed: {len(filtered)})")
    dec_summary = ", ".join(f"{k}={v}" for k, v in sorted(decisions.items()))
    print(f"DECISION COUNTS : {dec_summary}")
    chain_label = (
        f"VALID ({len(records)}/{len(records)} entries verified)"
        if chain_ok
        else f"BROKEN ({len(chain_errors)} error(s))"
    )
    print(f"HASH CHAIN      : {chain_label}")
    for err in chain_errors:
        print(f"  [CHAIN-ERROR] {err}")

    redaction_label = (
        "CLEAN (0 secret/PII leaks found)"
        if not leak_findings
        else f"VIOLATION ({len(leak_findings)} finding(s))"
    )
    print(f"REDACTION CHECK : {redaction_label}")
    for leak in leak_findings:
        print(f"  [LEAK-ALERT] {leak}")

    for note in hitl_notes:
        print(f"HITL TRACE      : {note}")
    print("=" * 84)

    if not chain_ok:
        return 2
    if leak_findings:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
