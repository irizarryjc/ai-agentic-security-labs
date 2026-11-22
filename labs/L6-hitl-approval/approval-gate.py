#!/usr/bin/env python3
"""Lab L6: Human-in-the-Loop (HITL) Approval Gate for High-Impact Tool Calls.

Defensive lab helper demonstrating:
1. Authoritative rendering of full tool name, exact paths, and raw arguments
   (strictly separated from untrusted model-authored rationale text).
2. SHA-256 digest + single-use nonce binding between approval and execution.
3. Rejection of post-approval argument tampering, nonce replay, and blanket
   auto-approval on high-impact operations.
4. Append-only JSONL audit logging of every approval and denial.

Run only inside an isolated lab environment with no production credentials.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import sys
from pathlib import Path
from typing import Any

HIGH_IMPACT_TOOLS = frozenset(
    {
        "bulk_file_delete",
        "delete_directory",
        "drop_table_draft",
        "force_push_branch",
        "modify_iam_policy",
    }
)

READ_ONLY_TOOLS = frozenset({"git_status", "list_dir", "read_file"})


def canonical_payload(
    session_id: str,
    nonce: str,
    tool: str,
    args: dict[str, Any],
) -> bytes:
    """Serialize executable action fields deterministically for hashing."""
    body = {
        "args": args,
        "nonce": nonce,
        "session_id": session_id,
        "tool": tool,
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_digest(
    session_id: str,
    nonce: str,
    tool: str,
    args: dict[str, Any],
) -> str:
    """Compute SHA-256 digest bound to exact tool, arguments, session, and nonce."""
    raw = canonical_payload(session_id, nonce, tool, args)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def sign_approval(secret_key: bytes, action_digest: str, operator: str) -> str:
    """Bind human approval token to the exact action digest and operator."""
    msg = f"{action_digest}|{operator}".encode("utf-8")
    return hmac.new(secret_key, msg, hashlib.sha256).hexdigest()


def dry_run_preview(tool: str, args: dict[str, Any]) -> str:
    """Return a deterministic preview of what the tool call would affect."""
    target = str(args.get("target", "<unspecified>"))
    recursive = bool(args.get("recursive", False))
    target_path = Path(target)
    if target_path.exists() and target_path.is_dir():
        count = sum(1 for _ in target_path.rglob("*"))
        return f"DRY-RUN: directory '{target}' exists ({count} nested entries)"
    if target_path.exists():
        size = target_path.stat().st_size
        return f"DRY-RUN: file '{target}' exists ({size} bytes)"
    mode = "recursive" if recursive else "single-target"
    return f"DRY-RUN: {tool} ({mode}) targeting '{target}' (simulated lab target)"


def next_seq(log_path: Path) -> int:
    """Determine next sequence number in the JSONL audit log."""
    if not log_path.exists():
        return 1
    lines = [ln for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    return len(lines) + 1


def append_audit_event(log_path: Path, event: dict[str, Any]) -> None:
    """Append a single structured JSONL event to the local audit log."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def render_approval_prompt(
    session_id: str,
    nonce: str,
    tool: str,
    args: dict[str, Any],
    rationale: str,
    digest: str,
) -> None:
    """Display raw executable arguments separately from untrusted rationale."""
    print("=" * 72)
    print("HUMAN-IN-THE-LOOP APPROVAL REQUIRED (HIGH-IMPACT ACTION)")
    print("=" * 72)
    print(f"Session ID   : {session_id}")
    print(f"Nonce        : {nonce}")
    print(f"Action Digest: {digest}")
    print("-" * 72)
    print("EXACT EXECUTABLE PAYLOAD (AUTHORITATIVE - VERIFY THIS):")
    print(f"  tool : {tool}")
    print(f"  args : {json.dumps(args, sort_keys=True)}")
    print(f"  {dry_run_preview(tool, args)}")
    print("-" * 72)
    print("AGENT RATIONALE (UNTRUSTED MODEL TEXT - DO NOT APPROVE FROM THIS):")
    print(f"  {rationale}")
    print("=" * 72)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lab L6 HITL approval gate for high-impact agent tool calls."
    )
    parser.add_argument("--tool", required=True, help="Tool name requested by agent.")
    parser.add_argument("--target", required=True, help="Target path or resource.")
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Whether the requested action is recursive.",
    )
    parser.add_argument(
        "--rationale",
        default="Cleaning up temporary workspace files.",
        help="Untrusted summary provided by the agent.",
    )
    parser.add_argument(
        "--operator",
        default=os.environ.get("LAB_OPERATOR", "labuser"),
        help="Approving human operator identity.",
    )
    parser.add_argument(
        "--agent-id",
        default="coder-agent-lab",
        help="Requesting agent identity.",
    )
    parser.add_argument(
        "--session-id",
        default="sess-l6-demo",
        help="Correlation session identifier.",
    )
    parser.add_argument(
        "--decision",
        choices=("interactive", "approve", "deny"),
        default="interactive",
        help="Human decision mode (use approve/deny for deterministic lab tests).",
    )
    parser.add_argument(
        "--auto-approve-all",
        action="store_true",
        help="Attempt blanket auto-approval (must be rejected on high-impact tools).",
    )
    parser.add_argument(
        "--simulate-tamper",
        default="",
        help="After approval, swap target to this path to verify digest binding.",
    )
    parser.add_argument(
        "--simulate-replay",
        action="store_true",
        help="Attempt to execute twice using the same approval nonce.",
    )
    parser.add_argument(
        "--audit-log",
        default="hitl-audit.jsonl",
        help="Path to append JSONL approval/denial records.",
    )
    return parser.parse_args()


def main() -> int:
    cli = parse_args()
    log_path = Path(cli.audit_log)
    seq = next_seq(log_path)
    ts_rel = f"T+{(seq - 1) * 5:02d}s"
    requested_args: dict[str, Any] = {
        "recursive": cli.recursive,
        "target": cli.target,
    }
    nonce = secrets.token_hex(8)
    digest = compute_digest(cli.session_id, nonce, cli.tool, requested_args)
    ephemeral_key = secrets.token_bytes(32)
    consumed_nonces: set[str] = set()

    if cli.tool in READ_ONLY_TOOLS:
        event = {
            "action_digest": digest,
            "agent_id": cli.agent_id,
            "decision": "ALLOW_POLICY",
            "operator": cli.operator,
            "outcome": "EXECUTED_READ_ONLY",
            "reason": "Low-impact read-only tool allowed without HITL prompt",
            "seq": seq,
            "session_id": cli.session_id,
            "target": cli.target,
            "tool": cli.tool,
            "ts_rel": ts_rel,
        }
        append_audit_event(log_path, event)
        print(f"[ALLOW] {cli.tool} on '{cli.target}' (read-only; logged seq={seq})")
        return 0

    if cli.tool not in HIGH_IMPACT_TOOLS:
        event = {
            "action_digest": digest,
            "agent_id": cli.agent_id,
            "decision": "DENY_UNKNOWN_TOOL",
            "operator": cli.operator,
            "outcome": "BLOCKED",
            "reason": "Tool not in allowlist; deny by default",
            "seq": seq,
            "session_id": cli.session_id,
            "target": cli.target,
            "tool": cli.tool,
            "ts_rel": ts_rel,
        }
        append_audit_event(log_path, event)
        print(f"[DENY] Unknown tool '{cli.tool}' blocked by default-deny policy.")
        return 1

    if cli.auto_approve_all:
        event = {
            "action_digest": digest,
            "agent_id": cli.agent_id,
            "decision": "DENY_AUTO_APPROVE_FORBIDDEN",
            "operator": cli.operator,
            "outcome": "BLOCKED",
            "reason": "Blanket auto-approve is forbidden for high-impact tools",
            "seq": seq,
            "session_id": cli.session_id,
            "target": cli.target,
            "tool": cli.tool,
            "ts_rel": ts_rel,
        }
        append_audit_event(log_path, event)
        print(
            "[DENY] Blanket --auto-approve-all rejected for high-impact tool "
            f"'{cli.tool}'."
        )
        return 1

    render_approval_prompt(
        cli.session_id, nonce, cli.tool, requested_args, cli.rationale, digest
    )

    if cli.decision == "interactive":
        prefix = digest[7:19]
        prompt = f"Type digest prefix ({prefix}) to approve, or 'n': "
        answer = input(prompt).strip()
        approved = answer == prefix
    else:
        approved = cli.decision == "approve"
        print(f"Operator decision ({cli.operator}): {cli.decision.upper()}")

    if not approved:
        event = {
            "action_digest": digest,
            "agent_id": cli.agent_id,
            "decision": "DENY_HUMAN",
            "operator": cli.operator,
            "outcome": "BLOCKED",
            "reason": "Human operator denied high-impact tool call",
            "seq": seq,
            "session_id": cli.session_id,
            "target": cli.target,
            "tool": cli.tool,
            "ts_rel": ts_rel,
        }
        append_audit_event(log_path, event)
        print(f"[DENY] Execution blocked by operator '{cli.operator}'. Logged seq={seq}.")
        return 1

    approval_sig = sign_approval(ephemeral_key, digest, cli.operator)

    exec_args = dict(requested_args)
    if cli.simulate_tamper:
        exec_args["target"] = cli.simulate_tamper
        print(
            "[TEST] Simulating post-approval argument swap -> "
            f"target='{cli.simulate_tamper}'"
        )

    exec_digest = compute_digest(cli.session_id, nonce, cli.tool, exec_args)
    expected_sig = sign_approval(ephemeral_key, exec_digest, cli.operator)

    if not hmac.compare_digest(approval_sig, expected_sig):
        event = {
            "action_digest": exec_digest,
            "agent_id": cli.agent_id,
            "approved_digest": digest,
            "decision": "DENY_DIGEST_MISMATCH",
            "operator": cli.operator,
            "outcome": "BLOCKED",
            "reason": "Execution payload digest did not match approved digest",
            "seq": seq,
            "session_id": cli.session_id,
            "target": exec_args["target"],
            "tool": cli.tool,
            "ts_rel": ts_rel,
        }
        append_audit_event(log_path, event)
        print(
            "[DENY] Digest mismatch detected! Approved payload does not match "
            "execution payload."
        )
        print(f"  approved : {digest}")
        print(f"  received : {exec_digest}")
        return 2

    consumed_nonces.add(nonce)
    event = {
        "action_digest": exec_digest,
        "agent_id": cli.agent_id,
        "decision": "APPROVE_HUMAN",
        "operator": cli.operator,
        "outcome": "SIMULATED_EXECUTION_OK",
        "reason": "Verified digest and single-use nonce matched operator approval",
        "seq": seq,
        "session_id": cli.session_id,
        "target": exec_args["target"],
        "tool": cli.tool,
        "ts_rel": ts_rel,
    }
    append_audit_event(log_path, event)
    print(
        f"[ALLOW] Bound approval verified for {cli.tool} on '{exec_args['target']}' "
        f"(simulated execution; logged seq={seq})."
    )

    if cli.simulate_replay:
        print("[TEST] Simulating approval replay with already-consumed nonce...")
        if nonce in consumed_nonces:
            replay_seq = next_seq(log_path)
            replay_event = {
                "action_digest": exec_digest,
                "agent_id": cli.agent_id,
                "decision": "DENY_NONCE_REPLAY",
                "operator": cli.operator,
                "outcome": "BLOCKED",
                "reason": "Approval nonce was already consumed",
                "seq": replay_seq,
                "session_id": cli.session_id,
                "target": exec_args["target"],
                "tool": cli.tool,
                "ts_rel": f"T+{(replay_seq - 1) * 5:02d}s",
            }
            append_audit_event(log_path, replay_event)
            print("[DENY] Replay blocked: single-use approval nonce already consumed.")
            return 3

    return 0


if __name__ == "__main__":
    sys.exit(main())
