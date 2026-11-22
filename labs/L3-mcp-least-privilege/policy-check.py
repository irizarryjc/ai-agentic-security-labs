#!/usr/bin/env python3
"""Lab L3: Policy Verification Runner for MCP/Tool Least Privilege.

Evaluates tool-server.py under either overprivileged or least-privilege mode.
Returns exit code 0 only when all security assertions pass.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List


def load_tool_server_module(server_path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("tool_server", server_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load {server_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Lab L3 MCP security controls.")
    parser.add_argument(
        "--profile",
        choices=["overprivileged", "least-privilege"],
        default="least-privilege",
    )
    parser.add_argument(
        "--policy",
        default="policies/mcp-least-privilege.json",
        help="Path to least-privilege JSON policy.",
    )
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    mod = load_tool_server_module(script_dir / "tool-server.py")
    policy = json.loads(Path(args.policy).read_text(encoding="utf-8"))

    with tempfile.TemporaryDirectory(prefix="l3-ws-") as tmp:
        ws = Path(tmp)
        (ws / "docs").mkdir()
        (ws / "docs" / "guide.md").write_text("# Lab Guide\nSafe doc.\n", encoding="utf-8")
        (ws / "fake-secrets.env").write_text(
            "CANARY_SECRET_FAKE=not-a-real-secret\n", encoding="utf-8"
        )

        server = mod.ToolServer(args.profile, ws, policy)
        valid_token = {
            "audience": "mcp://lab-repo-tools",
            "passthrough": False,
            "ttl_seconds": 300,
            "scopes": ["repo:read", "repo:patch_proposal"],
        }
        foreign_token = {
            "audience": "https://downstream-api.example.invalid",
            "passthrough": True,
            "ttl_seconds": 3600,
            "scopes": ["repo:read"],
        }

        checks: List[Dict[str, Any]] = [
            {
                "id": "L3-CHK-01-SECRET-FILE",
                "req": {
                    "tool": "read_repo_file",
                    "args": {"path": "fake-secrets.env"},
                    "token": valid_token,
                },
                "expect": "DENY",
            },
            {
                "id": "L3-CHK-02-UNRESTRICTED-SHELL",
                "req": {
                    "tool": "run_shell",
                    "args": {"command": "id"},
                    "token": valid_token,
                },
                "expect": "DENY",
            },
            {
                "id": "L3-CHK-03-SSRF-METADATA",
                "req": {
                    "tool": "http_fetch",
                    "args": {"url": "http://169.254.169.254/latest/meta-data/"},
                    "token": valid_token,
                },
                "expect": "DENY",
            },
            {
                "id": "L3-CHK-04-TOKEN-PASSTHROUGH",
                "req": {
                    "tool": "read_repo_file",
                    "args": {"path": "docs/guide.md"},
                    "token": foreign_token,
                },
                "expect": "DENY",
            },
            {
                "id": "L3-CHK-05-ALLOWED-DOC-READ",
                "req": {
                    "tool": "read_repo_file",
                    "args": {"path": "docs/guide.md"},
                    "token": valid_token,
                },
                "expect": "ALLOW",
            },
            {
                "id": "L3-CHK-06-PATCH-NEEDS-APPROVAL",
                "req": {
                    "tool": "propose_patch",
                    "args": {"path": "docs/guide.md", "diff": "+note"},
                    "token": valid_token,
                },
                "expect": "ASK",
            },
        ]

        started = time.monotonic()
        failures = 0
        print(f"=== Lab L3 MCP Least-Privilege Check (profile={args.profile}) ===")

        pin_ok = server.verify_schema_pin(mod.TOOL_SCHEMAS)
        elapsed = time.monotonic() - started
        if args.profile == "least-privilege":
            pin_status = "PASS" if pin_ok else "FAIL"
            if not pin_ok:
                failures += 1
        else:
            pin_status = "FAIL"
            failures += 1
        print(
            f"[T+{elapsed:05.2f}s] L3-CHK-00-SCHEMA-PIN status={pin_status} "
            f"sha256_prefix={mod.compute_schema_sha256()[:12]}"
        )

        for item in checks:
            resp = server.handle_request(item["req"])
            actual = resp.get("decision", "ERROR")
            ok = actual == item["expect"]
            if not ok:
                failures += 1
            elapsed = time.monotonic() - started
            reason = resp.get("reason", resp.get("path", "ok"))
            print(
                f"[T+{elapsed:05.2f}s] {item['id']:28s} exp={item['expect']:5s} "
                f"got={actual:5s} {'PASS' if ok else 'FAIL'} ({reason})"
            )

    total = len(checks) + 1
    print(f"Result: {total - failures}/{total} security controls passed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
