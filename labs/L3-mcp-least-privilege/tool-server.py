#!/usr/bin/env python3
"""Lab L3: Local MCP-Style Tool Server (Overprivileged vs. Least-Privilege).

Demonstrates deny-by-default tool authorization, canonical path containment,
schema SHA-256 pinning, SSRF destination checks, and token audience validation
(blocking token passthrough). Defensive lab only.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import ipaddress
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urlparse

TOOL_SCHEMAS: List[Dict[str, Any]] = [
    {
        "name": "read_repo_file",
        "description": "Read a UTF-8 file inside allowed workspace subdirectories.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
    },
    {
        "name": "list_repo_files",
        "description": "List relative files inside allowed workspace subdirectories.",
        "inputSchema": {
            "type": "object",
            "properties": {"subdir": {"type": "string"}},
            "required": ["subdir"],
        },
    },
    {
        "name": "propose_patch",
        "description": "Propose a unified diff; requires human approval.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string"},
                "diff": {"type": "string"},
            },
            "required": ["path", "diff"],
        },
    },
]


def compute_schema_sha256(schemas: List[Dict[str, Any]] | None = None) -> str:
    """Return canonical SHA-256 digest of the reviewed tool schema set."""
    payload = json.dumps(
        schemas if schemas is not None else TOOL_SCHEMAS,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def is_private_or_metadata_url(url: str) -> bool:
    """Block loopback, RFC1918, and link-local cloud metadata endpoints."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").strip().lower()
    if host in ("", "localhost") or host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return False


def matches_denied_glob(rel_path: str, denied_globs: List[str]) -> bool:
    """Check whether a normalized path or basename matches a denied glob."""
    norm = rel_path.replace("\\", "/").lstrip("/")
    name = os.path.basename(norm)
    for pattern in denied_globs:
        if fnmatch.fnmatch(norm, pattern) or fnmatch.fnmatch(name, pattern):
            return True
    return False


class ToolServer:
    """Minimal JSON-RPC-like dispatcher for Lab L3."""

    def __init__(
        self,
        profile: str,
        workspace: Path,
        policy: Dict[str, Any] | None = None,
    ) -> None:
        self.profile = profile
        self.workspace = workspace.resolve()
        self.policy = policy or {}

    def verify_schema_pin(self, active_schemas: List[Dict[str, Any]]) -> bool:
        expected = self.policy.get("server", {}).get("schema_sha256", "")
        return bool(expected) and compute_schema_sha256(active_schemas) == expected

    def handle_request(self, req: Dict[str, Any]) -> Dict[str, Any]:
        tool = str(req.get("tool", ""))
        args = req.get("args", {}) or {}
        token = req.get("token", {}) or {}

        if self.profile == "overprivileged":
            return self._handle_overprivileged(tool, args)
        return self._handle_least_privilege(tool, args, token)

    def _handle_overprivileged(
        self, tool: str, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Intentionally insecure baseline showing inherited client privileges."""
        if tool == "read_repo_file":
            target = (self.workspace / str(args.get("path", ""))).resolve()
            if target.is_file():
                text = target.read_text(encoding="utf-8")[:120]
                return {"decision": "ALLOW", "tool": tool, "preview": f"len={len(text)}"}
            return {"decision": "ERROR", "tool": tool, "reason": "not_found"}
        if tool == "run_shell":
            cmd = str(args.get("command", ""))
            return {"decision": "ALLOW", "tool": tool, "simulated_exec": cmd}
        if tool == "http_fetch":
            url = str(args.get("url", ""))
            return {"decision": "ALLOW", "tool": tool, "simulated_fetch": url}
        if tool == "propose_patch":
            return {"decision": "ALLOW", "tool": tool, "auto_applied": True}
        return {"decision": "DENY", "tool": tool, "reason": "unknown_tool"}

    def _handle_least_privilege(
        self, tool: str, args: Dict[str, Any], token: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Enforce deny-by-default policy, audience binding, and path confinement."""
        server_cfg = self.policy.get("server", {})
        expected_aud = server_cfg.get("expected_token_audience", "")
        if token.get("audience") != expected_aud or token.get("passthrough", False):
            return {
                "decision": "DENY",
                "tool": tool,
                "reason": "token_audience_mismatch",
            }
        max_ttl = int(server_cfg.get("credential_ttl_seconds", 300))
        if int(token.get("ttl_seconds", max_ttl + 1)) > max_ttl:
            return {"decision": "DENY", "tool": tool, "reason": "token_ttl_exceeded"}

        tool_cfg = self.policy.get("tools", {}).get(tool)
        if not tool_cfg:
            return {"decision": "DENY", "tool": tool, "reason": "default_deny_unlisted"}

        decision = str(tool_cfg.get("decision", "deny")).lower()
        if decision == "deny":
            return {"decision": "DENY", "tool": tool, "reason": "policy_explicit_deny"}

        req_scope = str(tool_cfg.get("required_scope", ""))
        token_scopes = set(token.get("scopes", []))
        if req_scope and req_scope not in token_scopes:
            return {"decision": "DENY", "tool": tool, "reason": "missing_required_scope"}

        if tool == "propose_patch" or decision == "ask":
            return {
                "decision": "ASK",
                "tool": tool,
                "reason": "APPROVAL_REQUIRED",
                "args_preview": sorted(args.keys()),
            }

        if tool == "http_fetch":
            url = str(args.get("url", ""))
            if is_private_or_metadata_url(url):
                return {"decision": "DENY", "tool": tool, "reason": "ssrf_blocked"}

        if tool == "read_repo_file":
            return self._read_confined_file(str(args.get("path", "")))

        return {"decision": "DENY", "tool": tool, "reason": "unhandled_tool"}

    def _read_confined_file(self, rel_path: str) -> Dict[str, Any]:
        fs_cfg = self.policy.get("filesystem", {})
        denied_globs = fs_cfg.get("denied_globs", [])
        allowed_subdirs = fs_cfg.get("allowed_subdirs", [])

        if matches_denied_glob(rel_path, denied_globs):
            return {"decision": "DENY", "tool": "read_repo_file", "reason": "denied_glob"}

        resolved = (self.workspace / rel_path).resolve()
        try:
            rel_to_ws = resolved.relative_to(self.workspace)
        except ValueError:
            return {
                "decision": "DENY",
                "tool": "read_repo_file",
                "reason": "path_traversal_blocked",
            }

        parts = rel_to_ws.parts
        if not parts or parts[0] not in allowed_subdirs:
            return {
                "decision": "DENY",
                "tool": "read_repo_file",
                "reason": "outside_allowed_subdirs",
            }
        if not resolved.is_file():
            return {"decision": "ERROR", "tool": "read_repo_file", "reason": "not_found"}

        max_bytes = int(fs_cfg.get("max_read_bytes", 65536))
        content = resolved.read_bytes()[:max_bytes].decode("utf-8", errors="replace")
        return {
            "decision": "ALLOW",
            "tool": "read_repo_file",
            "path": str(rel_to_ws),
            "bytes_read": len(content),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="Lab L3 local MCP-style tool server.")
    parser.add_argument(
        "--print-schema-sha256",
        action="store_true",
        help="Print canonical SHA-256 of the reviewed tool schemas and exit.",
    )
    parser.add_argument(
        "--profile",
        choices=["overprivileged", "least-privilege"],
        default="least-privilege",
    )
    parser.add_argument("--policy", default="policies/mcp-least-privilege.json")
    parser.add_argument("--workspace", default=".")
    args = parser.parse_args()

    if args.print_schema_sha256:
        print(compute_schema_sha256())
        return 0

    policy_data = json.loads(Path(args.policy).read_text(encoding="utf-8"))
    server = ToolServer(args.profile, Path(args.workspace), policy_data)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        print(json.dumps(server.handle_request(req), sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
