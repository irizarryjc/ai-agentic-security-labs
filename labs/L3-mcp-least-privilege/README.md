# Lab L3: Over-Permissioned vs. Least-Privilege MCP or Tool Server

Defensive MCP and tool-boundary lab for Chapter 6 of *AI Security, Safety, and Quality
for Agentic Coding*.

## Lab Safety Rule

Run this lab only against the disposable repository fixtures. Do not expose this tool
server on a network interface or supply real production OAuth tokens or API keys.

## What This Lab Demonstrates

Compares two profiles of the same local `stdio` JSON-RPC tool server (`tool-server.py`):

1. `overprivileged`: allows arbitrary filesystem reads (including `fake-secrets.env`),
   permits `run_shell`, accepts forwarded foreign tokens (token passthrough), and allows
   outbound SSRF-like fetches to `169.254.169.254`.
2. `least-privilege`: enforces `policies/mcp-least-privilege.json` with deny-by-default
   tools, canonical path confinement (`os.path.realpath`), explicit secret-file deny
   globs, pinned SHA-256 schema verification, strict token audience checks (no token
   passthrough), and an `ASK` gate for `propose_patch`.

## Quick Start

From `<project_root>`:

```bash
# 1. Verify pinned tool schema digest
python3 labs/L3-mcp-least-privilege/tool-server.py --print-schema-sha256

# 2. Run checks against overprivileged profile (expected exit code 1: controls fail)
python3 labs/L3-mcp-least-privilege/policy-check.py --profile overprivileged

# 3. Run checks against least-privilege profile (expected exit code 0: all gates hold)
python3 labs/L3-mcp-least-privilege/policy-check.py --profile least-privilege
```
