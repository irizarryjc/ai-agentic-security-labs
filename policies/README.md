# Vendor-Neutral Policy Examples

This directory contains illustrative policy files referenced across Chapters 2 and 6.
They follow a deny-by-default model with explicit `allow`, `ask`, and `deny` rules.

## Important Dated Note (November 2026)

Policy schema keys, file paths, and enforcement hooks differ across coding-agent tools
(IDE agents, terminal agents, and CI-hosted runners). Treat these files as vendor-neutral
blueprints and lab inputs rather than drop-in syntax for a specific vendor product. Before
deploying rules in a specific coding agent, verify current policy keys and defaults in
that vendor's official documentation.

## Files

- `default-deny-policy.yaml`: Baseline `allow`, `ask`, and `deny` policy introduced in
  Chapter 2 and copied into `<sandbox_dir>/policies/` by `scripts/bootstrap-lab.sh`.
- `mcp-least-privilege.json`: Scoped, pinned tool-server configuration used in Chapter 6
  (Lab `L3`).
- `egress-allowlist.txt`: Minimal outbound destination allowlist used with the sandboxed
  runner in Chapter 6 (Lab `L2`).

## Validating YAML Locally

```bash
python3 -c 'import yaml; yaml.safe_load(open("policies/default-deny-policy.yaml"))'
```
