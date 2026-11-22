# ai-agentic-security-labs

Companion lab repository for *AI Security, Safety, and Quality for Agentic Coding*
by Juan C. Irizarry, OCP (First Edition, November 2026).

Repository URL (when published): `https://github.com/irizarryjc/ai-agentic-security-labs`

## Lab Safety Notice

Run every script, policy test, and failure drill in this repository inside a disposable,
isolated lab environment. Do not execute these exercises against production repositories,
shared staging clusters, corporate identity providers, or live databases.

- Never place real production credentials, cloud root keys, SSH private keys, or live
  customer data inside `<sandbox_dir>` or this repository.
- All prompt-injection, secret-scanning, and supply-chain fixtures use harmless canary
  values such as `CANARY_INJECTION_HIT` and `CANARY_SECRET_FAKE=not-a-real-secret`.
- Every lab is defensive. It verifies that your runner, policy, approval gate, CI pipeline,
  or recovery workflow holds under controlled conditions.

## Prerequisites

- Linux workstation, virtual machine, or macOS/WSL2 host with Bash 4+ and Git
- Python 3.10+ (standard library is sufficient for the self-contained lab runners)
- Optional: Docker or Podman for container-level filesystem and egress isolation (Ch. 2, 6)
- Optional: `psql` / PostgreSQL or SQLite (bundled with Python) for Chapter 12 drills

## Repository Layout

```text
ai-agentic-security-labs/
  README.md
  LICENSE
  labs/
    L1-prompt-injection-harness/
    L2-sandboxed-agent-runner/
    L3-mcp-least-privilege/
    L4-secrets-precommit/
    L5-slopsquatting-pinning/
    L6-hitl-approval/
    L7-review-and-test-gates/
    L8-eval-suite/
    L9-cicd-guardrails/
    L10-audit-observability/
    L11-db-change-control/
    L12-capstone-incident/
  policies/
    README.md
    default-deny-policy.yaml
    mcp-least-privilege.json
    egress-allowlist.txt
  fixtures/
    README.md
    canary-readme.md
    canary-issue.md
    fake-secrets.env
    hallucinated-requirements.txt
    pinned-requirements.txt
  scripts/
    README.md
    bootstrap-lab.sh
  evals/
    README.md
    eval-cases.json
    run-evals.py
  lab-configs/
    lab-runner.env.example
    ci-guardrails.yml
    db-readonly-policy.sql
    change-ticket-template.yaml
```

## Quick Start (Chapter 2)

Bootstrap an isolated disposable workspace and verify that no cloud, database, or API
credentials are inherited from your shell environment:

```bash
bash scripts/bootstrap-lab.sh --sandbox-dir /tmp/ai-agentic-security-sandbox
```

To inspect environment hygiene without creating files:

```bash
bash scripts/bootstrap-lab.sh --check-only
```

To remove the disposable workspace after finishing your exercises:

```bash
bash scripts/bootstrap-lab.sh --teardown --sandbox-dir /tmp/ai-agentic-security-sandbox
```

## Lab Directory Index (L1-L12)

| Lab ID | Chapter | Directory | Control Proven |
|---|---|---|---|
| `L1` | Chapter 5 | `labs/L1-prompt-injection-harness/` | Direct and indirect injection canary detection |
| `L2` | Chapter 6 | `labs/L2-sandboxed-agent-runner/` | Filesystem mounts and default-deny egress |
| `L3` | Chapter 6 | `labs/L3-mcp-least-privilege/` | Over-permissioned vs. scoped, pinned tool server |
| `L4` | Chapter 7 | `labs/L4-secrets-precommit/` | Pre-commit and CI fake-secret detection |
| `L5` | Chapter 7 | `labs/L5-slopsquatting-pinning/` | Unknown package and unpinned dependency rejection |
| `L6` | Chapter 8 | `labs/L6-hitl-approval/` | Full-argument approval gate and logged denial |
| `L7` | Chapter 8 | `labs/L7-review-and-test-gates/` | Merge gate requiring human review and real tests |
| `L8` | Chapter 9 | `labs/L8-eval-suite/` | Regression eval suite for safety and quality |
| `L9` | Chapter 9 | `labs/L9-cicd-guardrails/` | Protected-branch checks enforced in CI |
| `L10` | Chapter 10 | `labs/L10-audit-observability/` | Tool-call audit-log timeline reconstruction |
| `L11` | Chapter 12 | `labs/L11-db-change-control/` | Blocked DB change or backup delete and restore |
| `L12` | Chapter 12 | `labs/L12-capstone-incident/` | End-to-end reference-architecture recovery drill |

Each folder under `labs/` includes a `README.md` with its scenario summary, safety notice,
commands, and expected canary or gate outcome.

## Script permissions after clone

The lab runners listed below are intended to be executable. This repository was published
through the GitHub contents API, which does not reliably preserve Unix executable bits.
Every command in this README and in the book already works with `bash` or `python3` and
does not require the execute bit. If you prefer to invoke the scripts directly after
cloning, restore the modes with:

```bash
chmod +x scripts/bootstrap-lab.sh \
  evals/run-evals.py \
  labs/L1-prompt-injection-harness/run-harness.py \
  labs/L2-sandboxed-agent-runner/run-sandbox.sh \
  labs/L3-mcp-least-privilege/policy-check.py \
  labs/L3-mcp-least-privilege/tool-server.py \
  labs/L4-secrets-precommit/scan-secrets.py \
  labs/L5-slopsquatting-pinning/verify-pins.py \
  labs/L6-hitl-approval/approval-gate.py \
  labs/L7-review-and-test-gates/check-merge-gate.py \
  labs/L7-review-and-test-gates/sample_strong_test.py \
  labs/L7-review-and-test-gates/sample_weak_test.py \
  labs/L8-eval-suite/run-l8.sh \
  labs/L9-cicd-guardrails/run-ci-gates.sh \
  labs/L10-audit-observability/reconstruct-timeline.py
```

## License and Disclaimer

All scripts, fixtures, policies, and lab templates in this repository are released under
the MIT License (see `LICENSE`).

This companion repository and the accompanying book are not affiliated with or endorsed by
the OWASP Foundation, the National Institute of Standards and Technology, the International
Organization for Standardization, or the vendors of any coding-agent, IDE, or cloud product
named in the text. All trademarks are the property of their respective owners and are used
only to identify those products or publications.
