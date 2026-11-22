# Lab L4: Pre-Commit and Secret Scanning

Defensive secrets-hygiene lab for Chapter 7 of *AI Security, Safety, and Quality for
Agentic Coding*.

## Lab Safety Rule

Test this scanner only with obviously synthetic canary values such as
`CANARY_SECRET_FAKE=not-a-real-secret`. Never commit real API keys, database passwords,
or SSH keys to any scratch or test repository.

## Files in This Lab

- `scan-secrets.py`: Local secret scanner that checks filenames and file contents,
  flags canary and credential patterns, redacts all matched values in stdout, and exits
  with code `1` on findings (`0` when clear).
- `.pre-commit-config.yaml`: Example pre-commit configuration wiring `scan-secrets.py`
  as a local hook before `git commit` succeeds.

## Quick Start

From `<project_root>`:

```bash
# 1. Confirm the scanner catches the planted fake secret (expected exit code 1)
python3 labs/L4-secrets-precommit/scan-secrets.py fixtures/fake-secrets.env

# 2. Confirm a clean file passes the gate (expected exit code 0)
python3 labs/L4-secrets-precommit/scan-secrets.py fixtures/pinned-requirements.txt
```
