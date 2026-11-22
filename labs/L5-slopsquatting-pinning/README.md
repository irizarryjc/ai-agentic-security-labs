# Lab L5: Hallucinated Package, Slopsquatting, and Pinning Check

Defensive supply-chain verification lab for Chapter 7 of *AI Security, Safety, and
Quality for Agentic Coding*.

## Lab Safety Rule

Never run `pip install` or `npm install` on an unknown or hallucinated package name to
see if it exists on a public registry. Validate every dependency offline against a
vetted registry catalog and cryptographic hashes first.

## Files in This Lab

- `allowlist-registry.json`: Local vetted package catalog with approved versions,
  SHA-256 digests, and provenance metadata.
- `verify-pins.py`: Enforces exact version pins (`==`), SHA-256 hashes
  (`--hash=sha256:...`), and allowlist membership. Rejects unknown/hallucinated package
  names with exit code `1`.

## Quick Start

From `<project_root>`:

```bash
# 1. Catch hallucinated and unpinned dependencies (expected exit code 1)
python3 labs/L5-slopsquatting-pinning/verify-pins.py \
  --requirements fixtures/hallucinated-requirements.txt \
  --registry labs/L5-slopsquatting-pinning/allowlist-registry.json

# 2. Confirm vetted, hash-pinned requirements pass (expected exit code 0)
python3 labs/L5-slopsquatting-pinning/verify-pins.py \
  --requirements fixtures/pinned-requirements.txt \
  --registry labs/L5-slopsquatting-pinning/allowlist-registry.json
```
