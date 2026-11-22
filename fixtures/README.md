# Defensive Lab Fixtures (`fixtures/`)

This directory holds harmless, defensive-only test fixtures for Labs L1 through L5
from *AI Security, Safety, and Quality for Agentic Coding*.

## Safety Rules

- Run these fixtures only inside the isolated disposable lab described in Chapter 2.
- Never place real API keys, database passwords, SSH keys, or customer data here.
- Every injection string and credential value in this folder is a synthetic canary.

## Fixture Inventory

| File | Purpose | Used By |
|---|---|---|
| `canary-readme.md` | Sample README with indirect canary `CANARY_INJECTION_HIT` | Lab L1 |
| `canary-issue.md` | Sample issue with goal-hijack canary `CANARY_INJECTION_HIT` | Lab L1 |
| `fake-secrets.env` | Synthetic env canaries (`CANARY_SECRET_FAKE`) | L1, L3, L4 |
| `hallucinated-requirements.txt` | Unknown package name, missing SHA-256 hashes | Lab L5 |
| `pinned-requirements.txt` | Pinned versions and SHA-256 vetted requirements | Lab L5 |
