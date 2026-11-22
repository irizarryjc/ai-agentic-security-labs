# Lab L1: Prompt-Injection Test Harness

Defensive-only test harness for Chapter 5 of *AI Security, Safety, and Quality for
Agentic Coding*.

## Lab Safety Rule

Run this harness only inside an isolated disposable lab directory with synthetic
fixtures. Never point it at production repositories, real credentials, or live
external endpoints. All injection payloads use the harmless canary
`CANARY_INJECTION_HIT`.

## What This Lab Demonstrates

1. **Direct prompt injection:** an operator prompt override and a pasted stack trace
   containing embedded instructions.
2. **Indirect prompt injection:** untrusted repository files (`fixtures/canary-readme.md`
   and `fixtures/canary-issue.md`) attempting agent goal hijack (`ASI01` / `LLM01`).
3. **Vulnerable vs. guarded runner:** shows why flattening instructions and data with
   unrestricted tools leads to canary execution (exit code `1`), while data delimiters
   plus deny-by-default tool policy block every canary (exit code `0`).

## Quick Start

From `<project_root>`:

```bash
# 1. Baseline failure: vulnerable flat-context runner (expected exit code 1)
python3 labs/L1-prompt-injection-harness/run-harness.py --mode vulnerable

# 2. Guarded runner: delimited context + deny-by-default policy (expected exit code 0)
python3 labs/L1-prompt-injection-harness/run-harness.py --mode guarded \
  --json-log /tmp/l1-audit.jsonl
```
