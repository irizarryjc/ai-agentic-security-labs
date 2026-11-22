# Shared Security and Quality Evaluation Suite (`evals/`)

**Safety Banner:** All fixtures in this directory are defensive lab canaries. Never place
production secrets, live customer records, or exploit payloads inside eval cases.

## Purpose

This directory contains the shared regression evaluation suite used by Lab L8
(`labs/L8-eval-suite/`) and Lab L9 (`labs/L9-cicd-guardrails/`). Re-run these evals
whenever you change:

- The underlying LLM or model snapshot
- System prompts, repo-level agent instructions, or tool descriptions
- Policy files, MCP server pins, or sandbox configuration

## Files

- `eval-cases.json`: Ten defensive cases spanning four categories:
  1. `injection_canary` (`EVAL-INJ-01`..`03`): direct and indirect prompt injection.
  2. `secret_leak_canary` (`EVAL-SEC-01`..`02`): planted fake secret and redaction check.
  3. `unknown_package_canary` (`EVAL-PKG-01`..`02`): hallucinated and unpinned packages.
  4. `quality_scope` and `quality_tests` (`EVAL-QUAL-01`..`03`): scope and test integrity.
- `run-evals.py`: Zero-dependency Python 3 evaluation runner.

## Usage

From `<project_root>`:

```bash
# Run hardened baseline profile (expected: 10/10 PASS, exit 0)
python3 evals/run-evals.py \
  --cases evals/eval-cases.json \
  --profile baseline-hardened \
  --min-pass-rate 1.0

# Run simulated regression profile (expected: 7/10 FAIL, exit 1)
python3 evals/run-evals.py \
  --cases evals/eval-cases.json \
  --profile regression-unconstrained \
  --min-pass-rate 1.0

# Evaluate recorded traces from your own local lab runner
python3 evals/run-evals.py \
  --cases evals/eval-cases.json \
  --responses /path/to/recorded-responses.json \
  --json-report /tmp/eval-scorecard.json
```
