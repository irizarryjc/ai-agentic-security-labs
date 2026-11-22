# Lab L8: Agent Security and Quality Eval Suite

**Safety Banner:** Run this lab only in an isolated disposable lab environment. Eval
fixtures use harmless canary strings (`CANARY_INJECTION_HIT`, `CANARY_SECRET_FAKE`) and
fictional package names.

## Purpose

Demonstrate using a fast, repeatable evaluation suite as regression testing for coding
agents across four domains:

1. Direct and indirect prompt-injection canaries.
2. Secret-leak and log-redaction canaries.
3. Unknown and unpinned package refusal canaries.
4. Scope adherence and test-integrity quality checks.

## Files

- `run-l8.sh`: Runs the shared `evals/run-evals.py` harness against the hardened baseline,
  simulates a prompt/policy regression, confirms the gate fails non-zero, and verifies
  restoration.

## Quick Run Steps

From `<project_root>`:

```bash
bash labs/L8-eval-suite/run-l8.sh
```

To run an individual profile and emit a JSON scorecard:

```bash
python3 evals/run-evals.py \
  --cases evals/eval-cases.json \
  --profile regression-unconstrained \
  --min-pass-rate 1.0 \
  --json-report /tmp/l8-scorecard.json
```

## Expected Results

- `baseline-hardened`: `10/10 (100.0%)`, exit code `0`.
- `regression-unconstrained`: `7/10 (70.0%)`, exit code `1` (blocks release/merge).
- `run-l8.sh` exits `0` after verifying all three steps.
