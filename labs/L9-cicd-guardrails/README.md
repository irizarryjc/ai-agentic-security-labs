# Lab L9: CI/CD Guardrails on a Protected Branch

**Safety Banner:** Run this lab only in an isolated disposable lab environment. The
failing candidate fixture uses a fake secret (`CANARY_SECRET_FAKE=not-a-real-secret`) and
a fictional package name (`acme-fast-validator-ghostpkg`).

## Purpose

Verify that all four required CI checks defined in `lab-configs/ci-guardrails.yml` run
deterministically and block a non-compliant agent pull request from merging to `main`:

1. Secret hygiene scan (`secret-scan`).
2. Dependency pinning and allowlist verification (`pin-check`).
3. Human review, unit test execution, and AST test integrity (`tests`).
4. Agent security and quality eval regression suite (`evals`).

## Files

- `run-ci-gates.sh`: Local CI pipeline simulator matching `lab-configs/ci-guardrails.yml`.
- Companion workflow definition: `lab-configs/ci-guardrails.yml`.

## Quick Run Steps

From `<project_root>`:

```bash
# 1. Confirm a compliant candidate PR passes all 4 gates (exit 0)
bash labs/L9-cicd-guardrails/run-ci-gates.sh --mode pass

# 2. Inject a non-compliant agent PR (fake secret, unpinned pkg, weak test,
#    regressed eval profile) and verify merge is blocked (exit 1)
bash labs/L9-cicd-guardrails/run-ci-gates.sh --mode fail-candidate

# 3. Run a single CI check stage independently
bash labs/L9-cicd-guardrails/run-ci-gates.sh --mode pass --only pin-check
```

## Expected Results

- `--mode pass`: `0` failures, `MERGE ELIGIBLE`, exit code `0`.
- `--mode fail-candidate`: `4` gate failures, `MERGE BLOCKED`, exit code `1`.
