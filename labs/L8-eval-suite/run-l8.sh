#!/usr/bin/env bash
# Lab L8: Agent Security and Quality Eval Suite Runner
# Defensive lab script: compares baseline-hardened vs regression-unconstrained
# eval runs and writes a JSON scorecard to a temporary lab directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CASES="${REPO_ROOT}/evals/eval-cases.json"
RUNNER="${REPO_ROOT}/evals/run-evals.py"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

echo "=== Step 1: Baseline Hardened Profile (Expected: PASS) ==="
python3 "${RUNNER}" \
  --cases "${CASES}" \
  --profile baseline-hardened \
  --min-pass-rate 1.0 \
  --json-report "${WORK_DIR}/baseline-scorecard.json"

echo ""
echo "=== Step 2: Simulated Prompt/Policy Regression (Expected: FAIL) ==="
set +e
python3 "${RUNNER}" \
  --cases "${CASES}" \
  --profile regression-unconstrained \
  --min-pass-rate 1.0 \
  --json-report "${WORK_DIR}/regression-scorecard.json"
REG_EXIT=$?
set -e

if [[ "${REG_EXIT}" -eq 0 ]]; then
  echo "[ERROR] Regression profile unexpectedly passed!"
  exit 1
fi
echo "[VERIFIED] Eval gate caught regression with exit code ${REG_EXIT}."

echo ""
echo "=== Step 3: Restored Hardened Profile (Expected: PASS) ==="
python3 "${RUNNER}" \
  --cases "${CASES}" \
  --profile baseline-hardened \
  --min-pass-rate 1.0

echo "[LAB L8 COMPLETE] Baseline verified, regression blocked, recovery confirmed."
