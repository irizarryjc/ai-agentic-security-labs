#!/usr/bin/env bash
# Lab L9: Local CI/CD Protected-Branch Guardrail Simulator
# Enforces all 4 required checks from lab-configs/ci-guardrails.yml:
#   1. secret-scan  : blocks planted fake secrets and private key headers
#   2. pin-check    : blocks unpinned or non-allowlisted package requirements
#   3. tests        : runs unittest + AST vacuous-test gate (L7)
#   4. evals        : runs agent security and quality eval suite (L8)
#
# Modes:
#   --mode pass           Clean candidate PR -> all 4 gates PASS (exit 0)
#   --mode fail-candidate Candidate with fake secret, unpinned pkg, weak test,
#                         and regressed eval profile -> merge BLOCKED (exit 1)
#   --only <gate>         Run a single gate (secret-scan|pin-check|tests|evals)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

MODE="pass"
ONLY_GATE="all"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      MODE="${2:-pass}"
      shift 2
      ;;
    --only)
      ONLY_GATE="${2:-all}"
      shift 2
      ;;
    *)
      echo "Usage: $0 [--mode pass|fail-candidate]" \
           "[--only secret-scan|pin-check|tests|evals]"
      exit 2
      ;;
  esac
done

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "${WORK_DIR}"' EXIT

ALLOWLIST_PKGS="pyyaml|urllib3|certifi"

# Build isolated candidate workspace inside temporary scratch directory
if [[ "${MODE}" == "pass" ]]; then
  cat > "${WORK_DIR}/app.py" <<'EOF'
"""Clean lab candidate module with no hardcoded secrets."""
def health_status() -> str:
    return "ok"
EOF
  cat > "${WORK_DIR}/requirements.txt" <<'EOF'
pyyaml==6.0.2
urllib3==2.2.3
EOF
  TEST_FILE="${REPO_ROOT}/labs/L7-review-and-test-gates/sample_strong_test.py"
  EVAL_PROFILE="baseline-hardened"
  REVIEW_FLAGS=(--reviewer senior-eng-02 --review-approved)
else
  cat > "${WORK_DIR}/app.py" <<'EOF'
"""Failing lab candidate with planted fake canary secret (not a real key)."""
CANARY_SECRET_FAKE = "not-a-real-secret"
EOF
  cat > "${WORK_DIR}/requirements.txt" <<'EOF'
pyyaml==6.0.2
requests
acme-fast-validator-ghostpkg==0.1.0
EOF
  TEST_FILE="${REPO_ROOT}/labs/L7-review-and-test-gates/sample_weak_test.py"
  EVAL_PROFILE="regression-unconstrained"
  REVIEW_FLAGS=()
fi

FAILURES=0

run_secret_scan() {
  echo "--- Gate 1: Secret Hygiene Scan ---"
  if grep -En "(CANARY_SECRET_FAKE|AKIA[0-9A-Z]{16}|BEGIN PRIVATE KEY)" \
      "${WORK_DIR}/app.py" >/dev/null 2>&1; then
    echo "[FAIL] Secret pattern detected in candidate app.py"
    FAILURES=$((FAILURES + 1))
  else
    echo "[PASS] No secret patterns found in candidate files"
  fi
}

run_pin_check() {
  echo "--- Gate 2: Dependency Pin and Allowlist Check ---"
  local bad=0
  while IFS= read -r line; do
    [[ -z "${line}" || "${line}" == \#* ]] && continue
    if ! [[ "${line}" =~ ^[a-zA-Z0-9_-]+==[0-9]+(\.[0-9]+)*$ ]]; then
      echo "[FAIL] Unpinned dependency line: ${line}"
      bad=1
      continue
    fi
    pkg="${line%%==*}"
    if ! [[ "${pkg}" =~ ^(${ALLOWLIST_PKGS})$ ]]; then
      echo "[FAIL] Package not in approved allowlist: ${pkg}"
      bad=1
    fi
  done < "${WORK_DIR}/requirements.txt"

  if [[ "${bad}" -eq 0 ]]; then
    echo "[PASS] All dependencies are pinned and allowlisted"
  else
    FAILURES=$((FAILURES + 1))
  fi
}

run_tests_gate() {
  echo "--- Gate 3: Review, Unit Tests, and AST Test Integrity ---"
  if python3 "${REPO_ROOT}/labs/L7-review-and-test-gates/check-merge-gate.py" \
      --test-file "${TEST_FILE}" \
      --author coder-agent-lab \
      "${REVIEW_FLAGS[@]}"; then
    echo "[PASS] Review and test integrity gate satisfied"
  else
    echo "[FAIL] Review or test integrity gate failed"
    FAILURES=$((FAILURES + 1))
  fi
}

run_evals_gate() {
  echo "--- Gate 4: Agent Security and Quality Evals ---"
  if python3 "${REPO_ROOT}/evals/run-evals.py" \
      --cases "${REPO_ROOT}/evals/eval-cases.json" \
      --profile "${EVAL_PROFILE}" \
      --min-pass-rate 1.0; then
    echo "[PASS] Eval suite met 100% pass threshold"
  else
    echo "[FAIL] Eval suite fell below required threshold"
    FAILURES=$((FAILURES + 1))
  fi
}

echo "========================================================================"
echo "CI GUARDRAILS SIMULATOR | mode=${MODE} | only=${ONLY_GATE}"
echo "========================================================================"

case "${ONLY_GATE}" in
  all)
    run_secret_scan
    run_pin_check
    run_tests_gate
    run_evals_gate
    ;;
  secret-scan) run_secret_scan ;;
  pin-check)   run_pin_check ;;
  tests)       run_tests_gate ;;
  evals)       run_evals_gate ;;
  *)
    echo "[ERROR] Unknown gate: ${ONLY_GATE}"
    exit 2
    ;;
esac

echo "========================================================================"
if [[ "${FAILURES}" -eq 0 ]]; then
  echo "PROTECTED BRANCH STATUS: ALL REQUIRED CHECKS PASSED (MERGE ELIGIBLE)"
  exit 0
else
  echo "PROTECTED BRANCH STATUS: ${FAILURES} GATE(S) FAILED (MERGE BLOCKED)"
  exit 1
fi
