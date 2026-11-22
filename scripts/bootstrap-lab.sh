#!/usr/bin/env bash
# bootstrap-lab.sh: Create, check, or tear down an isolated coding-agent lab sandbox.
# Companion script for Chapter 2 of "AI Security, Safety, and Quality for Agentic Coding".
# Safety rule: Run only on a disposable workstation or VM with zero production secrets.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SANDBOX_DIR="/tmp/ai-agentic-security-sandbox"
MODE="bootstrap"

BLOCKED_ENV_VARS=(
  "AWS_ACCESS_KEY_ID"
  "AWS_SECRET_ACCESS_KEY"
  "AWS_SESSION_TOKEN"
  "AZURE_CLIENT_SECRET"
  "AZURE_SUBSCRIPTION_ID"
  "GOOGLE_APPLICATION_CREDENTIALS"
  "PGPASSWORD"
  "DATABASE_URL"
  "MYSQL_PWD"
  "ORACLE_PASSWORD"
  "MONGODB_URI"
  "OPENAI_API_KEY"
  "ANTHROPIC_API_KEY"
  "GEMINI_API_KEY"
  "GITHUB_TOKEN"
  "GH_TOKEN"
  "SSH_AUTH_SOCK"
  "CANARY_TEST_TOKEN"
)

usage() {
  cat <<'EOF'
Usage: bootstrap-lab.sh [OPTIONS]

Options:
  --sandbox-dir PATH   Target disposable sandbox directory
                       (default: /tmp/ai-agentic-security-sandbox)
  --check-only         Verify shell environment hygiene without modifying disk
  --teardown           Remove the target disposable sandbox directory safely
  -h, --help           Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sandbox-dir)
      if [[ $# -lt 2 ]]; then
        echo "ERROR: --sandbox-dir requires a path argument." >&2
        exit 2
      fi
      SANDBOX_DIR="$2"
      shift 2
      ;;
    --check-only)
      MODE="check"
      shift
      ;;
    --teardown)
      MODE="teardown"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

validate_sandbox_path() {
  local target="$1"
  if [[ -z "${target}" || "${target}" == "/" || "${target}" == "${HOME}" ]]; then
    echo "ERROR: Refusing unsafe sandbox path: '${target}'" >&2
    exit 1
  fi
  if [[ "${target}" == "${PROJECT_ROOT}" ]]; then
    echo "ERROR: Sandbox directory must be separate from project root." >&2
    exit 1
  fi
}

check_environment_hygiene() {
  local found=0
  local var_name=""
  echo "[check] Scanning shell environment for inherited secrets or agents..."
  for var_name in "${BLOCKED_ENV_VARS[@]}"; do
    if [[ -n "${!var_name:-}" ]]; then
      echo "[FAIL] Sensitive variable is exported: ${var_name}" >&2
      found=1
    fi
  done

  if [[ "${found}" -ne 0 ]]; then
    echo "" >&2
    echo "Remediation: unset sensitive variables or run with a scrubbed shell:" >&2
    echo "  env -i HOME=\"\$HOME\" PATH=\"/usr/local/bin:/usr/bin:/bin\" \\" >&2
    echo "    bash scripts/bootstrap-lab.sh --sandbox-dir \"${SANDBOX_DIR}\"" >&2
    return 1
  fi

  echo "[PASS] Zero blocked cloud, database, API, or SSH-agent variables detected."
  return 0
}

teardown_sandbox() {
  validate_sandbox_path "${SANDBOX_DIR}"
  if [[ ! -d "${SANDBOX_DIR}" ]]; then
    echo "[teardown] Sandbox directory does not exist: ${SANDBOX_DIR}"
    return 0
  fi
  if [[ ! -f "${SANDBOX_DIR}/.lab-sandbox-marker" ]]; then
    echo "ERROR: Marker file missing in ${SANDBOX_DIR}; refusing rm -rf." >&2
    exit 1
  fi
  rm -rf "${SANDBOX_DIR}"
  echo "[teardown] Removed disposable sandbox: ${SANDBOX_DIR}"
}

bootstrap_sandbox() {
  validate_sandbox_path "${SANDBOX_DIR}"
  check_environment_hygiene

  local policy_src="${PROJECT_ROOT}/policies/default-deny-policy.yaml"
  local env_src="${PROJECT_ROOT}/lab-configs/lab-runner.env.example"

  if [[ ! -f "${policy_src}" ]]; then
    echo "ERROR: Missing policy file: ${policy_src}" >&2
    exit 1
  fi
  if [[ ! -f "${env_src}" ]]; then
    echo "ERROR: Missing env template: ${env_src}" >&2
    exit 1
  fi

  mkdir -p "${SANDBOX_DIR}/repo" \
           "${SANDBOX_DIR}/policies" \
           "${SANDBOX_DIR}/logs" \
           "${SANDBOX_DIR}/config"
  chmod 700 "${SANDBOX_DIR}" "${SANDBOX_DIR}/logs" "${SANDBOX_DIR}/config"

  printf "disposable-lab-sandbox=true\n" > "${SANDBOX_DIR}/.lab-sandbox-marker"

  cp "${policy_src}" "${SANDBOX_DIR}/policies/default-deny-policy.yaml"
  cp "${env_src}" "${SANDBOX_DIR}/config/lab-runner.env"
  chmod 600 "${SANDBOX_DIR}/config/lab-runner.env"

  if [[ ! -d "${SANDBOX_DIR}/repo/.git" ]]; then
    git -C "${SANDBOX_DIR}/repo" init -q -b main
    git -C "${SANDBOX_DIR}/repo" config user.name "Lab User"
    git -C "${SANDBOX_DIR}/repo" config user.email "labuser@sandbox.local"
    cat <<'EOF' > "${SANDBOX_DIR}/repo/README.md"
# Scratch Lab Service

Disposable local repository for coding-agent security and safety exercises.
Contains no production credentials, no customer records, and no remote origin.
EOF
    cat <<'EOF' > "${SANDBOX_DIR}/repo/app.py"
"""Minimal sample module for disposable coding-agent lab exercises."""


def calculate_total(subtotal: float, tax_rate: float) -> float:
    if subtotal < 0 or tax_rate < 0:
        raise ValueError("subtotal and tax_rate must be non-negative")
    return round(subtotal * (1.0 + tax_rate), 2)
EOF
    git -C "${SANDBOX_DIR}/repo" add README.md app.py
    git -C "${SANDBOX_DIR}/repo" commit -q -m "chore: initialize scratch lab repo"
  fi

  local ts_utc
  ts_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  printf '{"event":"bootstrap","ts":"%s","sandbox":"%s","status":"ready"}\n' \
    "${ts_utc}" "${SANDBOX_DIR}" >> "${SANDBOX_DIR}/logs/lab-bootstrap.jsonl"

  echo "[PASS] Repo:   ${SANDBOX_DIR}/repo (no remote configured)"
  echo "[PASS] Policy: ${SANDBOX_DIR}/policies/default-deny-policy.yaml"
  echo "[PASS] Config: ${SANDBOX_DIR}/config/lab-runner.env"
  echo "[PASS] Log:    ${SANDBOX_DIR}/logs/lab-bootstrap.jsonl"
}

case "${MODE}" in
  check)
    check_environment_hygiene
    ;;
  teardown)
    teardown_sandbox
    ;;
  bootstrap)
    bootstrap_sandbox
    ;;
esac
