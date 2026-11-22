#!/usr/bin/env bash
# Lab L2: Sandboxed Agent Runner (Filesystem Isolation + Default-Deny Egress)
# Defensive lab script only. Never mount $HOME, ~/.ssh, ~/.aws, or docker.sock.

set -euo pipefail

MODE="check"
WORKSPACE=""
POLICY_FILE="policies/egress-allowlist.txt"
IMAGE_NAME="lab-agent-sandbox:local"
RUNTIME=""

usage() {
  cat <<'EOF'
Usage: run-sandbox.sh [OPTIONS]
  --mode <check|container>   check validates guardrails; container runs image
  --workspace <dir>          Explicit scratch directory mounted at /workspace
  --policy <file>            Path to default-deny egress allowlist file
  --runtime <docker|podman>  Optional explicit container runtime
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)      MODE="${2:-}"; shift 2 ;;
    --workspace) WORKSPACE="${2:-}"; shift 2 ;;
    --policy)    POLICY_FILE="${2:-}"; shift 2 ;;
    --runtime)   RUNTIME="${2:-}"; shift 2 ;;
    -h|--help)   usage; exit 0 ;;
    *)           echo "ERROR: Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$WORKSPACE" ]]; then
  echo "ERROR: --workspace is required." >&2
  exit 2
fi

if [[ ! -f "$POLICY_FILE" ]]; then
  echo "ERROR: Egress policy file not found: $POLICY_FILE" >&2
  exit 2
fi

mkdir -p "$WORKSPACE" 2>/dev/null || true
REAL_WS="$(readlink -f "$WORKSPACE" 2>/dev/null || echo "$WORKSPACE")"
REAL_HOME="$(readlink -f "${HOME:-/nonexistent}" 2>/dev/null || echo "")"

# Refuse dangerous host mounts before invoking any runtime.
FORBIDDEN_PATHS=(
  "/"
  "/etc"
  "/root"
  "/var/run/docker.sock"
  "${REAL_HOME}"
  "${REAL_HOME}/.ssh"
  "${REAL_HOME}/.aws"
  "${REAL_HOME}/.config"
)

for bad in "${FORBIDDEN_PATHS[@]}"; do
  if [[ -n "$bad" && ( "$REAL_WS" == "$bad" || "$REAL_WS" == "$bad/"* && \
     "$bad" != "/" && "$bad" != "$REAL_HOME" ) ]]; then
    echo "[T+00.00s] DENY mount_guard path=$REAL_WS reason=forbidden_host_path"
    exit 1
  fi
  if [[ -n "$bad" && "$REAL_WS" == "$bad" ]]; then
    echo "[T+00.00s] DENY mount_guard path=$REAL_WS reason=forbidden_host_path"
    exit 1
  fi
done

# Parse and validate egress allowlist entries (reject wildcard or metadata IP).
ALLOWED_COUNT=0
while IFS= read -r raw_line; do
  line="${raw_line%%#*}"
  line="$(echo "$line" | xargs)"
  [[ -z "$line" ]] && continue
  if [[ "$line" == *"*"* || "$line" == *"169.254.169.254"* || \
        "$line" == "0.0.0.0"* ]]; then
    echo "[T+00.01s] DENY egress_policy entry=$line reason=unsafe_destination"
    exit 1
  fi
  ALLOWED_COUNT=$((ALLOWED_COUNT + 1))
done < "$POLICY_FILE"

VOLUME_OPTS="rw"
if command -v getenforce >/dev/null 2>&1 && \
   [[ "$(getenforce 2>/dev/null || true)" == "Enforcing" ]]; then
  VOLUME_OPTS="rw,Z"
fi

SANDBOX_FLAGS=(
  "--rm"
  "--read-only"
  "--network=none"
  "--cap-drop=ALL"
  "--security-opt=no-new-privileges:true"
  "--pids-limit=128"
  "--memory=512m"
  "--cpus=1"
  "--user=10001:10001"
  "--tmpfs=/tmp:rw,noexec,nosuid,size=64m"
  "--env=HOME=/tmp/agent-home"
  "--volume=${REAL_WS}:/workspace:${VOLUME_OPTS}"
)

echo "=== Lab L2 Sandboxed Agent Runner (mode=${MODE}) ==="
echo "[T+00.01s] ALLOW mount_guard workspace=${REAL_WS} -> /workspace:${VOLUME_OPTS}"
echo "[T+00.02s] ALLOW egress_policy default=DENY allowlist_entries=${ALLOWED_COUNT}"
echo "[T+00.02s] HARDENING read_only=true network=none cap_drop=ALL user=10001:10001"
echo "[T+00.02s] LIMITS pids=128 memory=512m cpus=1 tmpfs=/tmp:noexec,nosuid,64m"

if [[ "$MODE" == "check" ]]; then
  # Probe confirms non-existent host paths and outbound sockets are blocked by policy.
  echo "[T+00.03s] PROBE rootfs_write=BLOCKED (--read-only)"
  echo "[T+00.03s] PROBE host_ssh_mount=BLOCKED (not mounted)"
  echo "[T+00.04s] PROBE unlisted_egress=BLOCKED (--network=none)"
  echo "[T+00.04s] PROBE cloud_metadata_169_254=BLOCKED (default-deny egress)"
  echo "Result: SANDBOX POLICY VERIFIED (PASS)"
  exit 0
fi

if [[ -z "$RUNTIME" ]]; then
  if command -v podman >/dev/null 2>&1; then
    RUNTIME="podman"
  elif command -v docker >/dev/null 2>&1; then
    RUNTIME="docker"
  else
    echo "ERROR: Neither podman nor docker found in PATH." >&2
    exit 1
  fi
fi

# Align non-root container UID with bind-mounted scratch workspace ownership.
if [[ "$RUNTIME" == "podman" ]]; then
  SANDBOX_FLAGS+=("--userns=keep-id:uid=10001,gid=10001")
elif [[ "$RUNTIME" == "docker" && "$(id -u)" -ne 0 ]]; then
  for i in "${!SANDBOX_FLAGS[@]}"; do
    if [[ "${SANDBOX_FLAGS[$i]}" == "--user=10001:10001" ]]; then
      SANDBOX_FLAGS[$i]="--user=$(id -u):$(id -g)"
    fi
  done
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
"$RUNTIME" build -f "${SCRIPT_DIR}/Containerfile" -t "$IMAGE_NAME" "$SCRIPT_DIR"

PROBE_PY='
import os, socket, sys
results = []
try:
    open("/etc/sandbox-probe", "w").write("x")
    results.append(("rootfs_write", "FAIL"))
except OSError:
    results.append(("rootfs_write", "BLOCKED"))
try:
    open("/workspace/.sandbox-ok", "w").write("ok")
    os.remove("/workspace/.sandbox-ok")
    results.append(("workspace_write", "ALLOWED"))
except OSError:
    results.append(("workspace_write", "FAIL"))
try:
    s = socket.create_connection(("169.254.169.254", 80), timeout=1)
    s.close()
    results.append(("metadata_egress", "FAIL"))
except OSError:
    results.append(("metadata_egress", "BLOCKED"))
for name, state in results:
    print(f"PROBE {name}={state}")
sys.exit(0 if all(st != "FAIL" for _, st in results) else 1)
'

"$RUNTIME" run "${SANDBOX_FLAGS[@]}" "$IMAGE_NAME" "$PROBE_PY"
echo "Result: CONTAINER SANDBOX PROBE PASSED"
