# Lab L2: Sandboxed Agent Runner

Defensive container and OS-isolation lab for Chapter 6 of *AI Security, Safety, and
Quality for Agentic Coding*.

## Lab Safety Rule

Run this sandbox only against a disposable scratch workspace (`<sandbox_dir>`). Never
mount your home directory, `~/.ssh`, `~/.aws`, production config directories, or the
container runtime socket (`/var/run/docker.sock`) into the agent container.

## Files in This Lab

- `Containerfile`: Minimal non-root Python runner image (`UID 10001`, no `sudo`).
- `run-sandbox.sh`: Launches or validates the hardened sandbox with read-only rootfs,
  dropped Linux capabilities, explicit workspace mount, and `--network=none` default-deny
  egress.

## Quick Start

From `<project_root>`:

```bash
# 1. Validate sandbox configuration and egress allowlist (works without daemon pull)
bash labs/L2-sandboxed-agent-runner/run-sandbox.sh --mode check \
  --workspace /tmp/lab-sandbox --policy policies/egress-allowlist.txt

# 2. Verify that mounting a sensitive path (for example ~/.ssh) is rejected (exit 1)
bash labs/L2-sandboxed-agent-runner/run-sandbox.sh --mode check \
  --workspace "$HOME/.ssh" --policy policies/egress-allowlist.txt

# 3. Build and run the real isolated container (requires Docker or Podman)
bash labs/L2-sandboxed-agent-runner/run-sandbox.sh --mode container \
  --workspace /tmp/lab-sandbox --policy policies/egress-allowlist.txt
```
