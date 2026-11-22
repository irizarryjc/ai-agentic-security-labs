# Lab Helper Scripts

This directory contains helper scripts used to initialize, verify, and tear down the
disposable lab environment introduced in Chapter 2.

## Safety Notice

Run these scripts only on a disposable lab workstation, VM, or container host. Never run
them inside a production directory or while production credentials are exported in your
shell environment.

## Scripts

### `bootstrap-lab.sh`

Creates an isolated `<sandbox_dir>` containing:

- `repo/`: a fresh local-only Git scratch repository with no remote origin
- `policies/`: a local copy of `policies/default-deny-policy.yaml`
- `config/`: a local copy of `lab-configs/lab-runner.env.example`
- `logs/`: an append-only local directory (`chmod 700`) for lab audit events

Before writing any files, `bootstrap-lab.sh` inspects your current shell environment for
common cloud, database, SSH-agent, and AI API variables (such as `AWS_ACCESS_KEY_ID`,
`PGPASSWORD`, `DATABASE_URL`, `SSH_AUTH_SOCK`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, and
`CANARY_TEST_TOKEN`). If any blocked variable is set, the script exits with a non-zero
status and prints remediation commands.

#### Usage

Verify environment hygiene only:

```bash
bash scripts/bootstrap-lab.sh --check-only
```

Bootstrap a disposable sandbox:

```bash
bash scripts/bootstrap-lab.sh --sandbox-dir /tmp/ai-agentic-security-sandbox
```

Tear down and remove the disposable sandbox:

```bash
bash scripts/bootstrap-lab.sh --teardown --sandbox-dir /tmp/ai-agentic-security-sandbox
```

If your workstation shell normally exports `SSH_AUTH_SOCK` or API keys, launch the script
inside a scrubbed environment:

```bash
env -i HOME="$HOME" PATH="/usr/local/bin:/usr/bin:/bin" \
  bash scripts/bootstrap-lab.sh --sandbox-dir /tmp/ai-agentic-security-sandbox
```
