# Lab L6: Human-in-the-Loop Approval for a Destructive Action

**Safety Banner:** Run this lab only in an isolated disposable lab environment. Do not
point these scripts at production directories, real credentials, or live customer data.
`approval-gate.py` simulates destructive actions and never deletes files on disk.

## Purpose

Verify that a human-in-the-loop (HITL) approval gate:

1. Displays the full tool name, exact target path, raw JSON arguments, and a dry-run
   preview separately from untrusted model-authored rationale text.
2. Rejects blanket auto-approval (`--auto-approve-all`) on high-impact tools.
3. Binds each approval to a SHA-256 `action_digest` and single-use `nonce`, blocking
   post-approval argument tampering (`exit 2`) and approval replay (`exit 3`).
4. Records every allow, approval, and denial to an append-only JSONL audit log.

## Files

- `approval-gate.py`: Self-contained Python 3 HITL approval gate simulator.

## Quick Run Steps

From `<project_root>`:

```bash
# 1. Confirm baseline read-only tool call is allowed and logged
python3 labs/L6-hitl-approval/approval-gate.py \
  --tool git_status --target . \
  --audit-log /tmp/l6-hitl-audit.jsonl

# 2. Prove blanket auto-approve is rejected for a destructive tool
python3 labs/L6-hitl-approval/approval-gate.py \
  --tool delete_directory --target data/snapshots --recursive \
  --auto-approve-all \
  --audit-log /tmp/l6-hitl-audit.jsonl

# 3. Inspect raw arguments vs misleading rationale and deny the destructive call
python3 labs/L6-hitl-approval/approval-gate.py \
  --tool delete_directory --target data/snapshots --recursive \
  --rationale "Removing stale temporary cache files to speed up tests." \
  --decision deny \
  --audit-log /tmp/l6-hitl-audit.jsonl

# 4. Prove post-approval argument tampering fails digest verification (exit 2)
python3 labs/L6-hitl-approval/approval-gate.py \
  --tool bulk_file_delete --target tmp/cache.log \
  --rationale "Clear single temporary cache file." \
  --decision approve \
  --simulate-tamper data/ledger.db \
  --audit-log /tmp/l6-hitl-audit.jsonl

# 5. Prove single-use nonce blocks approval replay (exit 3)
python3 labs/L6-hitl-approval/approval-gate.py \
  --tool bulk_file_delete --target tmp/cache.log \
  --decision approve --simulate-replay \
  --audit-log /tmp/l6-hitl-audit.jsonl

# 6. Inspect the recorded JSONL audit trail
cat /tmp/l6-hitl-audit.jsonl
```

## Expected Results

| Step | Expected Exit Code | Expected Audit Decision |
|---|---|---|
| 1. Read-only `git_status` | `0` | `ALLOW_POLICY` |
| 2. Blanket `--auto-approve-all` | `1` | `DENY_AUTO_APPROVE_FORBIDDEN` |
| 3. Operator denies destructive delete | `1` | `DENY_HUMAN` |
| 4. Post-approval target swap | `2` | `DENY_DIGEST_MISMATCH` |
| 5. Replayed single-use nonce | `3` | `APPROVE_HUMAN` then `DENY_NONCE_REPLAY` |

## Cleanup

```bash
rm -f /tmp/l6-hitl-audit.jsonl
```
