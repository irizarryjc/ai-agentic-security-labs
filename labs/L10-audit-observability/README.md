# Lab L10: Audit-Log Reconstruction of a Tool-Call Sequence

**Safety Banner:** Run this lab only in an isolated disposable lab environment. The sample
JSONL audit log uses synthetic lab identities (`lab-eng-01`, `coder-agent-lab`) and
relative timestamps (`T+00s` to `T+58s`), with zero production data or real secrets.

## Purpose

Reconstruct a multi-step coding-agent tool-call sequence from an append-only, hash-chained
JSONL audit log and prove that:

1. Every event captures operator, agent identity, session ID, tool name, redacted
   arguments, policy/approval decision, and outcome.
2. Human approval/denial decisions correlate cryptographically to the exact `ASK_HITL`
   request via `action_digest`.
3. Any post-hoc modification to a single log line breaks the SHA-256 hash chain and is
   flagged immediately (`exit 2`).
4. Redaction hygiene checks flag accidental secret or PII leakage (`exit 1`).

## Files

- `sample-audit.jsonl`: Hash-chained 10-event JSONL trail from a simulated lab incident.
- `reconstruct-timeline.py`: Zero-dependency Python 3 timeline reconstructor and verifier.

## Quick Run Steps

From `<project_root>`:

```bash
# 1. Reconstruct full session timeline and verify hash chain (exit 0)
python3 labs/L10-audit-observability/reconstruct-timeline.py \
  --log labs/L10-audit-observability/sample-audit.jsonl

# 2. Filter to denied events only to inspect the attack/policy boundary
python3 labs/L10-audit-observability/reconstruct-timeline.py \
  --log labs/L10-audit-observability/sample-audit.jsonl \
  --decision DENY

# 3. Simulate log tampering on a temporary copy and verify chain detection (exit 2)
cp labs/L10-audit-observability/sample-audit.jsonl /tmp/l10-tampered.jsonl
python3 -c '
p = "/tmp/l10-tampered.jsonl"
txt = open(p, encoding="utf-8").read().replace("DENY_HUMAN", "APPROVE_HUMAN", 1)
open(p, "w", encoding="utf-8").write(txt)
'
python3 labs/L10-audit-observability/reconstruct-timeline.py \
  --log /tmp/l10-tampered.jsonl
```

## Expected Results

- Step 1: `HASH CHAIN : VALID (10/10 entries verified)`,
  `REDACTION CHECK : CLEAN`, exit `0`.
- Step 2: Displays `seq 4` (`DENY_POLICY`), `seq 5` (`DENY_EGRESS`),
  and `seq 7` (`DENY_HUMAN`).
- Step 3: `HASH CHAIN : BROKEN`, detects tampering at `seq=7`, exit `2`.

## Cleanup

```bash
rm -f /tmp/l10-tampered.jsonl
```
