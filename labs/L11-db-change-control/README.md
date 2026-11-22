# Lab L11: Database Change-Control, Backup Guard, and Recovery

Companion lab for Chapter 12 of *AI Security, Safety, and Quality for Agentic Coding*.
Repository: `https://github.com/irizarryjc/ai-agentic-security-labs`

> **SAFETY BANNER:** Run this lab only inside an isolated, disposable directory such as
> `/tmp/l11-db-lab`. Never point the runner at a production database, staging volume,
> real backup repository, or real customer data.

## Prerequisites

- Python 3.10 or newer with the standard `sqlite3` module (no external database daemon
  is required to run this lab).
- Optional: a disposable local PostgreSQL instance if you also test
  `lab-configs/db-readonly-policy.sql`.

## What This Lab Proves

1. A view-scoped, read-only database role (`agent_ro_ticket`) can run diagnostic
   queries on approved non-PII views while DDL (`DROP TABLE`), DML (`UPDATE`), and
   direct reads of unapproved tables (`migrations_history`) are denied and logged.
2. A write-protected backup repository blocks an agent attempt to delete the last
   known-good baseline snapshot and preserves its SHA-256 checksum.
3. If an over-privileged tool bypasses controls and drops a working table, the DBA
   operator can verify the backup checksum, restore the database, and validate
   integrity and row totals.

## Step-by-Step Execution

```bash
[labuser@<lab_host> <project_root>]$ python3 \
  labs/L11-db-change-control/db-guard-drill.py \
  --workdir /tmp/l11-db-lab --mode setup

[labuser@<lab_host> <project_root>]$ python3 \
  labs/L11-db-change-control/db-guard-drill.py \
  --workdir /tmp/l11-db-lab --mode test-readonly

[labuser@<lab_host> <project_root>]$ python3 \
  labs/L11-db-change-control/db-guard-drill.py \
  --workdir /tmp/l11-db-lab --mode test-backup-guard

[labuser@<lab_host> <project_root>]$ python3 \
  labs/L11-db-change-control/db-guard-drill.py \
  --workdir /tmp/l11-db-lab --mode simulate-bad-ddl

[labuser@<lab_host> <project_root>]$ python3 \
  labs/L11-db-change-control/db-guard-drill.py \
  --workdir /tmp/l11-db-lab --mode restore

[labuser@<lab_host> <project_root>]$ python3 \
  labs/L11-db-change-control/db-guard-drill.py \
  --workdir /tmp/l11-db-lab --mode status
```

## Cleanup and Rollback

```bash
[labuser@<lab_host> <project_root>]$ python3 \
  labs/L11-db-change-control/db-guard-drill.py \
  --workdir /tmp/l11-db-lab --mode clean
```
