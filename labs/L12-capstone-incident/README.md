# Lab L12: Capstone Incident Drill for the Reference Architecture

Companion lab for Chapter 12 and Appendix A of
*AI Security, Safety, and Quality for Agentic Coding*.
Repository: `https://github.com/irizarryjc/ai-agentic-security-labs`

> **SAFETY BANNER:** Run this capstone drill only in an isolated, disposable directory
> such as `/tmp/l12-capstone-lab`. Never point this script at a production database,
> real token store, or customer records. All canaries (`CANARY_INJECTION_HIT` and
> `CANARY_SECRET_FAKE=not-a-real-secret`) are harmless synthetic markers.

## Prerequisites

- Python 3.10 or newer with standard `sqlite3` support.
- Copy of Appendix A (Incident and Approval Runbook Template) to record timings and
  sign-off notes alongside the generated report.

## Drill Sequence

```bash
[labuser@<lab_host> <project_root>]$ python3 \
  labs/L12-capstone-incident/run-capstone-drill.py \
  --workdir /tmp/l12-capstone-lab --step baseline

[labuser@<lab_host> <project_root>]$ python3 \
  labs/L12-capstone-incident/run-capstone-drill.py \
  --workdir /tmp/l12-capstone-lab --step inject

[labuser@<lab_host> <project_root>]$ python3 \
  labs/L12-capstone-incident/run-capstone-drill.py \
  --workdir /tmp/l12-capstone-lab --step detect

[labuser@<lab_host> <project_root>]$ python3 \
  labs/L12-capstone-incident/run-capstone-drill.py \
  --workdir /tmp/l12-capstone-lab --step contain

[labuser@<lab_host> <project_root>]$ python3 \
  labs/L12-capstone-incident/run-capstone-drill.py \
  --workdir /tmp/l12-capstone-lab --step recover

[labuser@<lab_host> <project_root>]$ python3 \
  labs/L12-capstone-incident/run-capstone-drill.py \
  --workdir /tmp/l12-capstone-lab --step report
```

## Cleanup

```bash
[labuser@<lab_host> <project_root>]$ python3 \
  labs/L12-capstone-incident/run-capstone-drill.py \
  --workdir /tmp/l12-capstone-lab --step clean
```
