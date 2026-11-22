# Lab L7: Code Review and Testing Gates for AI-Written Code

**Safety Banner:** Run this lab only in an isolated disposable lab environment. No
production repositories or real secrets are used.

## Purpose

Demonstrate why "tests passed" alone is not an independent quality gate for AI-written
code, and enforce a merge gate that blocks:

1. Unreviewed changes or self-approved agent pull requests.
2. Vacuous tests that pass `unittest` while asserting nothing meaningful
   (`assertTrue(True)`, zero assertions, or `except Exception: pass`).
3. Changes containing canary secrets.

## Files

- `sample_weak_test.py`: Passes `unittest` despite vacuous tests and a buggy function.
- `sample_strong_test.py`: Hardened implementation with unit, boundary, error, and
  property-style invariant tests.
- `check-merge-gate.py`: Four-part merge gate enforcing review, AST test integrity,
  secret hygiene, and test execution.

## Quick Run Steps

From `<project_root>`:

```bash
# 1. Notice that sample_weak_test.py passes standard unittest on its own
python3 -m unittest labs/L7-review-and-test-gates/sample_weak_test.py

# 2. Run the merge gate without human review against the weak test (BLOCKS)
python3 labs/L7-review-and-test-gates/check-merge-gate.py \
  --test-file labs/L7-review-and-test-gates/sample_weak_test.py \
  --author coder-agent-lab

# 3. Even with a human reviewer, vacuous tests still block merge (BLOCKS)
python3 labs/L7-review-and-test-gates/check-merge-gate.py \
  --test-file labs/L7-review-and-test-gates/sample_weak_test.py \
  --author coder-agent-lab --reviewer senior-eng-02 --review-approved

# 4. Run against the hardened test suite with independent human review (PASSES)
python3 labs/L7-review-and-test-gates/check-merge-gate.py \
  --test-file labs/L7-review-and-test-gates/sample_strong_test.py \
  --author coder-agent-lab --reviewer senior-eng-02 --review-approved
```

## Expected Results

| Step | Expected Exit Code | Expected Outcome |
|---|---|---|
| 1. Raw `unittest` on weak test | `0` | Passes despite hidden bug |
| 2. Gate on weak test, no review | `1` | `MERGE BLOCKED` (review + AST fail) |
| 3. Gate on weak test, reviewed | `1` | `MERGE BLOCKED` (AST catches vacuous tests) |
| 4. Gate on strong test, reviewed | `0` | `MERGE ALLOWED` (all 4 gates pass) |
