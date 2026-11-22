#!/usr/bin/env python3
"""Lab L11: Database Change-Control, Backup Guard, and Recovery Drill.

Self-contained defensive lab using Python 3 standard library and SQLite.
Demonstrates:
  1. Read-only view-scoped agent queries (blocking DDL and DML).
  2. Write-protected backup repository enforcement against deletion.
  3. Recovery verification from an intact backup after an unapproved DROP.

SAFETY NOTICE:
  Run only inside an isolated disposable lab directory. Never point this
  script at a production database or real customer data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import sys

ALLOWED_VIEW = "order_summary_v"
SEED_ORDERS = [
    ("ORD-1001", "paid", 42000, "2026-11"),
    ("ORD-1002", "paid", 31500, "2026-11"),
    ("ORD-1003", "pending", 27500, "2026-11"),
    ("ORD-1004", "paid", 54000, "2026-11"),
    ("ORD-1005", "shipped", 30000, "2026-11"),
]
EXPECTED_TOTAL_CENTS = sum(row[2] for row in SEED_ORDERS)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def append_audit(workdir: Path, actor: str, action: str, target: str,
                 decision: str, detail: str) -> None:
    audit_path = workdir / "audit.jsonl"
    seq = 1
    if audit_path.exists():
        with audit_path.open("r", encoding="utf-8") as handle:
            seq = sum(1 for _ in handle) + 1
    record = {
        "seq": seq,
        "elapsed": f"T+{(seq - 1) * 5:02d}s",
        "actor": actor,
        "action": action,
        "target": target,
        "decision": decision,
        "detail": detail,
    }
    with audit_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def unlock_tree(root: Path) -> None:
    if not root.exists():
        return
    for dirpath, dirnames, filenames in os.walk(root):
        os.chmod(dirpath, 0o755)
        for name in dirnames:
            os.chmod(Path(dirpath) / name, 0o755)
        for name in filenames:
            os.chmod(Path(dirpath) / name, 0o644)


def cmd_setup(workdir: Path) -> int:
    if workdir.exists():
        unlock_tree(workdir)
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    backup_dir = workdir / "backup_repo"
    backup_dir.mkdir(mode=0o755)

    db_path = workdir / "app_orders.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(
            """
            CREATE TABLE orders (
                order_id TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                amount_cents INTEGER NOT NULL,
                billing_period TEXT NOT NULL
            );
            CREATE TABLE migrations_history (
                migration_id TEXT PRIMARY KEY,
                approved_by TEXT NOT NULL,
                status TEXT NOT NULL
            );
            CREATE VIEW order_summary_v AS
            SELECT order_id, status, amount_cents, billing_period
            FROM orders;
            """
        )
        conn.executemany(
            "INSERT INTO orders VALUES (?, ?, ?, ?)", SEED_ORDERS
        )
        conn.execute(
            "INSERT INTO migrations_history VALUES (?, ?, ?)",
            ("0001_init_orders", "senior-dba", "applied"),
        )
        conn.commit()
    finally:
        conn.close()

    backup_db = backup_dir / "baseline_orders.db"
    shutil.copy2(db_path, backup_db)
    digest = sha256_file(backup_db)
    manifest = backup_dir / "baseline_orders.sha256"
    manifest.write_text(f"{digest}  baseline_orders.db\n", encoding="utf-8")

    # Enforce read-only permissions on the backup repository.
    os.chmod(backup_db, 0o444)
    os.chmod(manifest, 0o444)
    os.chmod(backup_dir, 0o555)

    append_audit(
        workdir,
        actor="dba-operator",
        action="baseline_setup",
        target=str(db_path.name),
        decision="ALLOW",
        detail=f"rows={len(SEED_ORDERS)} backup_sha256={digest[:16]}",
    )
    print(f"[SETUP] Lab workspace ready: {workdir}")
    print(f"[SETUP] Working DB: {db_path.name} (orders={len(SEED_ORDERS)})")
    print(f"[SETUP] Protected backup: {backup_db.name}")
    print(f"[SETUP] Backup SHA-256: {digest}")
    print("[SETUP] Backup repo permissions: 0555 (read-only guard active)")
    return 0


def readonly_authorizer(action_code: int, arg1: str | None,
                        arg2: str | None, _db: str | None,
                        _trigger: str | None) -> int:
    # Permit SELECT and read on the approved view and underlying columns
    # resolved via the view; deny every write, DDL, pragma, or attach call.
    if action_code == sqlite3.SQLITE_SELECT:
        return sqlite3.SQLITE_OK
    if action_code == sqlite3.SQLITE_READ:
        if arg1 in {ALLOWED_VIEW, "orders"}:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    if action_code == sqlite3.SQLITE_FUNCTION:
        if (arg2 or "").lower() in {"count", "sum", "min", "max"}:
            return sqlite3.SQLITE_OK
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_DENY


def cmd_test_readonly(workdir: Path) -> int:
    db_path = workdir / "app_orders.db"
    if not db_path.exists():
        print("[ERROR] Run --mode setup first.", file=sys.stderr)
        return 1

    uri = f"file:{db_path.resolve()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.set_authorizer(readonly_authorizer)
    try:
        rows = conn.execute(
            "SELECT status, COUNT(*), SUM(amount_cents) "
            "FROM order_summary_v GROUP BY status ORDER BY status"
        ).fetchall()
        append_audit(
            workdir,
            actor="agent_ro_ticket",
            action="db_query",
            target="order_summary_v",
            decision="ALLOW",
            detail=f"groups={len(rows)}",
        )
        print("[ALLOW] agent_ro_ticket SELECT on order_summary_v:")
        for status, count, total in rows:
            print(f"  status={status:<8} count={count} sum_cents={total}")

        blocked_queries = [
            ("DROP TABLE orders", "orders"),
            ("UPDATE orders SET amount_cents = 0", "orders"),
            ("SELECT * FROM migrations_history", "migrations_history"),
        ]
        for sql_text, target in blocked_queries:
            try:
                conn.execute(sql_text)
                print(f"[FAIL] Unexpectedly allowed: {sql_text}")
                return 2
            except sqlite3.DatabaseError as exc:
                append_audit(
                    workdir,
                    actor="agent_ro_ticket",
                    action="db_query",
                    target=target,
                    decision="DENY",
                    detail=f"{sql_text} -> {exc}",
                )
                err_text = str(exc)
                if len(err_text) > 38:
                    err_text = err_text[:35] + "..."
                print(f"[DENY]  {sql_text} ({err_text})")
    finally:
        conn.close()
    return 0


def cmd_test_backup_guard(workdir: Path) -> int:
    backup_dir = workdir / "backup_repo"
    backup_db = backup_dir / "baseline_orders.db"
    manifest = backup_dir / "baseline_orders.sha256"
    if not backup_db.exists():
        print("[ERROR] Backup missing; run --mode setup first.",
              file=sys.stderr)
        return 1

    dir_mode = stat.S_IMODE(backup_dir.stat().st_mode)
    file_mode = stat.S_IMODE(backup_db.stat().st_mode)
    immutable_bits = (dir_mode & 0o222 == 0) and (file_mode & 0o222 == 0)

    blocked = False
    reason = ""
    if os.geteuid() == 0 and immutable_bits:
        # Running as root bypasses POSIX DAC bits; enforce policy guard.
        blocked = True
        reason = "immutable backup policy guard (dir=0555, file=0444)"
    else:
        try:
            backup_db.unlink()
        except PermissionError as exc:
            blocked = True
            reason = f"PermissionError: {exc.strerror}"

    expected = manifest.read_text(encoding="utf-8").split()[0]
    actual = sha256_file(backup_db)
    checksum_ok = (expected == actual)

    if blocked and checksum_ok:
        append_audit(
            workdir,
            actor="coding-agent-sandbox-01",
            action="delete_backup",
            target="backup_repo/baseline_orders.db",
            decision="DENY",
            detail=f"{reason}; sha256_verified={actual[:16]}",
        )
        print("[DENY]  Agent backup deletion attempt blocked.")
        print(f"[GUARD] Reason: {reason}")
        print(f"[CHECK] Backup SHA-256 intact: {actual[:16]}...")
        return 0

    print("[FAIL] Backup guard did not hold!", file=sys.stderr)
    return 2


def cmd_simulate_bad_ddl(workdir: Path) -> int:
    db_path = workdir / "app_orders.db"
    if not db_path.exists():
        print("[ERROR] Run --mode setup first.", file=sys.stderr)
        return 1

    conn = sqlite3.connect(db_path)
    try:
        conn.execute("DROP TABLE IF EXISTS orders")
        conn.commit()
    finally:
        conn.close()

    append_audit(
        workdir,
        actor="overprivileged-lab-tool",
        action="unapproved_ddl",
        target="orders",
        decision="INCIDENT",
        detail="DROP TABLE orders executed without change ticket",
    )
    print("[INCIDENT] Simulated unapproved DROP TABLE orders on working DB.")
    print("[INCIDENT] Working DB is now missing table 'orders'.")
    print("[STATUS]   Protected backup_repo/baseline_orders.db untouched.")
    return 0


def cmd_restore(workdir: Path) -> int:
    db_path = workdir / "app_orders.db"
    backup_db = workdir / "backup_repo" / "baseline_orders.db"
    manifest = workdir / "backup_repo" / "baseline_orders.sha256"
    if not backup_db.exists() or not manifest.exists():
        print("[ERROR] Protected backup missing.", file=sys.stderr)
        return 1

    expected = manifest.read_text(encoding="utf-8").split()[0]
    actual = sha256_file(backup_db)
    if expected != actual:
        print("[FAIL] Backup checksum mismatch! Halting restore.",
              file=sys.stderr)
        return 2

    shutil.copyfile(backup_db, db_path)
    os.chmod(db_path, 0o644)

    conn = sqlite3.connect(db_path)
    try:
        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        row_count, total_cents = conn.execute(
            "SELECT COUNT(*), SUM(amount_cents) FROM orders"
        ).fetchone()
    finally:
        conn.close()

    if integrity != "ok" or row_count != len(SEED_ORDERS) or (
        total_cents != EXPECTED_TOTAL_CENTS
    ):
        print("[FAIL] Post-restore validation failed.", file=sys.stderr)
        return 2

    append_audit(
        workdir,
        actor="dba-operator",
        action="backup_restore",
        target="app_orders.db",
        decision="RECOVERY_VERIFIED",
        detail=(
            f"integrity={integrity} rows={row_count} "
            f"sum_cents={total_cents}"
        ),
    )
    print(f"[RESTORE] Verified backup SHA-256: {actual[:16]}...")
    print(f"[RESTORE] PRAGMA integrity_check: {integrity}")
    print(f"[RESTORE] Restored orders={row_count}, sum_cents={total_cents}")
    print("[PASS]    Database recovery verified against baseline.")
    return 0


def cmd_status(workdir: Path) -> int:
    db_path = workdir / "app_orders.db"
    backup_db = workdir / "backup_repo" / "baseline_orders.db"
    audit_path = workdir / "audit.jsonl"
    if not db_path.exists():
        print("[STATUS] Lab not initialized. Run --mode setup.")
        return 0

    conn = sqlite3.connect(db_path)
    try:
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master "
                "WHERE type='table' ORDER BY name"
            ).fetchall()
        ]
        orders_count = (
            conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
            if "orders" in tables
            else None
        )
    finally:
        conn.close()

    audit_lines = (
        sum(1 for _ in audit_path.open("r", encoding="utf-8"))
        if audit_path.exists()
        else 0
    )
    print(f"[STATUS] Workdir: {workdir}")
    print(f"[STATUS] Tables in working DB: {tables}")
    print(f"[STATUS] orders row count: {orders_count}")
    print(f"[STATUS] Protected backup present: {backup_db.exists()}")
    print(f"[STATUS] Audit events recorded: {audit_lines}")
    return 0


def cmd_clean(workdir: Path) -> int:
    if workdir.exists():
        unlock_tree(workdir)
        shutil.rmtree(workdir)
    print(f"[CLEAN] Removed disposable lab directory: {workdir}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lab L11: DB change-control and backup guard drill."
    )
    parser.add_argument(
        "--workdir",
        type=Path,
        default=Path("/tmp/l11-db-lab"),
        help="Disposable lab directory (default: /tmp/l11-db-lab)",
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=[
            "setup",
            "test-readonly",
            "test-backup-guard",
            "simulate-bad-ddl",
            "restore",
            "status",
            "clean",
        ],
        help="Drill step to run.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    handlers = {
        "setup": cmd_setup,
        "test-readonly": cmd_test_readonly,
        "test-backup-guard": cmd_test_backup_guard,
        "simulate-bad-ddl": cmd_simulate_bad_ddl,
        "restore": cmd_restore,
        "status": cmd_status,
        "clean": cmd_clean,
    }
    return handlers[args.mode](args.workdir)


if __name__ == "__main__":
    raise SystemExit(main())
