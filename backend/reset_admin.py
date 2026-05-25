"""
Run this script to reset the admin (and optionally analyst) password.
Works locally and on Render (use the Render Shell tab to run it).

    python reset_admin.py
    python reset_admin.py --admin-password MyNewPass123! --analyst-password Analyst456!
"""

import argparse
import os
import sys
import sqlite3
import bcrypt
from pathlib import Path

DB_PATH = os.environ.get("DATABASE_URL", "cybrain.db")
# If DATABASE_URL starts with sqlite:/// strip it
if DB_PATH.startswith("sqlite:///"):
    DB_PATH = DB_PATH[10:]

def reset_password(username: str, new_password: str, conn: sqlite3.Connection) -> bool:
    pw_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt(12)).decode()
    cur = conn.execute(
        "UPDATE users SET password_hash=? WHERE username=?",
        (pw_hash, username),
    )
    conn.commit()
    return cur.rowcount > 0

def create_admin_if_missing(username: str, password: str, role: str, conn: sqlite3.Connection):
    import json
    from datetime import datetime, timezone
    exists = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if exists:
        return False
    perms = (
        json.dumps(["run_scan", "view_reports", "delete_reports", "manage_users", "view_audit"])
        if role == "admin"
        else json.dumps(["run_scan", "view_reports"])
    )
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO users (username,password_hash,role,permissions,is_active,created_at,created_by)"
        " VALUES (?,?,?,?,1,?,?)",
        (username, pw_hash, role, perms, now, "reset_script"),
    )
    conn.commit()
    return True

def main():
    parser = argparse.ArgumentParser(description="Reset CyBrain admin/analyst passwords")
    parser.add_argument("--admin-password",   default="Admin@2024!",   help="New admin password")
    parser.add_argument("--analyst-password", default="Analyst@2024!", help="New analyst password")
    parser.add_argument("--db",               default=DB_PATH,          help="Path to SQLite DB")
    args = parser.parse_args()

    db_path = args.db
    if not Path(db_path).exists():
        print(f"[!] Database not found at: {db_path}")
        print("    Make sure the Flask app has been started at least once to create the DB.")
        sys.exit(1)

    conn = sqlite3.connect(db_path)

    for username, password, role in [
        ("admin",   args.admin_password,   "admin"),
        ("analyst", args.analyst_password, "analyst"),
    ]:
        created = create_admin_if_missing(username, password, role, conn)
        if created:
            print(f"[+] Created missing user '{username}' with role '{role}'")
        else:
            ok = reset_password(username, password, conn)
            status = "OK" if ok else "NOT FOUND"
            print(f"[{'✓' if ok else '!'}] Reset password for '{username}': {status}")

    print()
    print("=" * 50)
    print(f"  Admin login   : admin / {args.admin_password}")
    print(f"  Analyst login : analyst / {args.analyst_password}")
    print("=" * 50)
    print()
    print("Restart the Flask app after running this script.")

    conn.close()

if __name__ == "__main__":
    main()
