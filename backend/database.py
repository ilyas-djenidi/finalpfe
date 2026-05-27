import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone

import bcrypt

logger = logging.getLogger(__name__)

# Allow overriding DB location via env var (e.g. Render Persistent Disk).
# If the requested path is not accessible, fall back to cybrain.db in cwd.
import os as _os

def _resolve_db_path(requested: str) -> str:
    parent = _os.path.dirname(_os.path.abspath(requested))
    if parent:
        try:
            _os.makedirs(parent, exist_ok=True)
            return requested          # parent exists (or was just created) — use it
        except OSError:
            pass                      # permission denied / disk not mounted
    # Fallback: store next to this file (always writable on Render)
    fallback = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "cybrain.db")
    logger.warning(
        "DB path '%s' is not accessible — falling back to '%s'. "
        "Mount the persistent disk or remove DB_PATH from env vars.",
        requested, fallback,
    )
    return fallback

DB_PATH = _resolve_db_path(_os.environ.get("DB_PATH", "cybrain.db"))

# Sentinel — distinguishes "caller didn't pass locked_target_value" from passing None (clear it)
_UNSET = object()

# ── Thread-local connection pool ──────────────────────────────────────────────
_local = threading.local()


def _get_db() -> sqlite3.Connection:
    if not getattr(_local, "conn", None):
        conn = sqlite3.connect(DB_PATH, check_same_thread=True)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        _local.conn = conn
    return _local.conn


def _exec(sql: str, params: tuple = ()) -> sqlite3.Cursor:
    db = _get_db()
    try:
        cur = db.execute(sql, params)
        db.commit()
        return cur
    except Exception as exc:
        db.rollback()
        logger.error("DB error | sql=%s | params=%s | err=%s", sql[:80], params, exc)
        raise


# ── Schema bootstrap ──────────────────────────────────────────────────────────

def init_db():
    db = _get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            username         TEXT    UNIQUE NOT NULL,
            password_hash    TEXT    NOT NULL,
            role             TEXT    NOT NULL DEFAULT 'analyst',
            permissions      TEXT    NOT NULL DEFAULT '[]',
            is_active        INTEGER NOT NULL DEFAULT 1,
            totp_secret      TEXT,
            totp_enabled     INTEGER NOT NULL DEFAULT 0,
            failed_attempts  INTEGER NOT NULL DEFAULT 0,
            locked_until     TEXT,
            last_login       TEXT,
            login_count      INTEGER NOT NULL DEFAULT 0,
            created_at       TEXT    NOT NULL,
            created_by       TEXT
        );

        CREATE TABLE IF NOT EXISTS scan_reports (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            token            TEXT    UNIQUE NOT NULL,
            user_id          INTEGER,
            username         TEXT,
            scan_type        TEXT,
            target           TEXT,
            risk_score       REAL    NOT NULL DEFAULT 0,
            vuln_count       INTEGER NOT NULL DEFAULT 0,
            critical_count   INTEGER NOT NULL DEFAULT 0,
            high_count       INTEGER NOT NULL DEFAULT 0,
            medium_count     INTEGER NOT NULL DEFAULT 0,
            low_count        INTEGER NOT NULL DEFAULT 0,
            result_json      TEXT    NOT NULL,
            original_content TEXT,
            stored_at        TEXT    NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED
        );

        CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id   INTEGER NOT NULL,
            check_name  TEXT    NOT NULL,
            severity    TEXT    NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
            title       TEXT    NOT NULL,
            description TEXT,
            evidence    TEXT,
            remediation TEXT,
            line_number INTEGER NOT NULL DEFAULT 0,
            cve_ids     TEXT    NOT NULL DEFAULT '[]',
            is_fixed    INTEGER NOT NULL DEFAULT 0,
            fixed_at    TEXT,
            found_at    TEXT    NOT NULL,
            FOREIGN KEY (report_id) REFERENCES scan_reports(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS audit_logs (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            action       TEXT    NOT NULL,
            username     TEXT,
            user_id      INTEGER,
            category     TEXT    NOT NULL DEFAULT 'general',
            resource     TEXT,
            ip_address   TEXT,
            user_agent   TEXT,
            status       TEXT,
            details      TEXT,
            created_at   TEXT    NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_users_username        ON users (username);
        CREATE INDEX IF NOT EXISTS idx_scan_reports_user     ON scan_reports (user_id, stored_at DESC);
        CREATE INDEX IF NOT EXISTS idx_scan_reports_token    ON scan_reports (token);
        CREATE INDEX IF NOT EXISTS idx_scan_reports_stored   ON scan_reports (stored_at DESC);
        CREATE INDEX IF NOT EXISTS idx_scan_reports_type     ON scan_reports (scan_type);
        CREATE INDEX IF NOT EXISTS idx_vulns_report          ON scan_vulnerabilities (report_id);
        CREATE INDEX IF NOT EXISTS idx_vulns_severity        ON scan_vulnerabilities (severity, report_id);
        CREATE INDEX IF NOT EXISTS idx_vulns_check           ON scan_vulnerabilities (check_name);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_user       ON audit_logs (user_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_action     ON audit_logs (action);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_category   ON audit_logs (category);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_time       ON audit_logs (created_at DESC);
    """)
    db.commit()

    # Built-in migrations for existing databases
    for migration in [
        "ALTER TABLE users ADD COLUMN totp_secret TEXT",
        "ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN last_login TEXT",
        "ALTER TABLE users ADD COLUMN login_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN locked_until TEXT",
        "ALTER TABLE users ADD COLUMN locked_target TEXT",
    ]:
        try:
            db.execute(migration)
            db.commit()
        except sqlite3.OperationalError:
            pass  # column already exists

    _bootstrap_admin()
    logger.info("database ready | path=%s", DB_PATH)


def _bootstrap_admin():
    """Create default admin + analyst if the users table is empty."""
    import os
    count = _get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count > 0:
        return

    admin_pw   = os.environ.get("CYBRAIN_ADMIN_PASSWORD",   "").strip() or "Admin@2024!"
    analyst_pw = os.environ.get("CYBRAIN_ANALYST_PASSWORD", "").strip() or "Analyst@2024!"

    now = datetime.now(timezone.utc).isoformat()
    for username, password, role in [
        ("admin",   admin_pw,   "admin"),
        ("analyst", analyst_pw, "analyst"),
    ]:
        perms = (
            json.dumps(["run_scan", "view_reports", "delete_reports", "manage_users", "view_audit"])
            if role == "admin"
            else json.dumps(["run_scan", "view_reports"])
        )
        pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        try:
            _get_db().execute(
                "INSERT INTO users (username,password_hash,role,permissions,is_active,created_at,created_by)"
                " VALUES (?,?,?,?,1,?,?)",
                (username, pw_hash, role, perms, now, "bootstrap"),
            )
        except sqlite3.IntegrityError:
            pass
    _get_db().commit()
    logger.warning(
        "bootstrapped default accounts — change passwords immediately | admin=%s | analyst=%s",
        admin_pw, analyst_pw,
    )


# ── Helpers ───────────────────────────────────────────────────────────────────

def _norm(row) -> dict | None:
    if not row:
        return None
    d = dict(row)
    if "permissions" in d and isinstance(d.get("permissions"), str):
        try:
            d["permissions"] = json.loads(d["permissions"])
        except (ValueError, TypeError):
            d["permissions"] = []
    elif not isinstance(d.get("permissions"), list):
        d["permissions"] = []
    return d


def _count_severities(vulns: list) -> tuple[int, int, int, int]:
    c = h = m = l = 0
    for v in vulns:
        s = (v.get("severity") or "info").lower()
        if s == "critical":
            c += 1
        elif s == "high":
            h += 1
        elif s == "medium":
            m += 1
        elif s == "low":
            l += 1
    return c, h, m, l


# ── User functions ────────────────────────────────────────────────────────────

def get_user_by_username(username: str) -> dict | None:
    row = _get_db().execute(
        "SELECT * FROM users WHERE username=? AND is_active=1", (username,)
    ).fetchone()
    return _norm(row)


def get_user_by_id(user_id: int) -> dict | None:
    row = _get_db().execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return _norm(row)


def get_all_users(page: int = 1, per_page: int = 100) -> list[dict]:
    offset = (page - 1) * per_page
    return [
        _norm(r) for r in _get_db().execute(
            "SELECT * FROM users ORDER BY id LIMIT ? OFFSET ?", (per_page, offset)
        ).fetchall()
    ]


def count_users() -> int:
    return _get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0]


def create_user(username: str, password: str, role: str = "analyst",
                permissions=None, created_by: str | None = None,
                allowed_target: str | None = None) -> tuple[bool, str]:
    if permissions is None:
        permissions = (
            ["run_scan", "view_reports", "delete_reports", "manage_users", "view_audit"]
            if role == "admin"
            else ["run_scan", "view_reports"]
        )
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    now = datetime.now(timezone.utc).isoformat()
    # allowed_target → stored in locked_target column
    target_val = allowed_target.strip().lower() if allowed_target and allowed_target.strip() else None
    try:
        _exec(
            "INSERT INTO users (username,password_hash,role,permissions,is_active,created_at,created_by,locked_target)"
            " VALUES (?,?,?,?,1,?,?,?)",
            (username, pw_hash, role, json.dumps(permissions), now, created_by, target_val),
        )
        return True, "User created successfully."
    except sqlite3.IntegrityError:
        return False, "Username already exists."
    except Exception as exc:
        logger.error("create_user: %s", exc)
        return False, "Database error."


def update_user(uid: int, role=None, permissions=None, is_active=None,
                new_password=None, failed_attempts=None, locked_until=None,
                reset_locked_target=False, locked_target_value=_UNSET, **_) -> tuple[bool, str]:
    fields, values = [], []
    if role            is not None: fields.append("role=?");             values.append(role)
    if permissions     is not None: fields.append("permissions=?");      values.append(json.dumps(permissions))
    if is_active       is not None: fields.append("is_active=?");        values.append(int(is_active))
    if new_password    is not None:
        ph = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        fields.append("password_hash=?"); values.append(ph)
    if failed_attempts is not None: fields.append("failed_attempts=?");  values.append(failed_attempts)
    if locked_until    is not None: fields.append("locked_until=?");     values.append(locked_until)
    if reset_locked_target:
        fields.append("locked_target=?"); values.append(None)
    elif locked_target_value is not _UNSET:
        # Admin explicitly setting a target (None = clear, str = set)
        fields.append("locked_target=?"); values.append(locked_target_value)
    if not fields:
        return True, ""
    values.append(uid)
    _exec(f"UPDATE users SET {', '.join(fields)} WHERE id=?", tuple(values))
    return True, "Updated successfully."


def update_last_login(user_id: int):
    _exec(
        "UPDATE users SET last_login=?, login_count=login_count+1 WHERE id=?",
        (datetime.now(timezone.utc).isoformat(), user_id),
    )


def get_locked_target(user_id: int) -> str | None:
    """Return the target (hostname/IP) that this analyst is locked to, or None if unset."""
    row = _get_db().execute(
        "SELECT locked_target FROM users WHERE id=?", (user_id,)
    ).fetchone()
    return row["locked_target"] if row else None


def set_locked_target(user_id: int, target: str) -> None:
    """Lock an analyst account to a specific target on their first scan."""
    _exec("UPDATE users SET locked_target=? WHERE id=?", (target, user_id))


def update_user_totp(user_id: int, secret: str, enabled: bool) -> tuple[bool, str]:
    _exec("UPDATE users SET totp_secret=?, totp_enabled=? WHERE id=?",
          (secret, int(enabled), user_id))
    return True, ""


def delete_user(uid: int) -> tuple[bool, str]:
    """Soft delete — deactivates the user without removing the record."""
    _exec("UPDATE users SET is_active=0 WHERE id=?", (uid,))
    return True, "User deactivated."


def hard_delete_user(uid: int) -> tuple[bool, str]:
    _exec("DELETE FROM users WHERE id=?", (uid,))
    return True, "User deleted."


def count_active_admins() -> int:
    return _get_db().execute(
        "SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1"
    ).fetchone()[0]


# ── Audit log ─────────────────────────────────────────────────────────────────

def log_event(action: str, username: str = "", user_id: int | None = None,
              category: str = "general", resource: str = "", ip_address: str = "",
              user_agent: str = "", status: str = "success", details: str = "", **_):
    try:
        _exec(
            "INSERT INTO audit_logs"
            " (action,username,user_id,category,resource,ip_address,user_agent,status,details,created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (action, username, user_id, category, resource, ip_address,
             user_agent, status, details, datetime.now(timezone.utc).isoformat()),
        )
    except Exception as exc:
        logger.warning("log_event failed: %s", exc)


def get_audit_log(user_id: int | None = None, category: str | None = None,
                  action: str | None = None, limit: int = 200,
                  date_from: str | None = None, date_to: str | None = None,
                  page: int = 1, per_page: int | None = None) -> tuple[list[dict], int]:
    clauses, params = [], []
    if user_id   is not None: clauses.append("user_id=?");         params.append(user_id)
    if category:              clauses.append("category=?");         params.append(category)
    if action:                clauses.append("action LIKE ?");      params.append(f"%{action}%")
    if date_from:             clauses.append("created_at >= ?");    params.append(date_from)
    if date_to:               clauses.append("created_at <= ?");    params.append(date_to)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    db    = _get_db()
    total = db.execute(f"SELECT COUNT(*) FROM audit_logs {where}", params).fetchone()[0]
    if per_page:
        offset = (max(page, 1) - 1) * per_page
        rows = db.execute(
            f"SELECT * FROM audit_logs {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            params + [per_page, offset],
        ).fetchall()
    else:
        rows = db.execute(
            f"SELECT * FROM audit_logs {where} ORDER BY created_at DESC LIMIT ?",
            params + [limit],
        ).fetchall()
    return [dict(r) for r in rows], total


def get_audit_stats() -> dict:
    db = _get_db()
    total  = db.execute("SELECT COUNT(*) FROM audit_logs").fetchone()[0]
    failed = db.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE status='failed'"
    ).fetchone()[0]
    by_cat = db.execute(
        "SELECT category, COUNT(*) as c FROM audit_logs GROUP BY category ORDER BY c DESC"
    ).fetchall()
    recent = db.execute(
        "SELECT username, action, created_at FROM audit_logs "
        "WHERE category='auth' ORDER BY created_at DESC LIMIT 10"
    ).fetchall()
    return {
        "total_events":  total,
        "failed_events": failed,
        "by_category":   [{"category": r["category"], "count": r["c"]} for r in by_cat],
        "recent_logins": [dict(r) for r in recent],
    }


# ── Report functions ──────────────────────────────────────────────────────────

def store_report(result: dict, risk_score: float, original_content: str | None,
                 user_id: int, username: str) -> str:
    token = uuid.uuid4().hex
    vulns = result.get("vulnerabilities", [])
    c, h, m, l = _count_severities(vulns)
    now = datetime.now(timezone.utc).isoformat()
    db = _get_db()
    try:
        cursor = db.execute(
            "INSERT INTO scan_reports"
            " (token,user_id,username,scan_type,target,risk_score,vuln_count,"
            "  critical_count,high_count,medium_count,low_count,result_json,original_content,stored_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (token, user_id, username,
             result.get("scan_type", ""), result.get("target", ""),
             risk_score, len(vulns), c, h, m, l,
             json.dumps(result), original_content, now),
        )
        report_id = cursor.lastrowid

        for vuln in vulns:
            sev = (str(vuln.get("severity", "low")).strip().lower() or "low")
            if sev not in {"critical", "high", "medium", "low", "info"}:
                sev = "low"
            raw_cves = vuln.get("cve_ids", [])
            if isinstance(raw_cves, str):
                cve_list = [c.strip() for c in raw_cves.split(",") if c.strip()]
            elif isinstance(raw_cves, list):
                cve_list = [str(c).strip() for c in raw_cves if str(c).strip()]
            else:
                cve_list = []
            db.execute(
                "INSERT INTO scan_vulnerabilities"
                " (report_id,check_name,severity,title,description,evidence,"
                "  remediation,line_number,cve_ids,is_fixed,fixed_at,found_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,0,NULL,?)",
                (
                    report_id,
                    str(vuln.get("check", "unknown_check")),
                    sev,
                    str(vuln.get("title", "Untitled finding")),
                    str(vuln.get("description", "")),
                    str(vuln.get("evidence", "")),
                    str(vuln.get("remediation", "")),
                    int(vuln.get("line_number", 0) or 0),
                    json.dumps(cve_list),
                    now,
                ),
            )
        db.commit()
    except Exception:
        db.rollback()
        raise
    return token


def get_report(token: str) -> dict | None:
    row = _get_db().execute("SELECT * FROM scan_reports WHERE token=?", (token,)).fetchone()
    if not row:
        return None
    d = dict(row)
    d["result"] = json.loads(d["result_json"])
    return d


def get_user_reports(user_id: int, limit: int = 100) -> list[dict]:
    return [dict(r) for r in _get_db().execute(
        "SELECT token,user_id,username,scan_type,target,risk_score,vuln_count,"
        "critical_count,high_count,medium_count,low_count,stored_at"
        " FROM scan_reports WHERE user_id=? ORDER BY stored_at DESC LIMIT ?",
        (user_id, limit),
    ).fetchall()]


def get_all_reports(limit: int = 200, date_from: str | None = None,
                    date_to: str | None = None, scan_type: str | None = None,
                    username: str | None = None) -> list[dict]:
    clauses, params = [], []
    if date_from: clauses.append("stored_at >= ?");  params.append(date_from)
    if date_to:   clauses.append("stored_at <= ?");  params.append(date_to)
    if scan_type: clauses.append("scan_type=?");     params.append(scan_type)
    if username:  clauses.append("username LIKE ?"); params.append(f"%{username}%")
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    return [dict(r) for r in _get_db().execute(
        f"SELECT * FROM scan_reports {where} ORDER BY stored_at DESC LIMIT ?", params
    ).fetchall()]


def delete_report(token: str) -> tuple[bool, str]:
    _exec("DELETE FROM scan_reports WHERE token=?", (token,))
    return True, "Report deleted."


# ── Dashboard stats ───────────────────────────────────────────────────────────

def get_dashboard_stats(user_id: int) -> dict:
    db = _get_db()
    total       = db.execute("SELECT COUNT(*) FROM scan_reports WHERE user_id=?", (user_id,)).fetchone()[0]
    avg         = db.execute("SELECT AVG(risk_score) FROM scan_reports WHERE user_id=?", (user_id,)).fetchone()[0] or 0
    total_vulns = db.execute("SELECT SUM(vuln_count) FROM scan_reports WHERE user_id=?", (user_id,)).fetchone()[0] or 0
    critical    = db.execute("SELECT SUM(critical_count) FROM scan_reports WHERE user_id=?", (user_id,)).fetchone()[0] or 0
    high        = db.execute("SELECT SUM(high_count) FROM scan_reports WHERE user_id=?", (user_id,)).fetchone()[0] or 0
    rows        = db.execute(
        "SELECT scan_type, COUNT(*) as c FROM scan_reports WHERE user_id=? GROUP BY scan_type",
        (user_id,),
    ).fetchall()
    recent      = db.execute(
        "SELECT risk_score FROM scan_reports WHERE user_id=? ORDER BY stored_at DESC LIMIT 10",
        (user_id,),
    ).fetchall()
    return {
        "total_scans":    total,
        "total_vulns":    int(total_vulns),
        "critical_count": int(critical),
        "high_count":     int(high),
        "avg_risk_score": round(float(avg), 1),
        "by_type":        [{"type": r["scan_type"], "count": r["c"]} for r in rows],
        "recent_scores":  [r["risk_score"] for r in recent],
    }


def get_all_dashboard_stats() -> dict:
    db = _get_db()
    total       = db.execute("SELECT COUNT(*) FROM scan_reports").fetchone()[0]
    avg         = db.execute("SELECT AVG(risk_score) FROM scan_reports").fetchone()[0] or 0
    total_vulns = db.execute("SELECT SUM(vuln_count) FROM scan_reports").fetchone()[0] or 0
    critical    = db.execute("SELECT SUM(critical_count) FROM scan_reports").fetchone()[0] or 0
    high        = db.execute("SELECT SUM(high_count) FROM scan_reports").fetchone()[0] or 0
    rows        = db.execute(
        "SELECT scan_type, COUNT(*) as c FROM scan_reports GROUP BY scan_type"
    ).fetchall()
    recent      = db.execute(
        "SELECT risk_score FROM scan_reports ORDER BY stored_at DESC LIMIT 10"
    ).fetchall()
    return {
        "total_scans":    total,
        "total_vulns":    int(total_vulns),
        "critical_count": int(critical),
        "high_count":     int(high),
        "avg_risk_score": round(float(avg), 1),
        "by_type":        [{"type": r["scan_type"], "count": r["c"]} for r in rows],
        "recent_scores":  [r["risk_score"] for r in recent],
    }


def get_system_stats() -> dict:
    db   = _get_db()
    now  = datetime.now(timezone.utc)
    today = now.date().isoformat()

    # ── Basic counts ──────────────────────────────────────────────────────────
    total_users  = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active_users = db.execute("SELECT COUNT(*) FROM users WHERE is_active=1").fetchone()[0]
    total_scans  = db.execute("SELECT COUNT(*) FROM scan_reports").fetchone()[0]
    total_vulns  = db.execute("SELECT SUM(vuln_count) FROM scan_reports").fetchone()[0] or 0
    critical     = db.execute("SELECT SUM(critical_count) FROM scan_reports").fetchone()[0] or 0
    today_scans  = db.execute(
        "SELECT COUNT(*) FROM scan_reports WHERE stored_at LIKE ?", (f"{today}%",)
    ).fetchone()[0]

    # ── This week ─────────────────────────────────────────────────────────────
    week_scans = db.execute(
        "SELECT COUNT(*) FROM scan_reports WHERE stored_at >= date('now','-7 days')"
    ).fetchone()[0]

    # ── Failed logins today ───────────────────────────────────────────────────
    failed_logins = db.execute(
        "SELECT COUNT(*) FROM audit_logs WHERE action='login_failed' AND created_at LIKE ?",
        (f"{today}%",),
    ).fetchone()[0]

    # ── Risk distribution ─────────────────────────────────────────────────────
    risk_row = db.execute(
        "SELECT "
        "  SUM(CASE WHEN risk_score >= 9.0 THEN 1 ELSE 0 END) as critical,"
        "  SUM(CASE WHEN risk_score >= 7.0 AND risk_score < 9.0 THEN 1 ELSE 0 END) as high,"
        "  SUM(CASE WHEN risk_score >= 4.0 AND risk_score < 7.0 THEN 1 ELSE 0 END) as medium,"
        "  SUM(CASE WHEN risk_score >= 1.0 AND risk_score < 4.0 THEN 1 ELSE 0 END) as low,"
        "  SUM(CASE WHEN risk_score < 1.0 THEN 1 ELSE 0 END) as minimal "
        "FROM scan_reports"
    ).fetchone()
    risk_distribution = {
        "critical": int(risk_row["critical"] or 0),
        "high":     int(risk_row["high"]     or 0),
        "medium":   int(risk_row["medium"]   or 0),
        "low":      int(risk_row["low"]      or 0),
        "minimal":  int(risk_row["minimal"]  or 0),
    }

    # ── Top scan types ────────────────────────────────────────────────────────
    top_scan_types = [
        {"type": r["scan_type"], "count": r["c"]}
        for r in db.execute(
            "SELECT scan_type, COUNT(*) as c FROM scan_reports "
            "GROUP BY scan_type ORDER BY c DESC"
        ).fetchall()
    ]

    # ── Recent scans (last 10) ────────────────────────────────────────────────
    recent_scans = [
        dict(r) for r in db.execute(
            "SELECT token,username,scan_type,target,risk_score,vuln_count,stored_at "
            "FROM scan_reports ORDER BY stored_at DESC LIMIT 10"
        ).fetchall()
    ]

    # ── Top scanners ──────────────────────────────────────────────────────────
    top_scanners = db.execute(
        "SELECT username, COUNT(*) as c FROM scan_reports "
        "GROUP BY username ORDER BY c DESC LIMIT 5"
    ).fetchall()

    # ── Recent events ─────────────────────────────────────────────────────────
    recent_events = db.execute(
        "SELECT action, username, created_at FROM audit_logs "
        "ORDER BY created_at DESC LIMIT 10"
    ).fetchall()

    # ── Users list (for admin user management) ────────────────────────────────
    users_list = [_norm(r) for r in db.execute("SELECT * FROM users ORDER BY id").fetchall()]

    return {
        "total_users":       total_users,
        "active_users":      active_users,
        "total_scans":       total_scans,
        "today_scans":       today_scans,
        "scans_this_week":   week_scans,
        "total_vulns":       int(total_vulns),
        "critical_vulns":    int(critical),
        "failed_logins":     failed_logins,
        "risk_distribution": risk_distribution,
        "top_scan_types":    top_scan_types,
        "recent_scans":      recent_scans,
        "recent_events":     [dict(r) for r in recent_events],
        "top_scanners":      [{"username": r["username"], "count": r["c"]} for r in top_scanners],
        "users_list":        users_list,
    }


def get_top_vulnerabilities(limit: int = 10) -> list[dict]:
    """Return the most frequent vulnerability check_names from the dedicated table."""
    rows = _get_db().execute(
        "SELECT check_name, severity, COUNT(*) AS count"
        " FROM scan_vulnerabilities"
        " GROUP BY check_name, severity"
        " ORDER BY count DESC"
        " LIMIT ?",
        (limit,),
    ).fetchall()
    if rows:
        return [{"check_name": r["check_name"], "severity": r["severity"], "count": r["count"]}
                for r in rows]
    # Fallback: parse result_json for databases that predate the scan_vulnerabilities table
    result_rows = _get_db().execute(
        "SELECT result_json FROM scan_reports ORDER BY stored_at DESC LIMIT 100"
    ).fetchall()
    counts: dict[str, dict] = {}
    for row in result_rows:
        try:
            vulns = json.loads(row["result_json"]).get("vulnerabilities", [])
        except (ValueError, TypeError):
            continue
        for v in vulns:
            title = (v.get("title") or v.get("check") or "Unknown")[:80]
            sev   = (v.get("severity") or "info").lower()
            if title not in counts:
                counts[title] = {"title": title, "severity": sev, "count": 0}
            counts[title]["count"] += 1
    ordered = sorted(counts.values(), key=lambda x: x["count"], reverse=True)
    return ordered[:limit]
