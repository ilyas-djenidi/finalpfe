# database.py
"""
CyBrain — Supabase PostgreSQL Persistence Layer
================================================
Replaces the old SQLite backend.
All function signatures are identical to the original so the rest of the
codebase (app.py, models.py) needs no changes beyond the import.

Setup:
  1. Run supabase_schema.sql in the Supabase SQL Editor (once).
  2. Set SUPABASE_URL and SUPABASE_SERVICE_KEY in .env.
"""

import json
import logging
import os
import secrets
import string
import uuid
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_client = None


def _get_db():
    global _client
    if _client is None:
        from supabase import create_client
        url = os.environ.get("SUPABASE_URL", "").strip()
        key = os.environ.get("SUPABASE_SERVICE_KEY", "").strip()
        if not url or not key:
            raise RuntimeError(
                "SUPABASE_URL and SUPABASE_SERVICE_KEY must be set in .env"
            )
        _client = create_client(url, key)
        logger.info("Supabase connected | url=%s", url[:40])
    return _client


# ── Schema / seed ─────────────────────────────────────────────────────────────

def init_db() -> None:
    """Verify connection and seed default users if the table is empty."""
    try:
        db    = _get_db()
        resp  = db.table("users").select("id", count="exact").execute()
        count = resp.count or 0
        logger.info("Supabase ready | users=%d", count)
        if count == 0:
            _seed_default_users(db)
    except Exception as exc:
        logger.error("Supabase init failed: %s", exc)
        raise


def _seed_default_users(db) -> None:
    import bcrypt
    admin_pw   = os.environ.get("CYBRAIN_ADMIN_PASSWORD", "").strip()
    analyst_pw = os.environ.get("CYBRAIN_ANALYST_PASSWORD", "").strip()
    if not admin_pw:
        alpha = string.ascii_letters + string.digits + "!@#$%^&*"
        admin_pw = "".join(secrets.choice(alpha) for _ in range(16))
    if not analyst_pw:
        alpha = string.ascii_letters + string.digits + "!@#$%^&*"
        analyst_pw = "".join(secrets.choice(alpha) for _ in range(16))

    now = datetime.now(timezone.utc).isoformat()
    db.table("users").insert([
        {"username": "admin",   "password_hash": bcrypt.hashpw(admin_pw.encode(),   bcrypt.gensalt(12)).decode(),
         "role": "admin",   "permissions": ["run_scan","view_reports","manage_users","view_audit"],
         "is_active": True, "created_at": now, "created_by": "system"},
        {"username": "analyst", "password_hash": bcrypt.hashpw(analyst_pw.encode(), bcrypt.gensalt(12)).decode(),
         "role": "analyst", "permissions": ["run_scan","view_reports"],
         "is_active": True, "created_at": now, "created_by": "system"},
    ]).execute()
    logger.warning("Default users seeded — CHANGE PASSWORDS | admin=%s | analyst=%s", admin_pw, analyst_pw)


# ── User CRUD ─────────────────────────────────────────────────────────────────

def _norm(row: dict) -> dict:
    perms = row.get("permissions", [])
    if isinstance(perms, str):
        try: perms = json.loads(perms)
        except Exception: perms = []
    row["permissions"] = perms if isinstance(perms, list) else list(perms)
    return row


def get_user_by_username(username: str) -> Optional[dict]:
    resp = _get_db().table("users").select("*").eq("username", username).eq("is_active", True).execute()
    return _norm(resp.data[0]) if resp.data else None


def get_user_by_id(user_id: int) -> Optional[dict]:
    resp = _get_db().table("users").select("*").eq("id", user_id).execute()
    return _norm(resp.data[0]) if resp.data else None


def get_all_users() -> list[dict]:
    resp = (_get_db().table("users")
            .select("id,username,role,permissions,is_active,created_at,last_login,login_count,created_by")
            .order("id").execute())
    return [_norm(r) for r in (resp.data or [])]


def create_user(username: str, password: str, role: str = "analyst",
                permissions: Optional[list] = None, created_by: str = "system") -> tuple[bool, str]:
    import bcrypt
    if permissions is None:
        permissions = {"admin":["run_scan","view_reports","manage_users","view_audit"],
                       "analyst":["run_scan","view_reports"],"viewer":["view_reports"]}.get(role,["view_reports"])
    try:
        _get_db().table("users").insert({
            "username": username,
            "password_hash": bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode(),
            "role": role, "permissions": permissions, "is_active": True,
            "created_at": datetime.now(timezone.utc).isoformat(), "created_by": created_by,
        }).execute()
        return True, "تم إنشاء المستخدم بنجاح."
    except Exception as exc:
        if "duplicate" in str(exc).lower() or "unique" in str(exc).lower():
            return False, f"اسم المستخدم '{username}' موجود مسبقاً."
        logger.error("create_user: %s", exc)
        return False, "خطأ داخلي أثناء إنشاء المستخدم."


def update_user(user_id: int, role: Optional[str]=None, permissions: Optional[list]=None,
                is_active: Optional[bool]=None, new_password: Optional[str]=None,
                failed_attempts: Optional[int]=None, locked_until: Optional[str]=None) -> tuple[bool, str]:
    import bcrypt
    upd: dict = {}
    if role            is not None: upd["role"]            = role
    if permissions     is not None: upd["permissions"]     = permissions
    if is_active       is not None: upd["is_active"]       = bool(is_active)
    if new_password    is not None: upd["password_hash"]   = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt(12)).decode()
    if failed_attempts is not None: upd["failed_attempts"] = int(failed_attempts)
    if locked_until    is not None: upd["locked_until"]    = locked_until or None
    if not upd: return False, "لا توجد بيانات للتحديث."
    try:
        _get_db().table("users").update(upd).eq("id", user_id).execute()
        return True, "تم تحديث المستخدم بنجاح."
    except Exception as exc:
        logger.error("update_user: %s", exc)
        return False, "خطأ داخلي أثناء التحديث."


def update_last_login(user_id: int) -> None:
    try:
        row   = get_user_by_id(user_id)
        count = int((row or {}).get("login_count", 0)) + 1
        _get_db().table("users").update({
            "last_login": datetime.now(timezone.utc).isoformat(),
            "login_count": count, "failed_attempts": 0, "locked_until": None,
        }).eq("id", user_id).execute()
    except Exception as exc:
        logger.error("update_last_login: %s", exc)


def hard_delete_user(user_id: int) -> tuple[bool, str]:
    try:
        row = get_user_by_id(user_id)
        if not row: return False, "المستخدم غير موجود."
        _get_db().table("users").delete().eq("id", user_id).execute()
        return True, f"تم حذف المستخدم '{row['username']}' نهائياً."
    except Exception as exc:
        logger.error("hard_delete_user: %s", exc)
        return False, "خطأ داخلي."


def update_user_totp(user_id: int, totp_secret: str, totp_enabled: bool) -> tuple[bool, str]:
    try:
        if not get_user_by_id(user_id): return False, "المستخدم غير موجود."
        _get_db().table("users").update({"totp_secret": totp_secret, "totp_enabled": bool(totp_enabled)}).eq("id", user_id).execute()
        return True, f"تم {'تفعيل' if totp_enabled else 'تعطيل'} المصادقة الثنائية بنجاح."
    except Exception as exc:
        logger.error("update_user_totp: %s", exc)
        return False, "خطأ داخلي."


def update_user_permissions(user_id: int, permissions: list) -> tuple[bool, str]:
    try:
        if not get_user_by_id(user_id): return False, "المستخدم غير موجود."
        _get_db().table("users").update({"permissions": permissions}).eq("id", user_id).execute()
        return True, "تم تحديث الصلاحيات بنجاح."
    except Exception as exc:
        logger.error("update_user_permissions: %s", exc)
        return False, "خطأ داخلي."


# ── Audit Log ─────────────────────────────────────────────────────────────────

def log_event(action: str, username: str="system", user_id: Optional[int]=None,
              category: str="general", resource: Optional[str]=None,
              ip_address: Optional[str]=None, user_agent: Optional[str]=None,
              status: str="success", details: Optional[str]=None) -> None:
    try:
        _get_db().table("audit_log").insert({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id, "username": username, "action": action,
            "category": category, "resource": resource, "ip_address": ip_address,
            "user_agent": user_agent, "status": status, "details": details,
        }).execute()
    except Exception as exc:
        logger.error("log_event: %s", exc)


def get_audit_log(user_id: Optional[int]=None, limit: int=200,
                  category: Optional[str]=None, action: Optional[str]=None) -> list[dict]:
    try:
        q = _get_db().table("audit_log").select("*").order("timestamp", desc=True).limit(limit)
        if user_id  is not None: q = q.eq("user_id", user_id)
        if category:             q = q.eq("category", category)
        if action:               q = q.ilike("action", f"%{action}%")
        return q.execute().data or []
    except Exception as exc:
        logger.error("get_audit_log: %s", exc); return []


def get_audit_stats() -> dict:
    try:
        resp = _get_db().rpc("get_audit_stats", {}).execute()
        data = resp.data
        if isinstance(data, str): data = json.loads(data)
        return data or {}
    except Exception as exc:
        logger.error("get_audit_stats: %s", exc)
        return {"total_events": 0, "failed_events": 0, "by_category": [], "recent_logins": []}


# ── Scan Reports ──────────────────────────────────────────────────────────────

def store_report(result: dict, risk_score: float, original_content: Optional[str],
                 user_id: int, username: str) -> str:
    token = uuid.uuid4().hex
    vulns = result.get("vulnerabilities", [])
    _c    = lambda sev: sum(1 for v in vulns if v.get("severity") == sev)
    now   = datetime.now(timezone.utc).isoformat()
    try:
        db   = _get_db()
        resp = db.table("scan_reports").insert({
            "token": token, "user_id": user_id, "username": username,
            "scan_type": result.get("scan_type",""), "target": result.get("target",""),
            "risk_score": round(risk_score,2), "vuln_count": len(vulns),
            "critical_count": _c("critical"), "high_count": _c("high"),
            "medium_count": _c("medium"), "low_count": _c("low"),
            "result_json": json.dumps(result, ensure_ascii=False),
            "original_content": original_content, "stored_at": now,
        }).execute()
        report_id = resp.data[0]["id"]

        vuln_rows = []
        for v in vulns:
            sev = (str(v.get("severity","low")).strip().lower() or "low")
            if sev not in {"critical","high","medium","low","info"}: sev = "low"
            raw = v.get("cve_ids",[])
            cve_list = (
                [c.strip() for c in raw.split(",") if c.strip()] if isinstance(raw, str)
                else [str(c).strip() for c in raw if str(c).strip()] if isinstance(raw, list) else []
            )
            vuln_rows.append({
                "report_id": report_id, "check_name": str(v.get("check","unknown_check")),
                "severity": sev, "title": str(v.get("title","Untitled finding")),
                "description": str(v.get("description","")), "evidence": str(v.get("evidence","")),
                "remediation": str(v.get("remediation","")), "line_number": int(v.get("line_number",0) or 0),
                "cve_ids": cve_list, "found_at": now,
            })
        if vuln_rows:
            db.table("scan_vulnerabilities").insert(vuln_rows).execute()
        return token
    except Exception as exc:
        logger.error("store_report: %s", exc); raise


def get_report(token: str) -> Optional[dict]:
    try:
        resp = _get_db().table("scan_reports").select("*").eq("token", token).execute()
        if not resp.data: return None
        row = resp.data[0]
        row["result"] = json.loads(row["result_json"])
        return row
    except Exception as exc:
        logger.error("get_report: %s", exc); return None


def get_user_reports(user_id: int, limit: int=100) -> list[dict]:
    try:
        return (_get_db().table("scan_reports")
                .select("token,scan_type,target,risk_score,vuln_count,critical_count,high_count,medium_count,low_count,stored_at")
                .eq("user_id", user_id).order("stored_at", desc=True).limit(limit).execute().data or [])
    except Exception as exc:
        logger.error("get_user_reports: %s", exc); return []


def get_all_reports(limit: int=200) -> list[dict]:
    try:
        return (_get_db().table("scan_reports")
                .select("token,username,scan_type,target,risk_score,vuln_count,critical_count,high_count,medium_count,low_count,stored_at")
                .order("stored_at", desc=True).limit(limit).execute().data or [])
    except Exception as exc:
        logger.error("get_all_reports: %s", exc); return []


def get_dashboard_stats(user_id: int) -> dict:
    try:
        resp = _get_db().rpc("get_dashboard_stats", {"p_user_id": user_id}).execute()
        data = resp.data
        if isinstance(data, str): data = json.loads(data)
        return data or _empty_stats()
    except Exception as exc:
        logger.error("get_dashboard_stats: %s", exc); return _empty_stats()


def get_all_dashboard_stats() -> dict:
    try:
        resp = _get_db().rpc("get_all_dashboard_stats", {}).execute()
        data = resp.data
        if isinstance(data, str): data = json.loads(data)
        return data or _empty_stats(admin=True)
    except Exception as exc:
        logger.error("get_all_dashboard_stats: %s", exc); return _empty_stats(admin=True)


def get_system_stats() -> dict:
    try:
        resp = _get_db().rpc("get_system_stats", {}).execute()
        data = resp.data
        if isinstance(data, str): data = json.loads(data)
        return data or {}
    except Exception as exc:
        logger.error("get_system_stats: %s", exc)
        return {"total_users":0,"active_users":0,"total_scans":0,"today_scans":0,
                "total_vulns":0,"critical_vulns":0,"failed_logins":0,
                "recent_events":[],"top_scanners":[],"users_list":[]}


def delete_report(token: str) -> tuple[bool, str]:
    try:
        if not _get_db().table("scan_reports").select("id").eq("token", token).execute().data:
            return False, "التقرير غير موجود."
        _get_db().table("scan_reports").delete().eq("token", token).execute()
        return True, "تم حذف التقرير بنجاح."
    except Exception as exc:
        logger.error("delete_report: %s", exc); return False, "خطأ داخلي."


def get_top_vulnerabilities(limit: int=10) -> list[dict]:
    try:
        resp = _get_db().rpc("get_top_vulnerabilities", {"p_limit": limit}).execute()
        data = resp.data
        if isinstance(data, str): data = json.loads(data)
        return data if isinstance(data, list) else []
    except Exception as exc:
        logger.error("get_top_vulnerabilities: %s", exc); return []


def _empty_stats(admin: bool=False) -> dict:
    d = {"total_scans":0,"total_vulns":0,"critical_count":0,"high_count":0,
         "avg_risk_score":0,"by_type":[],"recent_scores":[]}
    if admin: d["active_users"] = 0
    return d
