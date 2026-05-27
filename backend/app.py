# app.py
"""
CyBrain Security Platform — Flask Application
All routes and app setup in one flat file.
"""

import base64
import csv
import io
import json
import logging
import os
import re
import secrets
import tempfile
import zipfile
from functools import wraps

import bcrypt
import pyotp
import qrcode

from dotenv import load_dotenv
from flask import (
    Flask, Response, current_app, flash, g, jsonify, redirect,
    render_template, request, session, url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import (
    LoginManager, current_user,
    login_required, login_user, logout_user,
)
from flask_wtf.csrf import CSRFProtect

from database import (
    init_db,
    get_user_by_id, get_all_users, count_users, count_active_admins,
    create_user, update_user, hard_delete_user,
    update_last_login, update_user_totp,
    get_locked_target,
    log_event, get_audit_log, get_audit_stats,
    store_report, get_report, get_user_reports, get_all_reports,
    get_dashboard_stats, get_all_dashboard_stats,
    get_system_stats, delete_report, get_top_vulnerabilities,
)
from models import authenticate_user, load_user_from_db
from forms import LoginForm, ScanForm, TOTPForm, ChangePasswordForm, check_password_complexity
from flask_cors import CORS, cross_origin

from risk_engine import calculate_risk_v2
from ai_agent import get_aria

from scanners.netscan_scanner import run_nmap_scan
from scanners.web_scanner   import run_web_scan
from scanners.server_ext    import run_server_scan
from scanners.server_int    import run_server_config_scan, generate_fixed_config
from scanners.dep_scanner   import run_dep_scan
from scanners.sast_scanner  import run_sast_scan
from scanners.dast_scanner  import run_dast_scan

# ── Bootstrap ─────────────────────────────────────────────────────────────────
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

# ── App ───────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="static", static_url_path="/static")

SECRET_KEY = os.environ.get("SECRET_KEY", "").strip()
if not SECRET_KEY:
    raise RuntimeError(
        "SECRET_KEY is not set. Add it to .env:\n"
        "  SECRET_KEY=your-very-long-random-secret-key"
    )

_IS_PRODUCTION = os.environ.get("FLASK_ENV") == "production"

app.config.update(
    SECRET_KEY=SECRET_KEY,
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,
    SESSION_COOKIE_HTTPONLY=True,
    # SameSite=None + Secure is required for cross-origin cookie sending
    # (frontend on Render/Netlify calling backend on a different domain)
    SESSION_COOKIE_SAMESITE="None" if _IS_PRODUCTION else "Lax",
    SESSION_COOKIE_SECURE=_IS_PRODUCTION,
    MAX_CONTENT_LENGTH=10 * 1024 * 1024,   # 10 MB hard limit
    PERMANENT_SESSION_LIFETIME=1800,
)

# ── Extensions ────────────────────────────────────────────────────────────────
csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view    = "login"
login_manager.login_message = "يرجى تسجيل الدخول للمتابعة."

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200/hour", "50/minute"],
    storage_uri=os.environ.get("REDIS_URL", "memory://"),
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Default origins cover: local Vite dev, local Flask dev, and any HTTPS Render
# frontend. Add your deployed frontend URL via the ALLOWED_ORIGINS env var:
#   ALLOWED_ORIGINS=https://securax-frontend.onrender.com,https://your-app.netlify.app
_DEFAULT_ORIGINS = (
    "http://localhost:3000,"
    "http://localhost:5173,"
    "http://127.0.0.1:3000,"
    "http://127.0.0.1:5173"
)
_ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get("ALLOWED_ORIGINS", _DEFAULT_ORIGINS).split(",")
    if o.strip()
]
CORS(
    app,
    origins=_ALLOWED_ORIGINS,
    supports_credentials=True,
    allow_headers=["Content-Type", "X-CSRFToken", "Authorization", "Accept"],
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    expose_headers=["X-CSRFToken"],
    max_age=600,
)

# ── CSP nonce ─────────────────────────────────────────────────────────────────
@app.before_request
def set_csp_nonce():
    g.csp_nonce = secrets.token_hex(16)


# ── Security headers ──────────────────────────────────────────────────────────
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"]   = "nosniff"
    response.headers["X-Frame-Options"]          = "SAMEORIGIN"
    response.headers["X-XSS-Protection"]         = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = "geolocation=(), microphone=(), camera=()"
    nonce = getattr(g, "csp_nonce", "")
    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        f"img-src 'self' data: https:; "
        f"connect-src 'self'; "
        f"font-src 'self' data:; "
        f"frame-ancestors 'self';"
    )
    if nonce:
        response.headers["X-CSP-Nonce"] = nonce
    if "text/html" in response.headers.get("Content-Type", ""):
        response.headers["Content-Type"] = "text/html; charset=utf-8"
    if os.environ.get("FLASK_ENV") == "production":
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    return response


# ── DB init ───────────────────────────────────────────────────────────────────
with app.app_context():
    init_db()


# ── User loader ───────────────────────────────────────────────────────────────
@login_manager.user_loader
def load_user(user_id: str):
    return load_user_from_db(user_id)


# ── Permission decorator ──────────────────────────────────────────────────────
def require_permission(permission: str):
    def decorator(f):
        @wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            if not current_user.has_permission(permission):
                logger.warning(
                    "access denied | user=%s | permission=%s | path=%s",
                    current_user.username, permission, request.path,
                )
                log_event(
                    "access_denied", current_user.username, current_user.id,
                    category="security", resource=request.path,
                    ip_address=request.remote_addr, status="denied",
                    details=f"Missing permission: {permission}",
                )
                return jsonify({"error": "صلاحية غير كافية."}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ── File upload security ──────────────────────────────────────────────────────
_BLOCKED_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".sh", ".ps1", ".vbs", ".js", ".dll",
    ".so", ".dylib", ".bin", ".msi", ".com", ".scr", ".pif",
}
_MAX_ZIP_UNCOMPRESSED = 50 * 1024 * 1024  # 50 MB uncompressed cap (zip bomb guard)


def validate_upload(file_storage, allowed_extensions: set[str]) -> tuple[bool, str]:
    """Return (ok, error_message). Validates extension, size, and zip-bomb."""
    if not file_storage or not file_storage.filename:
        return False, "لم يتم رفع ملف."

    name = file_storage.filename.lower()
    ext  = os.path.splitext(name)[1]

    if ext in _BLOCKED_EXTENSIONS:
        return False, f"نوع الملف '{ext}' محظور لأسباب أمنية."
    if ext not in allowed_extensions:
        return False, f"الامتداد '{ext}' غير مسموح. المسموح: {', '.join(sorted(allowed_extensions))}"

    file_storage.seek(0, 2)
    size = file_storage.tell()
    file_storage.seek(0)
    if size > 10 * 1024 * 1024:
        return False, "حجم الملف يتجاوز الحد المسموح (10 MB)."

    if ext == ".zip":
        try:
            with zipfile.ZipFile(io.BytesIO(file_storage.read()), "r") as zf:
                total = sum(i.file_size for i in zf.infolist())
                if total > _MAX_ZIP_UNCOMPRESSED:
                    return False, "الملف المضغوط يحتوي على بيانات كبيرة جداً (zip bomb محتمل)."
            file_storage.seek(0)
        except zipfile.BadZipFile:
            return False, "الملف ليس ملف ZIP صالحاً."

    return True, ""


def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role != "admin":
            return jsonify({"error": "Admin access required."}), 403
        return f(*args, **kwargs)
    return wrapper


# ── Analyst target lock ───────────────────────────────────────────────────────

def _normalize_target(raw: str) -> str:
    """Strip protocol / path / port → bare lowercase hostname or IP."""
    t = re.sub(r'^https?://', '', raw.strip())
    t = t.split('/')[0].split('?')[0].split(':')[0]
    return t.lower().strip()


def _check_target_lock(raw_target: str):
    """
    Enforce admin-assigned target restriction.
    - Admin: always allowed.
    - Analyst, no target assigned by admin: allowed (unrestricted).
    - Analyst, target assigned and matches: allowed.
    - Analyst, target assigned but doesn't match: 403.

    Usage::
        ok, err = _check_target_lock(target)
        if not ok:
            return err
    """
    if current_user.role == "admin":
        return True, None

    locked = get_locked_target(current_user.id)

    if locked is None:
        # Admin has not assigned a target restriction — allow all scans
        return True, None

    normalized = _normalize_target(raw_target)
    if locked == normalized:
        return True, None

    # Target doesn't match the admin-assigned allowed target — reject
    log_event(
        "target_violation", current_user.username, current_user.id,
        category="security", resource=normalized, status="denied",
        details=f"Blocked: tried {normalized!r}, allowed target is {locked!r}",
        ip_address=request.remote_addr,
    )
    return False, (
        jsonify({
            "error": (
                f"غير مسموح. صلاحيات حسابك مقتصرة على الهدف «{locked}» فقط. "
                f"تواصل مع المدير لتغيير الهدف المصرّح به."
            ),
            "allowed_target": locked,
            "forbidden": True,
        }),
        403,
    )


# ── Error handlers ────────────────────────────────────────────────────────────
@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "طلب غير صالح."}), 400

@app.errorhandler(403)
def forbidden(e):
    return jsonify({"error": "وصول مرفوض."}), 403

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "المورد غير موجود."}), 404

@app.errorhandler(413)
def file_too_large(e):
    return jsonify({"error": "حجم الملف كبير جداً. الحد الأقصى 25MB."}), 413

@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({"error": "تجاوزت الحد المسموح من الطلبات. حاول لاحقاً."}), 429

@app.errorhandler(Exception)
def handle_unexpected(e):
    logger.exception("خطأ غير متوقع")
    return jsonify({"error": "خطأ داخلي في الخادم."}), 500


# ════════════════════════════════════════════════════════════════════════════
#  AUTH ROUTES
# ════════════════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10/minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))

    form = LoginForm()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user, err, _lock_secs = authenticate_user(username, password)

        if user:
            if user.totp_enabled:
                # Store pending user in session, redirect to TOTP verification
                session["pending_totp_user_id"] = user.id
                log_event("totp_required", username, user.id,
                          category="auth", ip_address=request.remote_addr, status="pending")
                return redirect(url_for("verify_totp"))

            login_user(user, remember=False)
            update_last_login(user.id)
            log_event("login_success", username, user.id,
                      category="auth", ip_address=request.remote_addr,
                      user_agent=request.user_agent.string)
            logger.info("login | user=%s | ip=%s", username, request.remote_addr)

            next_page = request.args.get("next", "")
            if next_page and next_page.startswith("/"):
                return redirect(next_page)
            return redirect(url_for("home"))

        log_event("login_failed", username, category="auth",
                  ip_address=request.remote_addr, status="failed", details=err)
        logger.warning("login failed | user=%s | ip=%s", username, request.remote_addr)
        flash(err or "اسم المستخدم أو كلمة المرور غير صحيحة.")

    return render_template("login.html", form=form)


@app.route("/verify-totp", methods=["GET", "POST"])
@limiter.limit("10/minute")
def verify_totp():
    pending_id = session.get("pending_totp_user_id")
    if not pending_id:
        return redirect(url_for("login"))

    form = TOTPForm()
    if request.method == "POST":
        token = (request.form.get("token") or "").strip()
        row   = get_user_by_id(pending_id)
        if row:
            from models import _row_to_user  # local import to avoid circular ref
            user = _row_to_user(row)
            if user.verify_totp(token):
                session.pop("pending_totp_user_id", None)
                login_user(user, remember=False)
                update_last_login(user.id)
                log_event("totp_verified", user.username, user.id,
                          category="auth", ip_address=request.remote_addr, status="success")
                return redirect(url_for("home"))

        log_event("totp_failed", category="auth",
                  ip_address=request.remote_addr, status="failed")
        flash("رمز المصادقة غير صحيح.")

    return render_template("verify_totp.html", form=form)


@app.route("/setup-totp", methods=["GET", "POST"])
@login_required
def setup_totp():
    form = TOTPForm()
    if request.method == "GET":
        secret = pyotp.random_base32()
        session["totp_setup_secret"] = secret
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=current_user.username, issuer_name="CyBrain Security"
        )
        img    = qrcode.make(uri)
        buf    = io.BytesIO()
        img.save(buf, "PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
        return render_template("setup_totp.html", form=form, qr_b64=qr_b64, secret=secret)

    secret = session.get("totp_setup_secret")
    token  = (request.form.get("token") or "").strip()
    if secret and pyotp.TOTP(secret).verify(token, valid_window=1):
        ok, msg = update_user_totp(current_user.id, secret, True)
        if ok:
            session.pop("totp_setup_secret", None)
            log_event("totp_enabled", current_user.username, current_user.id,
                      category="auth", ip_address=request.remote_addr)
            flash("تم تفعيل المصادقة الثنائية بنجاح.")
            return redirect(url_for("home"))
        flash(msg)
    else:
        flash("رمز التحقق غير صحيح. حاول مرة أخرى.")

    return redirect(url_for("setup_totp"))


@app.route("/disable-totp", methods=["POST"])
@login_required
def disable_totp():
    ok, msg = update_user_totp(current_user.id, "", False)
    log_event("totp_disabled", current_user.username, current_user.id,
              category="auth", ip_address=request.remote_addr,
              status="success" if ok else "failed")
    flash(msg)
    return redirect(url_for("home"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw     = request.form.get("new_password", "")

        row = get_user_by_id(current_user.id)
        if not row or not bcrypt.checkpw(current_pw.encode(), row["password_hash"].encode()):
            flash("كلمة المرور الحالية غير صحيحة.")
            return render_template("change_password.html", form=form)

        ok, msg = check_password_complexity(new_pw)
        if not ok:
            flash(msg)
            return render_template("change_password.html", form=form)

        update_user(current_user.id, new_password=new_pw)
        log_event("password_changed", current_user.username, current_user.id,
                  category="auth", ip_address=request.remote_addr)
        flash("تم تغيير كلمة المرور بنجاح.")
        return redirect(url_for("home"))

    return render_template("change_password.html", form=form)


@app.route("/logout")
@login_required
def logout():
    log_event("logout", current_user.username, current_user.id,
              category="auth", ip_address=request.remote_addr)
    logger.info("logout | user=%s", current_user.username)
    logout_user()
    return redirect(url_for("login"))


# ════════════════════════════════════════════════════════════════════════════
#  MAIN ROUTES
# ════════════════════════════════════════════════════════════════════════════

@app.route("/")
@login_required
def home():
    form = ScanForm()
    return render_template("index.html", form=form, user=current_user.username)


@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role == "admin":
        stats   = get_all_dashboard_stats()
        reports = get_all_reports(limit=20)
    else:
        stats   = get_dashboard_stats(current_user.id)
        reports = get_user_reports(current_user.id, limit=20)
    return render_template(
        "dashboard.html",
        stats=stats, reports=reports, user=current_user.username,
    )


_UUID_RE = re.compile(r"^[0-9a-f]{32}$")


@app.route("/report/<token>")
@login_required
@limiter.limit("30/minute")
def view_report(token: str):
    if not _UUID_RE.match(token):
        return jsonify({"error": "رمز التقرير غير صالح."}), 400

    data = get_report(token)
    if not data:
        return jsonify({"error": "التقرير غير موجود أو انتهت صلاحيته."}), 404

    if data.get("user_id") != current_user.id and current_user.role != "admin":
        log_event("idor_attempt", current_user.username, current_user.id,
                  category="security", resource=f"/report/{token}",
                  ip_address=request.remote_addr, status="blocked")
        return jsonify({"error": "هذا التقرير لا يخصّك."}), 403

    return render_template(
        "report.html",
        result     = data["result"],
        risk_score = data["risk_score"],
        stored_at  = data["stored_at"],
        has_fix    = bool(data.get("original_content")),
        token      = token,
        user       = current_user.username,
    )


@app.route("/download-fixed/<token>")
@login_required
@limiter.limit("10/minute")
def download_fixed(token: str):
    if not _UUID_RE.match(token):
        return jsonify({"error": "رمز التقرير غير صالح."}), 400

    data = get_report(token)
    if not data:
        return jsonify({"error": "التقرير غير موجود."}), 404

    if data.get("user_id") != current_user.id and current_user.role != "admin":
        return jsonify({"error": "هذا التقرير لا يخصّك."}), 403

    original = data.get("original_content")
    if not original:
        return jsonify({"error": "لا يوجد ملف إعدادات مخزّن لهذا الفحص."}), 400

    vulns         = data["result"].get("vulnerabilities", [])
    fixed_content, change_log = generate_fixed_config(original, vulns)

    return Response(
        fixed_content,
        mimetype="text/plain",
        headers={
            "Content-Disposition": "attachment; filename=httpd_cybrain_fixed.conf",
            "X-Changes-Count":     str(len(change_log)),
        },
    )


# ════════════════════════════════════════════════════════════════════════════
#  SCAN API
# ════════════════════════════════════════════════════════════════════════════

@app.route("/start-scan", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("5/minute")
def start_scan():
    form = ScanForm()
    if not form.validate_on_submit():
        return jsonify({"error": "بيانات غير صالحة.", "details": form.errors}), 400

    target        = form.target.data.strip()
    scan_type     = form.scan_type.data
    deep_scan     = form.deep_scan.data
    cve_check     = form.cve_check.data
    ssl_check     = form.ssl_check.data
    has_pii       = bool(form.has_pii.data)
    has_payment   = bool(form.has_payment.data)
    exploit_known = bool(form.exploit_known.data)

    EXTERNAL_TYPES = {"network_ext", "web", "server_ext", "dast"}
    if scan_type in EXTERNAL_TYPES and not form.legal_disclaimer.data:
        return jsonify({"error": "يجب الموافقة على الإقرار القانوني للفحوصات الخارجية."}), 400

    try:
        criticality = float(form.criticality.data)
    except (ValueError, TypeError):
        return jsonify({"error": "قيمة criticality غير صالحة."}), 400

    logger.info("scan start | user=%s | type=%s | target=%s", current_user.username, scan_type, target)
    log_event("scan_started", current_user.username, current_user.id,
              category="scan", resource=target, ip_address=request.remote_addr,
              details=f"type={scan_type}")

    result   = None
    tmp_path = None
    original_config_content = None

    try:
        if scan_type == "network_ext":
            result = run_nmap_scan(target, deep=deep_scan)

        elif scan_type == "network_int":
            result = run_nmap_scan(target, deep=deep_scan, internal=True)

        elif scan_type == "web":
            result = run_web_scan(target, cve_check=cve_check, ssl_check=ssl_check)

        elif scan_type == "server_ext":
            result = run_server_scan(target, deep=deep_scan)

        elif scan_type == "server_int":
            upload = request.files.get("config_file")
            ok, err = validate_upload(upload, {".conf", ".txt"})
            if not ok:
                return jsonify({"error": err}), 400
            with tempfile.NamedTemporaryFile(delete=False, suffix=".conf", mode="wb") as tmp:
                upload.save(tmp)
                tmp_path = tmp.name
            try:
                with open(tmp_path, encoding="utf-8", errors="replace") as _fh:
                    original_config_content = _fh.read()
            except OSError:
                pass
            result = run_server_config_scan(tmp_path)

        elif scan_type == "dependencies":
            upload = request.files.get("config_file")
            ok, err = validate_upload(upload, {".txt", ".json", ".toml"})
            if not ok:
                return jsonify({"error": err}), 400
            fname  = upload.filename.lower()
            suffix = ".json" if fname.endswith(".json") else (".toml" if fname.endswith(".toml") else ".txt")
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, mode="wb") as tmp:
                upload.save(tmp)
                tmp_path = tmp.name
            named_path = os.path.join(tempfile.gettempdir(), os.path.basename(upload.filename))
            try:
                os.replace(tmp_path, named_path)
                tmp_path = named_path
            except OSError:
                pass
            result = run_dep_scan(tmp_path)

        elif scan_type == "sast":
            upload = request.files.get("source_file") or request.files.get("config_file")
            ok, err = validate_upload(upload, {".zip"})
            if not ok:
                return jsonify({"error": err}), 400
            with tempfile.NamedTemporaryFile(delete=False, suffix=".zip", mode="wb") as tmp:
                upload.save(tmp)
                tmp_path = tmp.name
            result = run_sast_scan(tmp_path)

        elif scan_type == "dast":
            result = run_dast_scan(target)

        else:
            return jsonify({"error": "نوع فحص غير مدعوم."}), 400

    except RuntimeError as exc:
        logger.error("scan failed | %s | %s | %s", target, scan_type, exc)
        return jsonify({"error": str(exc)}), 500
    except Exception:
        logger.exception("unexpected scan error | target=%s", target)
        return jsonify({"error": "حدث خطأ غير متوقع أثناء الفحص."}), 500
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    internet_facing = scan_type in {"network_ext", "web", "server_ext", "dast"}
    breakdown = calculate_risk_v2(
        result,
        criticality=criticality,
        internet_facing=internet_facing,
        has_pii=has_pii,
        has_payment=has_payment,
        exploit_known=exploit_known,
    )
    risk_score = breakdown.final_score

    result["risk_breakdown"] = {
        "base_score":      breakdown.base_score,
        "temporal_score":  breakdown.temporal_score,
        "env_score":       breakdown.env_score,
        "final_score":     breakdown.final_score,
        "risk_level":      breakdown.risk_level,
        "confidence":      breakdown.confidence,
        "recommendations": breakdown.recommendations,
    }

    report_token = store_report(result, risk_score, original_config_content,
                                current_user.id, current_user.username)

    log_event("scan_completed", current_user.username, current_user.id,
              category="scan", resource=target, status="success",
              details=f"type={scan_type} risk={risk_score} level={breakdown.risk_level} findings={len(result.get('vulnerabilities',[]))}")

    logger.info(
        "scan done | user=%s | type=%s | target=%s | risk=%.2f | level=%s | findings=%d",
        current_user.username, scan_type, target,
        risk_score, breakdown.risk_level, len(result.get("vulnerabilities", [])),
    )

    return jsonify({
        "scan_result":    result,
        "risk_score":     risk_score,
        "risk_level":     breakdown.risk_level,
        "confidence":     breakdown.confidence,
        "recommendations": breakdown.recommendations,
        "message":        "تم الفحص بنجاح.",
        "report_token":   report_token,
    })


# ════════════════════════════════════════════════════════════════════════════
#  AI ROUTES
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/ai/analyze", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("20/minute")
@csrf.exempt
def ai_analyze():
    data      = request.get_json(silent=True) or {}
    findings  = data.get("findings", [])
    target    = data.get("target", "unknown")
    scan_type = data.get("scan_type", "web")

    # report.html sends a token — load findings from DB
    token = (data.get("token") or "").strip()
    if token and not findings:
        if not _UUID_RE.match(token):
            return jsonify({"error": "رمز التقرير غير صالح."}), 400
        report_data = get_report(token)
        if not report_data:
            return jsonify({"error": "التقرير غير موجود."}), 404
        if report_data.get("user_id") != current_user.id and current_user.role != "admin":
            log_event("idor_attempt", current_user.username, current_user.id,
                      category="security", resource=f"/api/ai/analyze/{token}",
                      ip_address=request.remote_addr, status="blocked")
            return jsonify({"error": "هذا التقرير لا يخصّك."}), 403
        result    = report_data.get("result", {})
        findings  = result.get("vulnerabilities", [])
        target    = result.get("target", "unknown")
        scan_type = result.get("scan_type", "web")

    if not findings:
        return jsonify({"error": "No findings to analyze."}), 400
    if not isinstance(findings, list):
        return jsonify({"error": "findings must be a list."}), 400
    if len(findings) > 500:
        return jsonify({"error": "findings list exceeds maximum of 500 items."}), 400
    findings = [f for f in findings if isinstance(f, dict)]
    if not findings:
        return jsonify({"error": "findings must contain dict objects."}), 400

    aria     = get_aria()
    analysis = aria.analyze_findings(findings, target, scan_type)
    return jsonify({"analysis": analysis})


@app.route("/api/ai/chat", methods=["POST"])
@login_required
@limiter.limit("10/minute")
@csrf.exempt
def ai_chat():
    data    = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    context = data.get("context", {})

    if not message:
        return jsonify({"error": "الرسالة فارغة."}), 400
    if len(message) > 2000:
        return jsonify({"error": "الرسالة طويلة جداً (الحد 2000 حرف)."}), 400

    aria  = get_aria()
    reply = aria.chat(message, context, user_id=str(current_user.id))
    return jsonify({"reply": reply, "ai_mode": "online" if aria.ai_active else "offline"})


@app.route("/api/ai/fix", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("10/minute")
@csrf.exempt
def ai_fix():
    data     = request.get_json(silent=True) or {}
    vuln_type = (data.get("vuln_type") or "").strip()
    context   = data.get("context", {})
    if not vuln_type:
        return jsonify({"error": "vuln_type required."}), 400
    aria = get_aria()
    fix  = aria.generate_fix(vuln_type, context)
    return jsonify({"fix": fix})


@app.route("/api/ai/history/clear", methods=["POST"])
@login_required
@csrf.exempt
def ai_history_clear():
    aria = get_aria()
    aria.clear_history(str(current_user.id))
    return jsonify({"ok": True, "message": "Conversation history cleared."})


@app.route("/api/ai/status")
@login_required
def ai_status():
    aria = get_aria()
    return jsonify({
        "status":   "online" if aria.ai_active else "offline",
        "model":    getattr(aria, "_model_name", "gemini-2.0-flash"),
        "provider": getattr(aria, "provider", "unknown"),
    })


# ════════════════════════════════════════════════════════════════════════════
#  ADMIN ROUTES
# ════════════════════════════════════════════════════════════════════════════

@app.route("/admin")
@admin_required
def admin_hub():
    stats     = get_system_stats()
    top_vulns = get_top_vulnerabilities(limit=10)
    return render_template("admin_hub.html", stats=stats, top_vulns=top_vulns, user=current_user.username)


@app.route("/admin/users")
@admin_required
def admin_users():
    users = get_all_users()
    return render_template("users.html", users=users, user=current_user.username)


@app.route("/admin/users/create", methods=["POST"])
@admin_required
@limiter.limit("20/minute")
def admin_create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    confirm  = request.form.get("confirm_password", "")
    role     = request.form.get("role", "analyst")

    if not username or not password:
        flash("اسم المستخدم وكلمة المرور مطلوبان.", "error")
        return redirect(url_for("admin_users"))

    if password != confirm:
        flash("كلمة المرور وتأكيدها غير متطابقتين.", "error")
        return redirect(url_for("admin_users"))

    ok, msg = check_password_complexity(password)
    if not ok:
        flash(msg, "error")
        return redirect(url_for("admin_users"))

    ok, msg = create_user(username, password, role, created_by=current_user.username)
    if ok:
        log_event("user_created", current_user.username, current_user.id,
                  category="admin", resource=username, status="success")
        flash(f"تم إنشاء المستخدم «{username}» بنجاح.", "success")
    else:
        flash(msg, "error")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:uid>/update", methods=["POST"])
@admin_required
def admin_update_user(uid: int):
    data        = request.get_json(silent=True) or {}
    role        = data.get("role")
    permissions = data.get("permissions")
    is_active   = data.get("is_active")
    new_password = data.get("new_password")

    if new_password:
        ok, msg = check_password_complexity(new_password)
        if not ok:
            return jsonify({"error": msg}), 400

    ok, msg = update_user(uid, role=role, permissions=permissions,
                           is_active=is_active, new_password=new_password)
    if ok:
        log_event("user_updated", current_user.username, current_user.id,
                  category="admin", resource=str(uid), status="success")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@app.route("/admin/users/<int:uid>/delete", methods=["POST"])
@admin_required
def admin_delete_user(uid: int):
    if uid == current_user.id:
        flash("لا يمكنك حذف حسابك الخاص.", "error")
        return redirect(url_for("admin_users"))
    ok, msg = hard_delete_user(uid)
    if ok:
        log_event("user_deleted", current_user.username, current_user.id,
                  category="admin", resource=str(uid), status="success")
        flash("تم حذف المستخدم بنجاح.", "success")
    else:
        flash(msg, "error")
    return redirect(url_for("admin_users"))


@app.route("/admin/scans")
@admin_required
def admin_scans():
    filter_user = request.args.get("user", "").strip()
    filter_type = request.args.get("type", "").strip()
    all_reports = get_all_reports(limit=500)
    if filter_user:
        all_reports = [r for r in all_reports if filter_user.lower() in (r.get("username") or "").lower()]
    if filter_type:
        all_reports = [r for r in all_reports if r.get("scan_type") == filter_type]
    top_vulns = get_top_vulnerabilities(limit=10)
    return render_template(
        "admin_scans.html",
        reports=all_reports, top_vulns=top_vulns,
        filter_user=filter_user, filter_type=filter_type,
        user=current_user.username,
    )


@app.route("/admin/scans/<token>/delete", methods=["POST"])
@admin_required
def admin_delete_scan(token: str):
    if not _UUID_RE.match(token):
        return jsonify({"error": "رمز التقرير غير صالح."}), 400
    ok, msg = delete_report(token)
    if ok:
        log_event("scan_deleted", current_user.username, current_user.id,
                  category="admin", resource=token, status="success")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@app.route("/admin/audit")
@admin_required
def admin_audit():
    uid      = request.args.get("user_id", type=int)
    category = request.args.get("category")
    action   = request.args.get("action")
    logs, _  = get_audit_log(user_id=uid, category=category, action=action, limit=200)
    stats    = get_audit_stats()
    return render_template(
        "audit_log.html",
        logs=logs, stats=stats, user=current_user.username,
    )


# ════════════════════════════════════════════════════════════════════════════
#  HEALTH CHECK
# ════════════════════════════════════════════════════════════════════════════

@app.route("/health", methods=["GET", "OPTIONS"])
@csrf.exempt
@cross_origin(origins="*", supports_credentials=False)   # public ping — no auth needed
def health():
    """Lightweight liveness probe — called by the login page to detect server wake-up."""
    try:
        from database import _get_db
        _get_db().execute("SELECT 1").fetchone()
        status = "ok"
    except Exception:
        status = "degraded"
    return jsonify({"status": status, "service": "cybrain"}), 200


@app.route("/api/stats")
@login_required
def platform_stats():
    """Public platform-level counters for the scan form stats bar."""
    try:
        raw = get_system_stats()
        return jsonify({
            "total_scans":  int(raw.get("total_scans", 0)),
            "total_vulns":  int(raw.get("total_vulns",  0)),
        })
    except Exception:
        return jsonify({"total_scans": 0, "total_vulns": 0})


# ════════════════════════════════════════════════════════════════════════════
#  REACT API BRIDGE  ── JSON endpoints for the React frontend
#  These routes mirror existing logic but return pure JSON.
#  NO existing logic is changed — only new routes are added here.
# ════════════════════════════════════════════════════════════════════════════

# ── Auth ──────────────────────────────────────────────────────────────────

@app.route("/api/auth/login", methods=["POST"])
@csrf.exempt
@limiter.limit("10/minute")
def api_login():
    if current_user.is_authenticated:
        return jsonify({"ok": True, "user": {"username": current_user.username, "role": current_user.role}})

    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password required."}), 400

    user, err, lock_secs = authenticate_user(username, password)
    if not user:
        log_event("login_failed", username, category="auth",
                  ip_address=request.remote_addr, status="failed", details=err)
        resp = {"ok": False, "error": err or "Invalid credentials."}
        if lock_secs:
            resp["lock_seconds_remaining"] = lock_secs
        return jsonify(resp), 401

    if user.totp_enabled:
        session["pending_totp_user_id"] = user.id
        return jsonify({"ok": False, "totp_required": True}), 200

    login_user(user, remember=False)
    update_last_login(user.id)
    log_event("login_success", username, user.id, category="auth",
              ip_address=request.remote_addr, user_agent=request.user_agent.string)
    return jsonify({
        "ok":   True,
        "user": {"username": user.username, "role": user.role, "id": user.id},
    })


@app.route("/api/auth/logout", methods=["POST"])
@csrf.exempt
@login_required
def api_logout():
    log_event("logout", current_user.username, current_user.id,
              category="auth", ip_address=request.remote_addr)
    logout_user()
    return jsonify({"ok": True})


@app.route("/api/auth/me")
def api_me():
    if not current_user.is_authenticated:
        return jsonify({"authenticated": False}), 401
    return jsonify({
        "authenticated": True,
        "user": {
            "id":           current_user.id,
            "username":     current_user.username,
            "role":         current_user.role,
            "is_admin":     current_user.is_admin,
            "permissions":  list(current_user._permissions),
            "totp_enabled": current_user.totp_enabled,
            "is_active":    current_user.is_active,
            "last_login":   current_user.last_login,
            "login_count":  current_user.login_count,
        },
    })


# ── TOTP verify (React API) ────────────────────────────────────────────────

@app.route("/api/auth/totp-verify", methods=["POST"])
@csrf.exempt
@limiter.limit("10/minute")
def api_totp_verify():
    """Verify a TOTP code for a pending login session (React frontend)."""
    pending_id = session.get("pending_totp_user_id")
    if not pending_id:
        return jsonify({"ok": False, "error": "No pending TOTP session."}), 400

    data  = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    if not token:
        return jsonify({"ok": False, "error": "Token required."}), 400

    row = get_user_by_id(pending_id)
    if not row:
        session.pop("pending_totp_user_id", None)
        return jsonify({"ok": False, "error": "Session expired."}), 401

    from models import _row_to_user
    user = _row_to_user(row)
    if not user.verify_totp(token):
        log_event("totp_failed", category="auth",
                  ip_address=request.remote_addr, status="failed")
        return jsonify({"ok": False, "error": "Invalid TOTP code."}), 401

    session.pop("pending_totp_user_id", None)
    login_user(user, remember=False)
    update_last_login(user.id)
    log_event("totp_verified", user.username, user.id,
              category="auth", ip_address=request.remote_addr, status="success")
    return jsonify({
        "ok":   True,
        "user": {"username": user.username, "role": user.role, "id": user.id},
    })


# ── TOTP setup / enable (React API) ──────────────────────────────────────

@app.route("/api/auth/totp/setup", methods=["POST"])
@login_required
@csrf.exempt
def api_totp_setup():
    """Generate a new TOTP secret and return QR code as base64 PNG."""
    secret = pyotp.random_base32()
    session["totp_setup_secret"] = secret
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=current_user.username, issuer_name="CyBrain Security"
    )
    import qrcode as _qrcode
    img = _qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return jsonify({"secret": secret, "qr_b64": qr_b64})


@app.route("/api/auth/totp/enable", methods=["POST"])
@login_required
@csrf.exempt
def api_totp_enable():
    """Verify TOTP token then persist totp_enabled=True."""
    data   = request.get_json(silent=True) or {}
    token  = (data.get("token") or "").strip()
    secret = session.get("totp_setup_secret")
    if not secret:
        return jsonify({"ok": False, "error": "No TOTP setup session found."}), 400
    if not token:
        return jsonify({"ok": False, "error": "Token required."}), 400
    if not pyotp.TOTP(secret).verify(token, valid_window=1):
        return jsonify({"ok": False, "error": "Invalid verification code."}), 400
    ok, msg = update_user_totp(current_user.id, secret, True)
    if ok:
        session.pop("totp_setup_secret", None)
        log_event("totp_enabled", current_user.username, current_user.id,
                  category="auth", ip_address=request.remote_addr)
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 500)


# ── Change password (React JSON API) ─────────────────────────────────────

@app.route("/api/auth/change-password", methods=["POST"])
@login_required
@csrf.exempt
def api_change_password():
    """JSON endpoint: verify current password, enforce complexity on new."""
    data       = request.get_json(silent=True) or {}
    current_pw = data.get("current_password", "")
    new_pw     = data.get("new_password", "")

    if not current_pw or not new_pw:
        return jsonify({"ok": False, "error": "current_password and new_password required."}), 400

    row = get_user_by_id(current_user.id)
    if not row or not bcrypt.checkpw(current_pw.encode("utf-8"), row["password_hash"].encode("utf-8")):
        return jsonify({"ok": False, "error": "Current password is incorrect."}), 400

    ok, msg = check_password_complexity(new_pw)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400

    update_user(current_user.id, new_password=new_pw)
    log_event("password_changed", current_user.username, current_user.id,
              category="auth", ip_address=request.remote_addr)
    return jsonify({"ok": True, "message": "Password changed successfully."})


# ── Self-registration ─────────────────────────────────────────────────────

@app.route("/api/auth/register", methods=["POST"])
@csrf.exempt
@limiter.limit("5/minute")
def api_register():
    """
    Self-registration endpoint.
    Creates an analyst account (unprivileged). Admin can promote later.
    Rate-limited to 5/minute to prevent account enumeration.
    """
    data     = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password required."}), 400

    if len(username) < 3 or len(username) > 32:
        return jsonify({"ok": False, "error": "Username must be 3–32 characters."}), 400
    if not re.match(r"^[a-zA-Z0-9_\-]+$", username):
        return jsonify({"ok": False, "error": "Username may only contain letters, digits, _ and -."}), 400

    ok, msg = check_password_complexity(password)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400

    ok, msg = create_user(username, password, role="analyst", created_by="self-registration")
    if not ok:
        return jsonify({"ok": False, "error": msg}), 409

    log_event("user_registered", username, category="auth",
              ip_address=request.remote_addr, status="success")
    logger.info("self-registration | user=%s | ip=%s", username, request.remote_addr)
    return jsonify({"ok": True, "message": "Account created. You can now log in."}), 201


# ── Dashboard ─────────────────────────────────────────────────────────────

@app.route("/api/dashboard")
@login_required
def api_dashboard():
    if current_user.role == "admin":
        stats   = get_all_dashboard_stats()
        reports = get_all_reports(limit=20)
    else:
        stats   = get_dashboard_stats(current_user.id)
        reports = get_user_reports(current_user.id, limit=20)

    # Serialize reports (sqlite Row objects → dict)
    reports_list = []
    for r in reports:
        reports_list.append({
            "token":          r.get("token"),
            "target":         r.get("target"),
            "scan_type":      r.get("scan_type"),
            "risk_score":     r.get("risk_score"),
            "vuln_count":     r.get("vuln_count", 0),
            "critical_count": r.get("critical_count", 0),
            "high_count":     r.get("high_count", 0),
            "medium_count":   r.get("medium_count", 0),
            "stored_at":      r.get("stored_at"),
            "username":       r.get("username"),
        })

    stats_dict = dict(stats) if stats else {}
    return jsonify({"stats": stats_dict, "reports": reports_list})


# ── Reports ───────────────────────────────────────────────────────────────

@app.route("/api/reports")
@login_required
def api_reports():
    if current_user.role == "admin":
        reports = get_all_reports(limit=100)
    else:
        reports = get_user_reports(current_user.id, limit=100)
    return jsonify({"reports": [dict(r) for r in reports]})


@app.route("/api/reports/<token>")
@login_required
@limiter.limit("30/minute")
def api_report(token: str):
    if not _UUID_RE.match(token):
        return jsonify({"error": "Invalid report token."}), 400
    data = get_report(token)
    if not data:
        return jsonify({"error": "Report not found."}), 404
    if data.get("user_id") != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Access denied."}), 403
    return jsonify({
        "result":     data["result"],
        "risk_score": data["risk_score"],
        "stored_at":  data["stored_at"],
        "has_fix":    bool(data.get("original_content")),
        "token":      token,
        "user":       current_user.username,
    })


@app.route("/api/reports/<token>", methods=["DELETE"])
@login_required
@csrf.exempt
def api_delete_report(token: str):
    if not _UUID_RE.match(token):
        return jsonify({"error": "Invalid report token."}), 400
    data = get_report(token)
    if not data:
        return jsonify({"error": "Report not found."}), 404
    if data.get("user_id") != current_user.id and current_user.role != "admin":
        log_event("idor_attempt", current_user.username, current_user.id,
                  category="security", resource=f"/api/reports/{token}",
                  ip_address=request.remote_addr, status="blocked")
        return jsonify({"error": "Access denied."}), 403
    ok, msg = delete_report(token)
    if ok:
        log_event("report_deleted", current_user.username, current_user.id,
                  category="scan", resource=token, status="success")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 500)


def _rtl_text(text: str) -> str:
    """Apply Arabic reshaping + bidi reorder if libraries are available."""
    try:
        import arabic_reshaper
        from bidi.algorithm import get_display
        return get_display(arabic_reshaper.reshape(text))
    except Exception:
        return text


@app.route("/download_report")
@login_required
@limiter.limit("10/minute")
def download_report_pdf():
    """Download report as a professional PDF (with Arabic RTL support when lang=ar)."""
    token = request.args.get("token", "").strip()
    lang  = request.args.get("lang", "en").strip().lower()
    if token and _UUID_RE.match(token):
        data = get_report(token)
    else:
        rows = get_user_reports(current_user.id, limit=1)
        data = rows[0] if rows else None
    if not data:
        return jsonify({"error": "No report found. Run a scan first."}), 404
    if data.get("user_id") != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Access denied."}), 403

    result = data.get("result") or {}
    vulns  = result.get("vulnerabilities", [])
    target = result.get("target", "unknown")
    score  = data.get("risk_score", 0)
    arabic = lang == "ar"

    try:
        from reportlab.lib import colors as rl_colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf, pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm, bottomMargin=2*cm,
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "title", parent=styles["Title"],
            fontSize=20, spaceAfter=6,
            alignment=2 if arabic else 0,
        )
        h2_style = ParagraphStyle(
            "h2", parent=styles["Heading2"],
            fontSize=13, spaceAfter=4,
            alignment=2 if arabic else 0,
        )
        body_style = ParagraphStyle(
            "body", parent=styles["Normal"],
            fontSize=9, leading=14,
            alignment=2 if arabic else 0,
        )

        SEV_COLOR = {
            "critical": rl_colors.HexColor("#c0392b"),
            "high":     rl_colors.HexColor("#e67e22"),
            "medium":   rl_colors.HexColor("#f1c40f"),
            "low":      rl_colors.HexColor("#2ecc71"),
            "info":     rl_colors.HexColor("#3498db"),
        }

        def _p(text: str, style=None) -> Paragraph:
            t = _rtl_text(text) if arabic else text
            return Paragraph(t, style or body_style)

        def _label(text: str) -> str:
            return _rtl_text(text) if arabic else text

        story = [
            _p("CyBrain Security Platform — Vulnerability Report", title_style),
            HRFlowable(width="100%", thickness=1, color=rl_colors.HexColor("#2c3e50")),
            Spacer(1, 0.3*cm),
            _p(f"Target: {target}"),
            _p(f"Risk Score: {score:.1f} / 10"),
            _p(f"Findings: {len(vulns)}"),
            _p(f"Generated: {data.get('stored_at', '')}"),
            Spacer(1, 0.5*cm),
            _p("Findings", h2_style),
            HRFlowable(width="100%", thickness=0.5, color=rl_colors.grey),
            Spacer(1, 0.3*cm),
        ]

        for i, v in enumerate(vulns, 1):
            sev   = (v.get("severity") or "info").lower()
            title = v.get("title") or v.get("check") or "Finding"
            desc  = v.get("description") or ""
            rem   = v.get("remediation") or ""
            color = SEV_COLOR.get(sev, rl_colors.grey)
            badge = [[_label(f"[{sev.upper()}]  {title}")]]
            tbl   = Table(badge, colWidths=[doc.width])
            tbl.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), color),
                ("TEXTCOLOR",  (0, 0), (-1, -1), rl_colors.white),
                ("FONTSIZE",   (0, 0), (-1, -1), 10),
                ("FONTNAME",   (0, 0), (-1, -1), "Helvetica-Bold"),
                ("LEFTPADDING",  (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING",   (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
            ]))
            story.append(tbl)
            if desc:
                story.append(_p(desc))
            if rem:
                story.append(_p(f"Remediation: {rem}"))
            story.append(Spacer(1, 0.4*cm))

        doc.build(story)
        pdf_bytes = buf.getvalue()
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": "attachment; filename=cybrain_report.pdf"},
        )

    except ImportError:
        # Graceful degradation: serve Markdown if reportlab not installed
        lines = [
            "# CyBrain Security Report",
            f"**Target:** {target}",
            f"**Risk Score:** {score}/10",
            f"**Generated:** {data.get('stored_at', '')}",
            f"**Total Findings:** {len(vulns)}",
            "", "---", "", "## Findings", "",
        ]
        for i, v in enumerate(vulns, 1):
            sev   = (v.get("severity") or "info").upper()
            title = v.get("title") or v.get("check") or "Finding"
            desc  = v.get("description") or ""
            rem   = v.get("remediation") or ""
            lines += [f"### {i}. [{sev}] {title}", desc, f"Remediation: {rem}" if rem else "", ""]
        return current_app.response_class(
            "\n".join(lines),
            mimetype="text/markdown",
            headers={"Content-Disposition": "attachment; filename=vulnerability_report.md"},
        )


@app.route("/download_report_csv")
@login_required
@limiter.limit("10/minute")
def download_report_csv():
    """Download most recent report as CSV."""
    token = request.args.get("token", "").strip()
    if token and _UUID_RE.match(token):
        data = get_report(token)
    else:
        rows = get_user_reports(current_user.id, limit=1)
        data = rows[0] if rows else None
    if not data:
        return jsonify({"error": "No report found. Run a scan first."}), 404
    if data.get("user_id") != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Access denied."}), 403

    result = data.get("result") or {}
    vulns  = result.get("vulnerabilities", [])
    buf    = io.StringIO()
    w      = csv.writer(buf)
    w.writerow(["Severity", "Title", "Description", "Evidence", "Remediation", "CVE IDs"])
    for v in vulns:
        w.writerow([
            (v.get("severity") or "").upper(),
            v.get("title") or v.get("check") or "",
            v.get("description") or "",
            v.get("evidence") or "",
            v.get("remediation") or "",
            ", ".join(v.get("cve_ids") or []),
        ])
    return current_app.response_class(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=findings_summary.csv"},
    )


@app.route("/download_report_json")
@login_required
@limiter.limit("10/minute")
def download_report_json():
    """Download most recent report as raw JSON."""
    token = request.args.get("token", "").strip()
    if token and _UUID_RE.match(token):
        data = get_report(token)
    else:
        rows = get_user_reports(current_user.id, limit=1)
        data = rows[0] if rows else None
    if not data:
        return jsonify({"error": "No report found. Run a scan first."}), 404
    if data.get("user_id") != current_user.id and current_user.role != "admin":
        return jsonify({"error": "Access denied."}), 403

    payload = json.dumps(data.get("result") or {}, indent=2, ensure_ascii=False)
    return current_app.response_class(
        payload,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=findings.json"},
    )


# ── Admin ─────────────────────────────────────────────────────────────────

@app.route("/api/admin/stats")
@admin_required
def api_admin_stats():
    stats     = get_system_stats()
    top_vulns = get_top_vulnerabilities(limit=10)
    return jsonify({"stats": dict(stats), "top_vulns": list(top_vulns)})


@app.route("/api/admin/users")
@admin_required
def api_admin_users():
    page     = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    per_page = min(max(per_page, 1), 200)
    users    = get_all_users(page=page, per_page=per_page)
    total    = count_users()
    return jsonify({
        "users":    [dict(u) for u in users],
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    max(1, -(-total // per_page)),
    })


@app.route("/api/admin/users", methods=["POST"])
@admin_required
@csrf.exempt
@limiter.limit("20/minute")
def api_admin_create_user():
    data           = request.get_json(silent=True) or {}
    username       = (data.get("username") or "").strip()
    password       = data.get("password", "")
    confirm        = data.get("confirm_password", "")
    role           = data.get("role", "analyst")
    allowed_target = (data.get("allowed_target") or "").strip()

    if not username or not password:
        return jsonify({"ok": False, "error": "Username and password required."}), 400
    if password != confirm:
        return jsonify({"ok": False, "error": "Passwords do not match."}), 400

    ok, msg = check_password_complexity(password)
    if not ok:
        return jsonify({"ok": False, "error": msg}), 400

    # Normalise the target the same way scan enforcement does
    normalized_target = _normalize_target(allowed_target) if allowed_target else None

    ok, msg = create_user(
        username, password, role,
        created_by=current_user.username,
        allowed_target=normalized_target,
    )
    if ok:
        log_event("user_created", current_user.username, current_user.id,
                  category="admin", resource=username, status="success",
                  details=f"role={role} allowed_target={normalized_target or 'unrestricted'}")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@app.route("/api/admin/users/<int:uid>", methods=["PATCH"])
@admin_required
@csrf.exempt
def api_admin_update_user(uid: int):
    data                 = request.get_json(silent=True) or {}
    role                 = data.get("role")
    permissions          = data.get("permissions")
    is_active            = data.get("is_active")
    new_password         = data.get("new_password")
    reset_locked_target  = bool(data.get("reset_locked_target", False))
    reset_failed         = bool(data.get("reset_failed_attempts", False))
    # set_allowed_target: empty string = clear, non-empty string = set to that value
    set_allowed_target   = data.get("set_allowed_target")   # None means "not provided"

    if new_password:
        ok, msg = check_password_complexity(new_password)
        if not ok:
            return jsonify({"ok": False, "error": msg}), 400

    # Determine locked_target_value to pass to update_user
    from database import _UNSET as _DB_UNSET
    locked_target_value = _DB_UNSET   # sentinel — don't touch locked_target
    audit_action = "user_updated"

    if reset_locked_target:
        # Explicit clear — handled by reset_locked_target flag in update_user
        audit_action = "target_lock_reset"
    elif set_allowed_target is not None:
        raw = set_allowed_target.strip()
        if raw:
            locked_target_value = _normalize_target(raw)
            audit_action = "target_assigned"
        else:
            # Empty string → clear
            locked_target_value = None
            audit_action = "target_lock_reset"

    ok, msg = update_user(
        uid,
        role=role,
        permissions=permissions,
        is_active=is_active,
        new_password=new_password,
        reset_locked_target=reset_locked_target,
        locked_target_value=locked_target_value,
        failed_attempts=0 if reset_failed else None,
    )
    if ok:
        log_event(audit_action, current_user.username, current_user.id,
                  category="admin", resource=str(uid), status="success")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@app.route("/api/admin/users/<int:uid>", methods=["DELETE"])
@admin_required
@csrf.exempt
def api_admin_delete_user(uid: int):
    if uid == current_user.id:
        return jsonify({"ok": False, "error": "Cannot delete your own account."}), 400
    target_row = get_user_by_id(uid)
    if target_row and target_row["role"] == "admin" and count_active_admins() <= 1:
        return jsonify({"ok": False, "error": "Cannot delete the last active admin account."}), 400
    ok, msg = hard_delete_user(uid)
    if ok:
        log_event("user_deleted", current_user.username, current_user.id,
                  category="admin", resource=str(uid), status="success")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@app.route("/api/admin/scans")
@admin_required
def api_admin_scans():
    filter_user = request.args.get("user", "").strip() or None
    filter_type = request.args.get("type", "").strip() or None
    date_from   = request.args.get("date_from", "").strip() or None
    date_to     = request.args.get("date_to", "").strip() or None
    page        = request.args.get("page", 1, type=int)
    per_page    = min(request.args.get("per_page", 50, type=int), 500)
    all_reports = get_all_reports(
        limit=per_page,
        date_from=date_from,
        date_to=date_to,
        scan_type=filter_type,
        username=filter_user,
    )
    top_vulns = get_top_vulnerabilities(limit=10)
    return jsonify({
        "reports":   [dict(r) for r in all_reports],
        "top_vulns": list(top_vulns),
    })


@app.route("/api/admin/scans/<token>", methods=["DELETE"])
@admin_required
@csrf.exempt
def api_admin_delete_scan(token: str):
    if not _UUID_RE.match(token):
        return jsonify({"ok": False, "error": "Invalid token."}), 400
    ok, msg = delete_report(token)
    if ok:
        log_event("scan_deleted", current_user.username, current_user.id,
                  category="admin", resource=token, status="success")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@app.route("/api/admin/audit")
@admin_required
def api_admin_audit():
    uid       = request.args.get("user_id", type=int)
    category  = request.args.get("category") or None
    action    = request.args.get("action") or None
    date_from = request.args.get("date_from") or None
    date_to   = request.args.get("date_to") or None
    page     = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    logs, total = get_audit_log(user_id=uid, category=category, action=action,
                                date_from=date_from, date_to=date_to,
                                page=page, per_page=per_page)
    return jsonify({"logs": [dict(l) for l in logs], "total": total})


@app.route("/api/admin/ai/clear-all", methods=["POST"])
@admin_required
@csrf.exempt
def api_admin_ai_clear_all():
    aria   = get_aria()
    count  = aria.clear_all_histories()
    log_event("ai_history_cleared", current_user.username, current_user.id,
              "admin", details=f"Cleared {count} AI conversation sessions")
    return jsonify({"message": f"Cleared {count} AI conversation session(s).", "count": count})


# ── React Scan Bridges ────────────────────────────────────────────────────
# These bridge the React endpoint names to the existing Flask scan logic.

@app.route("/scan_url", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("5/minute")
@csrf.exempt
def scan_url_bridge():
    """Bridge: React /scan_url → Flask web scanner."""
    data          = request.get_json(silent=True) or {}
    target        = (data.get("url") or data.get("target") or "").strip()
    has_pii       = bool(data.get("has_pii", False))
    has_payment   = bool(data.get("has_payment", False))
    exploit_known = bool(data.get("exploit_known", False))
    if not target:
        return jsonify({"error": "URL/target required."}), 400
    ok, err = _check_target_lock(target)
    if not ok:
        return err
    try:
        result = run_web_scan(target, cve_check=True, ssl_check=True)
        vulns  = result.get("vulnerabilities", [])
        findings = []
        for v in vulns:
            findings.append({
                "severity": (v.get("severity") or "INFO").upper(),
                "code":     v.get("title") or v.get("check") or "Finding",
                "message":  v.get("description") or v.get("recommendation") or "",
                "file":     target,
            })
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=True,
            has_pii=has_pii, has_payment=has_payment, exploit_known=exploit_known,
        )
        report_token = store_report(result, breakdown.final_score, None,
                                    current_user.id, current_user.username)
        log_event("scan_completed", current_user.username, current_user.id,
                  category="scan", resource=target, status="success",
                  details=f"type=web risk={breakdown.final_score}")
        return jsonify({
            "findings":     findings,
            "risk":         breakdown.risk_level,
            "risk_score":   breakdown.final_score,
            "report_token": report_token,
        })
    except Exception as exc:
        logger.exception("scan_url_bridge error")
        return jsonify({"error": str(exc)}), 500


@app.route("/scan_network", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("3/minute")
@csrf.exempt
def scan_network_bridge():
    """Bridge: React /scan_network → Flask nmap scanner."""
    data          = request.get_json(silent=True) or {}
    target        = (data.get("target") or "").strip()
    mode          = data.get("mode", "full")
    deep          = mode == "full"
    has_pii       = bool(data.get("has_pii", False))
    has_payment   = bool(data.get("has_payment", False))
    exploit_known = bool(data.get("exploit_known", False))
    if not target:
        return jsonify({"error": "Target required."}), 400
    ok, err = _check_target_lock(target)
    if not ok:
        return err
    try:
        result = run_nmap_scan(target, deep=deep)
        vulns  = result.get("vulnerabilities", [])
        findings = []
        for v in vulns:
            findings.append({
                "severity": (v.get("severity") or "INFO").upper(),
                "code":     v.get("title") or v.get("check") or "Finding",
                "message":  v.get("description") or "",
                "file":     target,
            })
        recon = {
            "ip":         result.get("target", target),
            "os":         result.get("os_info", "Unknown"),
            "open_ports": len(result.get("open_ports", [])),
        }
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=True,
            has_pii=has_pii, has_payment=has_payment, exploit_known=exploit_known,
        )
        report_token = store_report(result, breakdown.final_score, None,
                                    current_user.id, current_user.username)
        log_event("scan_completed", current_user.username, current_user.id,
                  category="scan", resource=target, status="success",
                  details=f"type=network risk={breakdown.final_score}")
        return jsonify({
            "findings":     findings,
            "recon":        recon,
            "risk":         breakdown.risk_level,
            "risk_score":   breakdown.final_score,
            "report_token": report_token,
        })
    except Exception as exc:
        logger.exception("scan_network_bridge error")
        return jsonify({"error": str(exc)}), 500


@app.route("/analyze_code", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("5/minute")
@csrf.exempt
def analyze_code_bridge():
    """Bridge: React /analyze_code → SAST scanner."""
    upload = request.files.get("file") or request.files.get("source_file")
    ok_val, err = validate_upload(upload, {".zip"})
    if not ok_val:
        return jsonify({"error": err}), 400
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip", mode="wb") as tmp:
            upload.save(tmp)
            tmp_path = tmp.name
        result = run_sast_scan(tmp_path)
        vulns  = result.get("vulnerabilities", [])
        findings = []
        for v in vulns:
            findings.append({
                "severity": (v.get("severity") or "INFO").upper(),
                "code":     v.get("title") or v.get("check") or "Finding",
                "message":  v.get("description") or "",
                "file":     v.get("file", ""),
                "line":     v.get("line_number"),
            })
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=False,
            has_pii=False, has_payment=False, exploit_known=False,
        )
        report_token = store_report(result, breakdown.final_score, None,
                                    current_user.id, current_user.username)
        return jsonify({
            "findings":     findings,
            "risk":         breakdown.risk_level,
            "risk_score":   breakdown.final_score,
            "report_token": report_token,
        })
    except Exception as exc:
        logger.exception("analyze_code_bridge error")
        return jsonify({"error": str(exc)}), 500
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


@app.route("/fix_config", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("5/minute")
@csrf.exempt
def fix_config_bridge():
    """Bridge: React /fix_config → Apache config scanner."""
    upload = request.files.get("file") or request.files.get("config_file")
    ok_val, err = validate_upload(upload, {".conf", ".txt"})
    if not ok_val:
        return jsonify({"error": err}), 400
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".conf", mode="wb") as tmp:
            upload.save(tmp)
            tmp_path = tmp.name
        with open(tmp_path, encoding="utf-8", errors="replace") as _fh:
            original = _fh.read()
        result   = run_server_config_scan(tmp_path)
        vulns    = result.get("vulnerabilities", [])
        findings = []
        for v in vulns:
            findings.append({
                "severity": (v.get("severity") or "INFO").upper(),
                "code":     v.get("title") or v.get("check") or "Finding",
                "message":  v.get("description") or "",
                "evidence": v.get("evidence", ""),
                "fix":      v.get("fixed_directive", ""),
            })
        fixed_content, change_log = generate_fixed_config(original, vulns)
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=False,
            has_pii=False, has_payment=False, exploit_known=False,
        )
        report_token = store_report(result, breakdown.final_score, original,
                                    current_user.id, current_user.username)
        return jsonify({
            "findings":      findings,
            "fixed_config":  fixed_content,
            "changes":       change_log,
            "risk":          breakdown.risk_level,
            "risk_score":    breakdown.final_score,
            "report_token":  report_token,
        })
    except Exception as exc:
        logger.exception("fix_config_bridge error")
        return jsonify({"error": str(exc)}), 500
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


@app.route("/scan_server", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("3/minute")
@csrf.exempt
def scan_server_bridge():
    """Bridge: React /scan_server → external server scanner (black-box HTTP + TLS + ports)."""
    data          = request.get_json(silent=True) or {}
    target        = (data.get("target") or data.get("url") or "").strip()
    deep          = bool(data.get("deep", False))
    has_pii       = bool(data.get("has_pii", False))
    has_payment   = bool(data.get("has_payment", False))
    exploit_known = bool(data.get("exploit_known", False))
    if not target:
        return jsonify({"error": "Target required."}), 400
    ok, err = _check_target_lock(target)
    if not ok:
        return err
    try:
        result = run_server_scan(target, deep=deep)
        vulns  = result.get("vulnerabilities", [])
        findings = []
        for v in vulns:
            findings.append({
                "severity": (v.get("severity") or "INFO").upper(),
                "code":     v.get("check") or v.get("title") or "Finding",
                "message":  v.get("description") or "",
                "evidence": v.get("evidence", ""),
                "fix":      v.get("remediation", ""),
                "cves":     v.get("cves", []),
            })
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=True,
            has_pii=has_pii, has_payment=has_payment, exploit_known=exploit_known,
        )
        report_token = store_report(result, breakdown.final_score, None,
                                    current_user.id, current_user.username)
        log_event("scan_completed", current_user.username, current_user.id,
                  category="scan", resource=target, status="success",
                  details=f"type=server_ext risk={breakdown.final_score}")
        return jsonify({
            "findings":     findings,
            "risk":         breakdown.risk_level,
            "risk_score":   breakdown.final_score,
            "server_type":  result.get("server_type", "unknown"),
            "server_version": result.get("server_version", ""),
            "report_token": report_token,
        })
    except Exception as exc:
        logger.exception("scan_server_bridge error")
        return jsonify({"error": str(exc)}), 500


@app.route("/scan_dast", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("5/minute")
@csrf.exempt
def scan_dast_bridge():
    """Bridge: React /scan_dast → DAST scanner."""
    data          = request.get_json(silent=True) or {}
    target        = (data.get("url") or data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "Target URL required."}), 400
    ok, err = _check_target_lock(target)
    if not ok:
        return err
    try:
        result = run_dast_scan(target)
        vulns  = result.get("vulnerabilities", [])
        findings = []
        for v in vulns:
            findings.append({
                "severity": (v.get("severity") or "INFO").upper(),
                "code":     v.get("title") or v.get("check") or "Finding",
                "message":  v.get("description") or "",
                "evidence": v.get("evidence") or "",
                "fix":      v.get("remediation") or "",
                "file":     target,
            })
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=True,
            has_pii=False, has_payment=False, exploit_known=False,
        )
        report_token = store_report(result, breakdown.final_score, None,
                                    current_user.id, current_user.username)
        log_event("scan_completed", current_user.username, current_user.id,
                  category="scan", resource=target, status="success",
                  details=f"type=dast risk={breakdown.final_score}")
        return jsonify({
            "findings":     findings,
            "risk":         breakdown.risk_level,
            "risk_score":   breakdown.final_score,
            "report_token": report_token,
        })
    except Exception as exc:
        logger.exception("scan_dast_bridge error")
        return jsonify({"error": str(exc)}), 500


@app.route("/scan_dependencies", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("5/minute")
@csrf.exempt
def scan_dependencies_bridge():
    """Bridge: React /scan_dependencies → Dep scanner."""
    upload = request.files.get("file") or request.files.get("package_file")
    ok_val, err = validate_upload(upload, {".json", ".txt", ".toml"})
    if not ok_val:
        return jsonify({"error": err}), 400
    tmp_path = None
    try:
        fname  = upload.filename.lower()
        suffix = ".json" if fname.endswith(".json") else (".toml" if fname.endswith(".toml") else ".txt")
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, mode="wb") as tmp:
            upload.save(tmp)
            tmp_path = tmp.name
        
        result = run_dep_scan(tmp_path)
        vulns  = result.get("vulnerabilities", [])
        findings = []
        for v in vulns:
            findings.append({
                "severity": (v.get("severity") or "INFO").upper(),
                "code":     v.get("title") or v.get("check") or "Finding",
                "message":  v.get("description") or "",
                "evidence": v.get("evidence") or "",
                "fix":      v.get("remediation") or "",
            })
        breakdown = calculate_risk_v2(
            result, criticality=1.0, internet_facing=False,
            has_pii=False, has_payment=False, exploit_known=False,
        )
        report_token = store_report(result, breakdown.final_score, None,
                                    current_user.id, current_user.username)
        log_event("scan_completed", current_user.username, current_user.id,
                  category="scan", resource="dependencies", status="success",
                  details=f"type=dep risk={breakdown.final_score}")
        return jsonify({
            "findings":     findings,
            "risk":         breakdown.risk_level,
            "risk_score":   breakdown.final_score,
            "report_token": report_token,
        })
    except Exception as exc:
        logger.exception("scan_dependencies_bridge error")
        return jsonify({"error": str(exc)}), 500
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


@app.route("/api/analyze_findings", methods=["POST"])
@login_required
@limiter.limit("20/minute")
@csrf.exempt
def analyze_findings_bridge():
    """Bridge: React /api/analyze_findings → ARIA AI analyze."""
    data      = request.get_json(silent=True) or {}
    findings  = data.get("findings", [])
    target    = data.get("target", "unknown")
    scan_type = data.get("scan_type", "web")
    if not findings:
        return jsonify({"analysis": "No findings to analyze."}), 200
    try:
        aria     = get_aria()
        analysis = aria.analyze_findings(findings, target, scan_type)
        return jsonify({"analysis": analysis})
    except Exception as exc:
        logger.exception("analyze_findings_bridge error")
        return jsonify({"analysis": f"AI analysis error: {exc}"}), 200


@app.route("/api/chat", methods=["POST"])
@login_required
@limiter.limit("30/minute")
@csrf.exempt
def chat_bridge():
    """Bridge: React /api/chat → ARIA AI chat."""
    data    = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    context = data.get("context", {})
    if not message:
        return jsonify({"response": "Empty message."}), 400
    try:
        aria  = get_aria()
        reply = aria.chat(message, context, user_id=str(current_user.id))
        return jsonify({"response": reply})
    except Exception as exc:
        logger.exception("chat_bridge error")
        return jsonify({"response": f"AI error: {exc}"}), 200


# ════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )

