# app.py
"""
CyBrain Security Platform — Flask Application
All routes and app setup in one flat file.
"""

import base64
import io
import logging
import os
import re
import tempfile
from functools import wraps

import bcrypt
import pyotp
import qrcode

from dotenv import load_dotenv
from flask import (
    Flask, Response, flash, jsonify, redirect,
    render_template, request, url_for,
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
    get_user_by_id, get_all_users,
    create_user, update_user, hard_delete_user,
    update_last_login, update_user_totp,
    log_event, get_audit_log, get_audit_stats,
    store_report, get_report, get_user_reports, get_all_reports,
    get_dashboard_stats, get_all_dashboard_stats,
    get_system_stats, delete_report, get_top_vulnerabilities,
)
from models import authenticate_user, load_user_from_db
from forms import LoginForm, ScanForm, TOTPForm, ChangePasswordForm, check_password_complexity
from risk_engine import calculate_risk
from ai_agent import get_aria

from scanners.nmap_scanner  import run_nmap_scan
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

app.config.update(
    SECRET_KEY=SECRET_KEY,
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,
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


def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role != "admin":
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return wrapper


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

        user, err = authenticate_user(username, password)

        if user:
            if user.totp_enabled:
                # Store pending user in session, redirect to TOTP verification
                from flask import session
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
    from flask import session
    pending_id = session.get("pending_totp_user_id")
    if not pending_id:
        return redirect(url_for("login"))

    form = TOTPForm()
    if request.method == "POST":
        token = (request.form.get("token") or "").strip()
        row   = get_user_by_id(pending_id)
        if row:
            from models import _row_to_user
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
        from flask import session
        session["totp_setup_secret"] = secret
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=current_user.username, issuer_name="CyBrain Security"
        )
        img    = qrcode.make(uri)
        buf    = io.BytesIO()
        img.save(buf, "PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
        return render_template("setup_totp.html", form=form, qr_b64=qr_b64, secret=secret)

    from flask import session
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

    target      = form.target.data.strip()
    scan_type   = form.scan_type.data
    deep_scan   = form.deep_scan.data
    cve_check   = form.cve_check.data
    ssl_check   = form.ssl_check.data

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
            if not (upload and upload.filename):
                return jsonify({"error": "فحص السيرفر الداخلي يتطلب رفع ملف httpd.conf"}), 400
            fname = upload.filename.lower()
            if not (fname.endswith(".conf") or fname.endswith(".txt")):
                return jsonify({"error": "يُقبل فقط .conf أو .txt"}), 400
            upload.seek(0, 2); size = upload.tell(); upload.seek(0)
            if size > 2 * 1024 * 1024:
                return jsonify({"error": "حجم الملف يتجاوز 2MB"}), 400
            with tempfile.NamedTemporaryFile(delete=False, suffix=".conf", mode="wb") as tmp:
                upload.save(tmp)
                tmp_path = tmp.name
            try:
                original_config_content = open(tmp_path, encoding="utf-8", errors="replace").read()
            except OSError:
                pass
            result = run_server_config_scan(tmp_path)

        elif scan_type == "dependencies":
            upload = request.files.get("config_file")
            if not (upload and upload.filename):
                return jsonify({"error": "فحص التبعيات يتطلب رفع requirements.txt أو package.json"}), 400
            fname = upload.filename.lower()
            if not any(fname.endswith(ext) for ext in (".txt", ".json", ".toml")):
                return jsonify({"error": "يُقبل .txt .json .toml فقط"}), 400
            suffix    = ".json" if fname.endswith(".json") else (".toml" if fname.endswith(".toml") else ".txt")
            real_name = upload.filename
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix, mode="wb") as tmp:
                upload.save(tmp)
                tmp_path = tmp.name
            named_path = os.path.join(tempfile.gettempdir(), real_name)
            try:
                os.replace(tmp_path, named_path)
                tmp_path = named_path
            except OSError:
                pass
            result = run_dep_scan(tmp_path)

        elif scan_type == "sast":
            upload = request.files.get("source_file") or request.files.get("config_file")
            if not (upload and upload.filename and upload.filename.lower().endswith(".zip")):
                return jsonify({"error": "فحص SAST يتطلب ملف .zip"}), 400
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

    risk_score   = calculate_risk(result, criticality)
    report_token = store_report(result, risk_score, original_config_content,
                                current_user.id, current_user.username)

    log_event("scan_completed", current_user.username, current_user.id,
              category="scan", resource=target, status="success",
              details=f"type={scan_type} risk={risk_score} findings={len(result.get('vulnerabilities',[]))}")

    logger.info(
        "scan done | user=%s | type=%s | target=%s | risk=%.2f | findings=%d",
        current_user.username, scan_type, target,
        risk_score, len(result.get("vulnerabilities", [])),
    )

    return jsonify({
        "scan_result":  result,
        "risk_score":   risk_score,
        "message":      "تم الفحص بنجاح.",
        "report_token": report_token,
    })


# ════════════════════════════════════════════════════════════════════════════
#  AI ROUTES
# ════════════════════════════════════════════════════════════════════════════

@app.route("/api/ai/analyze", methods=["POST"])
@require_permission("run_scan")
@limiter.limit("20/minute")
def ai_analyze():
    data     = request.get_json(silent=True) or {}
    findings = data.get("findings", [])
    target   = data.get("target", "unknown")
    scan_type = data.get("scan_type", "web")

    if not findings:
        return jsonify({"error": "لا توجد نتائج للتحليل."}), 400

    aria   = get_aria()
    report = aria.analyze_findings(findings, target, scan_type)
    return jsonify({"analysis": report, "ai_mode": "online" if aria.ai_active else "offline"})


@app.route("/api/ai/chat", methods=["POST"])
@login_required
@limiter.limit("30/minute")
def ai_chat():
    data    = request.get_json(silent=True) or {}
    message = (data.get("message") or "").strip()
    context = data.get("context", {})

    if not message:
        return jsonify({"error": "الرسالة فارغة."}), 400
    if len(message) > 2000:
        return jsonify({"error": "الرسالة طويلة جداً (الحد 2000 حرف)."}), 400

    aria  = get_aria()
    reply = aria.chat(message, context)
    return jsonify({"reply": reply, "ai_mode": "online" if aria.ai_active else "offline"})


# ════════════════════════════════════════════════════════════════════════════
#  ADMIN ROUTES
# ════════════════════════════════════════════════════════════════════════════

@app.route("/admin")
@admin_required
def admin_hub():
    stats = get_system_stats()
    return render_template("admin.html", stats=stats, user=current_user.username)


@app.route("/admin/users")
@admin_required
def admin_users():
    users = get_all_users()
    return render_template("admin_users.html", users=users, user=current_user.username)


@app.route("/admin/users/create", methods=["POST"])
@admin_required
@limiter.limit("20/minute")
def admin_create_user():
    username    = request.form.get("username", "").strip()
    password    = request.form.get("password", "")
    role        = request.form.get("role", "analyst")
    permissions = request.form.getlist("permissions") or None

    if not username or not password:
        return jsonify({"error": "اسم المستخدم وكلمة المرور مطلوبان."}), 400

    ok, msg = check_password_complexity(password)
    if not ok:
        return jsonify({"error": msg}), 400

    ok, msg = create_user(username, password, role, permissions, created_by=current_user.username)
    if ok:
        log_event("user_created", current_user.username, current_user.id,
                  category="admin", resource=username, status="success")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


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
        return jsonify({"error": "لا يمكنك حذف حسابك الخاص."}), 400
    ok, msg = hard_delete_user(uid)
    if ok:
        log_event("user_deleted", current_user.username, current_user.id,
                  category="admin", resource=str(uid), status="success")
    return jsonify({"ok": ok, "message": msg}), (200 if ok else 400)


@app.route("/admin/scans")
@admin_required
def admin_scans():
    reports = get_all_reports(limit=200)
    top_vulns = get_top_vulnerabilities(limit=10)
    return render_template(
        "admin_scans.html",
        reports=reports, top_vulns=top_vulns, user=current_user.username,
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
    logs     = get_audit_log(user_id=uid, category=category, action=action, limit=200)
    stats    = get_audit_stats()
    return render_template(
        "admin_audit.html",
        logs=logs, stats=stats, user=current_user.username,
    )


# ════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
