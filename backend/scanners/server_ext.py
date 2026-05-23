# scanners/server_ext.py
"""
Apache / Web-Server Configuration Scanner
─────────────────────────────────────────
يفحص إعدادات السيرفر من الخارج فقط (black-box).
لا يتطلب وصولاً مباشراً للملفات أو SSH.

الفحوصات:
    1. تسريب معلومات الـ Headers
    2. إعدادات TLS/SSL
    3. الصفحات والمسارات الحساسة المكشوفة
    4. HTTP Methods الخطرة
    5. إصدار Apache وما يقابله من CVEs معروفة
"""

import logging
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from urllib.parse import urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════
#  Types & Constants
# ══════════════════════════════════════════════════════

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

# إصدارات Apache القديمة المعروفة بثغرات حرجة
# المصدر: NVD / Apache Security Reports (updated through 2026)
VULNERABLE_APACHE_VERSIONS: dict[str, dict] = {
    # ── 2024–2026 ──────────────────────────────────────────────────────────
    "2.4.58": {
        "cves": ["CVE-2024-38473", "CVE-2024-38474", "CVE-2024-38475", "CVE-2024-38476"],
        "severity": Severity.HIGH,
        "description": "mod_rewrite URL encoding bypass / information disclosure / RCE via server-side includes",
    },
    "2.4.57": {
        "cves": ["CVE-2023-45802"],
        "severity": Severity.HIGH,
        "description": "HTTP/2 stream memory not reclaimed — DoS via memory exhaustion",
    },
    "2.4.56": {
        "cves": ["CVE-2023-27522", "CVE-2023-25690"],
        "severity": Severity.CRITICAL,
        "description": "HTTP request smuggling via mod_proxy (CVE-2023-25690) & mod_rewrite",
    },
    "2.4.55": {
        "cves": ["CVE-2023-27522"],
        "severity": Severity.HIGH,
        "description": "HTTP response splitting in mod_proxy_uwsgi",
    },
    # ── 2022 ───────────────────────────────────────────────────────────────
    "2.4.54": {
        "cves": ["CVE-2022-36760", "CVE-2022-37436"],
        "severity": Severity.HIGH,
        "description": "HTTP request smuggling (mod_proxy_ajp) & response splitting",
    },
    "2.4.53": {
        "cves": ["CVE-2022-22719", "CVE-2022-22720", "CVE-2022-22721"],
        "severity": Severity.CRITICAL,
        "description": "HTTP request smuggling + use-after-free in mod_lua + OOB write",
    },
    "2.4.52": {
        "cves": ["CVE-2021-44790", "CVE-2021-44224"],
        "severity": Severity.CRITICAL,
        "description": "mod_lua buffer overflow & SSRF via mod_proxy",
    },
    # ── 2021 ───────────────────────────────────────────────────────────────
    "2.4.51": {
        "cves": ["CVE-2021-41773"],
        "severity": Severity.CRITICAL,
        "description": "Path Traversal & RCE (partial patch — use 2.4.51 only with 2021-42013 fix)",
    },
    "2.4.50": {
        "cves": ["CVE-2021-42013"],
        "severity": Severity.CRITICAL,
        "description": "Path Traversal bypass — RCE if mod_cgi enabled",
    },
    "2.4.49": {
        "cves": ["CVE-2021-41773", "CVE-2021-42013"],
        "severity": Severity.CRITICAL,
        "description": "Path Traversal & RCE — actively exploited in the wild",
    },
    # ── 2020 ───────────────────────────────────────────────────────────────
    "2.4.46": {
        "cves": ["CVE-2020-11984"],
        "severity": Severity.HIGH,
        "description": "mod_proxy buffer overflow",
    },
    "2.4.43": {
        "cves": ["CVE-2020-1927", "CVE-2020-1934"],
        "severity": Severity.MEDIUM,
        "description": "Redirect & mod_proxy_ftp issues",
    },
}

# إصدارات Nginx القديمة المعروفة بثغرات
VULNERABLE_NGINX_VERSIONS: dict[str, dict] = {
    "1.25.4": {
        "cves": ["CVE-2024-7347"],
        "severity": Severity.MEDIUM,
        "description": "mp4 module out-of-bounds read",
    },
    "1.24.0": {
        "cves": ["CVE-2023-44487"],
        "severity": Severity.HIGH,
        "description": "HTTP/2 Rapid Reset DoS (Rapid Reset Attack)",
    },
    "1.22.1": {
        "cves": ["CVE-2022-41741", "CVE-2022-41742"],
        "severity": Severity.HIGH,
        "description": "mp4 module memory corruption",
    },
    "1.20.2": {
        "cves": ["CVE-2021-23017"],
        "severity": Severity.HIGH,
        "description": "1-byte memory overwrite via DNS response",
    },
}

# مسارات حساسة يجب أن تكون محمية أو غير موجودة
SENSITIVE_PATHS: list[dict] = [
    {"path": "/server-status",  "severity": Severity.HIGH,   "description": "Apache mod_status - يكشف معلومات الـ server و الـ requests الحالية"},
    {"path": "/server-info",    "severity": Severity.HIGH,   "description": "Apache mod_info - يكشف إعدادات الـ modules والـ configuration"},
    {"path": "/.htaccess",      "severity": Severity.MEDIUM, "description": "ملف .htaccess مكشوف"},
    {"path": "/.htpasswd",      "severity": Severity.CRITICAL,"description": "ملف كلمات المرور .htpasswd مكشوف"},
    {"path": "/manual/",        "severity": Severity.LOW,    "description": "دليل Apache المدمج - يكشف الإصدار"},
    {"path": "/icons/",         "severity": Severity.LOW,    "description": "مجلد الأيقونات الافتراضي مكشوف"},
    {"path": "/.git/",          "severity": Severity.CRITICAL,"description": "مجلد Git مكشوف - يمكن تسريب الكود"},
    {"path": "/.env",           "severity": Severity.CRITICAL,"description": "ملف متغيرات البيئة مكشوف"},
    {"path": "/phpinfo.php",    "severity": Severity.HIGH,   "description": "phpinfo() مكشوف - يكشف كل إعدادات PHP والسيرفر"},
    {"path": "/wp-login.php",   "severity": Severity.INFO,   "description": "WordPress login page (تحقق من Brute-Force protection)"},
]

# HTTP Methods الخطرة
DANGEROUS_METHODS: list[dict] = [
    {"method": "TRACE",  "severity": Severity.MEDIUM, "description": "XST - Cross Site Tracing attack vector"},
    {"method": "PUT",    "severity": Severity.HIGH,   "description": "رفع ملفات على السيرفر"},
    {"method": "DELETE", "severity": Severity.HIGH,   "description": "حذف ملفات من السيرفر"},
    {"method": "CONNECT","severity": Severity.MEDIUM, "description": "استخدام السيرفر كـ proxy"},
]

# Timeout settings
REQUEST_TIMEOUT = 10          # ثانية
MAX_REDIRECTS   = 3
CONNECT_TIMEOUT = 5


# ══════════════════════════════════════════════════════
#  Result Schema
# ══════════════════════════════════════════════════════

@dataclass
class Finding:
    """نتيجة فحص واحدة."""
    check:       str
    severity:    Severity
    title:       str
    description: str
    evidence:    str = ""          # القيمة الفعلية التي وجدناها (header value, response code...)
    remediation: str = ""          # كيفية الإصلاح
    cves:        list[str] = field(default_factory=list)

@dataclass
class ServerScanResult:
    """النتيجة الكاملة لفحص السيرفر."""
    target:          str
    server_type:     str = "unknown"     # apache / nginx / iis / unknown
    server_version:  str = ""
    scanned_at:      str = ""
    reachable:       bool = False
    vulnerabilities: list[Finding] = field(default_factory=list)
    info:            list[Finding] = field(default_factory=list)    # ملاحظات غير خطرة
    error:           Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "scan_type":      "server_ext",
            "target":         self.target,
            "server_type":    self.server_type,
            "server_version": self.server_version,
            "scanned_at":     self.scanned_at,
            "reachable":      self.reachable,
            "vulnerabilities": [
                {
                    "check":       f.check,
                    "severity":    f.severity.value,
                    "title":       f.title,
                    "description": f.description,
                    "evidence":    f.evidence,
                    "remediation": f.remediation,
                    "cves":        f.cves,
                }
                for f in self.vulnerabilities
            ],
            "info":  [
                {
                    "check":       f.check,
                    "title":       f.title,
                    "description": f.description,
                    "evidence":    f.evidence,
                }
                for f in self.info
            ],
            "error": self.error,
        }


# ══════════════════════════════════════════════════════
#  HTTP Session Helper
# ══════════════════════════════════════════════════════

def _build_session() -> requests.Session:
    """
    Session مع:
    - لا يتبع redirects تلقائياً (نريد رؤية 301/302 كما هي)
    - Retry محدود على أخطاء الاتصال فقط
    - User-Agent محايد
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
    })

    retry = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "HEAD", "OPTIONS"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://",  adapter)
    session.mount("https://", adapter)

    return session


def _normalize_target(target: str) -> tuple[str, str]:
    """
    يُعيد (http_url, https_url) من الهدف.
    مثال: 'example.com' → ('http://example.com', 'https://example.com')
    """
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target      # نبدأ بـ HTTPS

    parsed   = urlparse(target)
    base     = f"{parsed.scheme}://{parsed.netloc}"
    http_url  = base.replace("https://", "http://")
    https_url = base.replace("http://", "https://")
    return http_url, https_url


# ══════════════════════════════════════════════════════
#  Individual Checks
# ══════════════════════════════════════════════════════

def _check_headers(response: requests.Response) -> tuple[list[Finding], str, str]:
    """
    يفحص HTTP Response Headers.
    يُعيد (findings, server_type, server_version)
    """
    findings       = []
    headers        = response.headers
    server_type    = "unknown"
    server_version = ""

    # ── Server Header ──
    server_header = headers.get("Server", "")
    if server_header:
        findings.append(Finding(
            check="header_server_disclosure",
            severity=Severity.MEDIUM,
            title="تسريب إصدار السيرفر عبر Server Header",
            description="الـ Server header يكشف نوع وإصدار البرنامج، مما يُسهّل استهداف ثغرات محددة.",
            evidence=f"Server: {server_header}",
            remediation=(
                "في httpd.conf:\n"
                "  ServerTokens Prod\n"
                "  ServerSignature Off"
            ),
        ))

        server_lower = server_header.lower()
        if "apache" in server_lower:
            server_type = "apache"
            match = re.search(r"apache/(\d+\.\d+\.\d+)", server_lower)
            if match:
                server_version = match.group(1)

        elif "nginx" in server_lower:
            server_type = "nginx"
            match = re.search(r"nginx/(\d+\.\d+\.\d+)", server_lower)
            if match:
                server_version = match.group(1)

        elif "iis" in server_lower or "microsoft" in server_lower:
            server_type = "iis"

    # ── X-Powered-By Header ──
    powered_by = headers.get("X-Powered-By", "")
    if powered_by:
        findings.append(Finding(
            check="header_x_powered_by",
            severity=Severity.LOW,
            title="تسريب تقنيات الخادم عبر X-Powered-By",
            description="يكشف عن PHP version أو تقنيات backend أخرى.",
            evidence=f"X-Powered-By: {powered_by}",
            remediation=(
                "في php.ini:\n"
                "  expose_php = Off\n"
                "أو في .htaccess:\n"
                "  Header unset X-Powered-By"
            ),
        ))

    # ── Security Headers المفقودة ──
    security_headers = {
        "X-Frame-Options": Finding(
            check="missing_x_frame_options",
            severity=Severity.MEDIUM,
            title="X-Frame-Options مفقود",
            description="الصفحة عرضة لهجمات Clickjacking.",
            evidence="Header غير موجود",
            remediation="Header always append X-Frame-Options SAMEORIGIN",
        ),
        "X-Content-Type-Options": Finding(
            check="missing_x_content_type_options",
            severity=Severity.LOW,
            title="X-Content-Type-Options مفقود",
            description="المتصفح قد يُخمّن نوع المحتوى (MIME sniffing).",
            evidence="Header غير موجود",
            remediation="Header always set X-Content-Type-Options nosniff",
        ),
        "Content-Security-Policy": Finding(
            check="missing_csp",
            severity=Severity.MEDIUM,
            title="Content-Security-Policy مفقود",
            description="لا توجد حماية ضد XSS و Code Injection.",
            evidence="Header غير موجود",
            remediation="Header always set Content-Security-Policy \"default-src 'self'\"",
        ),
        "Strict-Transport-Security": Finding(
            check="missing_hsts",
            severity=Severity.MEDIUM,
            title="HSTS مفقود",
            description="الموقع لا يفرض HTTPS، عرضة لـ SSL Stripping.",
            evidence="Header غير موجود",
            remediation="Header always set Strict-Transport-Security \"max-age=63072000; includeSubDomains\"",
        ),
        "Referrer-Policy": Finding(
            check="missing_referrer_policy",
            severity=Severity.LOW,
            title="Referrer-Policy مفقود",
            description="بيانات الـ Referrer تُرسل كاملة لمواقع خارجية.",
            evidence="Header غير موجود",
            remediation="Header always set Referrer-Policy \"strict-origin-when-cross-origin\"",
        ),
        "Permissions-Policy": Finding(
            check="missing_permissions_policy",
            severity=Severity.LOW,
            title="Permissions-Policy مفقود",
            description="لم يُحدَّد أي قيود على صلاحيات المتصفح (camera, mic, location...).",
            evidence="Header غير موجود",
            remediation="Header always set Permissions-Policy \"camera=(), microphone=(), geolocation=()\"",
        ),
    }

    for header_name, finding in security_headers.items():
        if header_name not in headers:
            findings.append(finding)

    return findings, server_type, server_version


def _check_tls(hostname: str) -> list[Finding]:
    """يفحص إعدادات TLS/SSL."""
    findings = []

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=CONNECT_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert    = ssock.getpeercert()
                version = ssock.version()

                # ── إصدار TLS قديم ──
                if version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                    findings.append(Finding(
                        check="weak_tls_version",
                        severity=Severity.HIGH,
                        title=f"إصدار TLS قديم وغير آمن: {version}",
                        description="الإصدارات القديمة (TLS 1.0/1.1) عرضة لهجمات POODLE و BEAST.",
                        evidence=f"TLS Version: {version}",
                        remediation=(
                            "في httpd.conf أو ssl.conf:\n"
                            "  SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1\n"
                            "  SSLCipherSuite HIGH:!aNULL:!MD5:!3DES"
                        ),
                    ))

                # ── انتهاء صلاحية الشهادة ──
                if cert:
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expiry = expiry.replace(tzinfo=timezone.utc)
                        now    = datetime.now(timezone.utc)
                        days_left = (expiry - now).days

                        if days_left < 0:
                            findings.append(Finding(
                                check="expired_ssl_cert",
                                severity=Severity.CRITICAL,
                                title="شهادة SSL منتهية الصلاحية",
                                description="الشهادة انتهت صلاحيتها، المتصفحات ستُظهر تحذيرات.",
                                evidence=f"Expired: {not_after}",
                                remediation="جدّد الشهادة فوراً. استخدم Let's Encrypt للتجديد التلقائي.",
                            ))
                        elif days_left < 30:
                            findings.append(Finding(
                                check="ssl_cert_expiring_soon",
                                severity=Severity.MEDIUM,
                                title=f"شهادة SSL ستنتهي خلال {days_left} يوم",
                                description="الشهادة قريبة من الانتهاء.",
                                evidence=f"Expires: {not_after} ({days_left} days left)",
                                remediation="جدّد الشهادة قبل انتهائها.",
                            ))

    except ssl.SSLError as e:
        findings.append(Finding(
            check="ssl_error",
            severity=Severity.HIGH,
            title="خطأ في إعدادات SSL",
            description="فشل التحقق من شهادة SSL.",
            evidence=str(e),
            remediation="تحقق من إعدادات SSL في ملف ssl.conf",
        ))
    except (socket.timeout, ConnectionRefusedError, OSError):
        # HTTPS غير متاح — ليس بالضرورة خطأ (قد يعمل على HTTP فقط)
        findings.append(Finding(
            check="https_not_available",
            severity=Severity.HIGH,
            title="HTTPS غير متاح على المنفذ 443",
            description="السيرفر لا يدعم HTTPS أو المنفذ 443 مغلق.",
            evidence="Port 443 unreachable",
            remediation=(
                "فعّل HTTPS عبر mod_ssl:\n"
                "  a2enmod ssl\n"
                "  a2ensite default-ssl\n"
                "  service apache2 restart"
            ),
        ))

    return findings


def _probe_path(item: dict, base_url: str, session: requests.Session) -> Finding | None:
    """Probe a single sensitive path — designed to run inside a thread pool."""
    url = base_url.rstrip("/") + item["path"]
    try:
        resp = session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False, verify=False)
        if resp.status_code == 200:
            return Finding(
                check=f"exposed_path_{item['path'].strip('/').replace('/', '_') or 'root'}",
                severity=item["severity"],
                title=f"مسار حساس مكشوف: {item['path']}",
                description=item["description"],
                evidence=f"HTTP {resp.status_code} - {url}",
                remediation=(
                    f"أضف في .htaccess أو httpd.conf:\n"
                    f"  <Location {item['path']}>\n"
                    f"      Require all denied\n"
                    f"  </Location>"
                ),
            )
        if resp.status_code == 403:
            return Finding(
                check=f"protected_path_{item['path'].strip('/').replace('/', '_') or 'root'}",
                severity=Severity.INFO,
                title=f"مسار موجود لكن محمي: {item['path']}",
                description="الـ path موجود (403) لكن محمي. تحقق أن هذا مقصود.",
                evidence=f"HTTP 403 - {url}",
                remediation="",
            )
    except requests.RequestException:
        pass
    return None


def _check_sensitive_paths(base_url: str, session: requests.Session) -> list[Finding]:
    """Check all sensitive paths in parallel — ~10× faster than sequential."""
    findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=len(SENSITIVE_PATHS), thread_name_prefix="pathprobe") as pool:
        futures = {pool.submit(_probe_path, item, base_url, session): item for item in SENSITIVE_PATHS}
        for fut in as_completed(futures):
            result = fut.result()
            if result is not None:
                findings.append(result)
    return findings


def _check_http_methods(base_url: str, session: requests.Session) -> list[Finding]:
    """يفحص HTTP Methods الخطرة المُفعَّلة."""
    findings = []

    # نستخدم OPTIONS لمعرفة الـ methods المتاحة
    try:
        resp = session.options(
            base_url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            verify=False,
        )

        allow_header = resp.headers.get("Allow", "")
        if allow_header:
            for item in DANGEROUS_METHODS:
                if item["method"] in allow_header.upper():
                    findings.append(Finding(
                        check=f"dangerous_method_{item['method'].lower()}",
                        severity=item["severity"],
                        title=f"HTTP Method خطير مُفعَّل: {item['method']}",
                        description=item["description"],
                        evidence=f"Allow: {allow_header}",
                        remediation=(
                            "في httpd.conf:\n"
                            "  <LimitExcept GET POST HEAD>\n"
                            "      Require all denied\n"
                            "  </LimitExcept>"
                        ),
                    ))

    except requests.RequestException:
        pass

    return findings


def _check_apache_version(version: str) -> list[Finding]:
    """Check Apache version against known CVEs."""
    if not version:
        return []
    findings = []
    vuln = VULNERABLE_APACHE_VERSIONS.get(version)
    if vuln:
        findings.append(Finding(
            check="vulnerable_apache_version",
            severity=vuln["severity"],
            title=f"إصدار Apache يحتوي ثغرات معروفة: {version}",
            description=vuln["description"],
            evidence=f"Apache version: {version}",
            remediation="حدّث Apache إلى أحدث إصدار مستقر (2.4.62+).",
            cves=vuln["cves"],
        ))
    else:
        try:
            major, minor, _ = (int(x) for x in version.split("."))
            if major == 2 and minor < 4:
                findings.append(Finding(
                    check="outdated_apache_major",
                    severity=Severity.HIGH,
                    title=f"إصدار Apache قديم جداً: {version}",
                    description="الفرع 2.2 وما قبله لم يعد مدعوماً وبه ثغرات متعددة.",
                    evidence=f"Apache version: {version}",
                    remediation="رقّ إلى Apache 2.4.62+.",
                ))
        except ValueError:
            pass
    return findings


def _check_nginx_version(version: str) -> list[Finding]:
    """Check Nginx version against known CVEs."""
    if not version:
        return []
    findings = []
    vuln = VULNERABLE_NGINX_VERSIONS.get(version)
    if vuln:
        findings.append(Finding(
            check="vulnerable_nginx_version",
            severity=vuln["severity"],
            title=f"إصدار Nginx يحتوي ثغرات معروفة: {version}",
            description=vuln["description"],
            evidence=f"Nginx version: {version}",
            remediation="حدّث Nginx إلى أحدث إصدار مستقر (1.26.x+).",
            cves=vuln["cves"],
        ))
    else:
        try:
            major, minor, _ = (int(x) for x in version.split("."))
            if major == 1 and minor < 20:
                findings.append(Finding(
                    check="outdated_nginx_major",
                    severity=Severity.HIGH,
                    title=f"إصدار Nginx قديم جداً: {version}",
                    description="الإصدارات قبل 1.20 لم تعد مدعومة وتحتوي ثغرات متعددة.",
                    evidence=f"Nginx version: {version}",
                    remediation="رقّ إلى Nginx 1.26.x (mainline) أو 1.24.x (stable).",
                ))
        except ValueError:
            pass
    return findings


# ══════════════════════════════════════════════════════
#  Public Entry Point
# ══════════════════════════════════════════════════════

def run_server_scan(target: str, deep: bool = False) -> dict:
    """
    نقطة الدخول الرئيسية — تُستدعى من app.py.

    يُجمع بين:
    - فحص المنافذ والخدمات عبر Nmap
    - فحص HTTP-level (Headers، SSL، مسارات حساسة، HTTP Methods)

    Args:
        target: النطاق أو عنوان IP (مثال: example.com أو 192.168.1.1)
        deep:   إذا True، يُنفّذ فحوصات إضافية (أبطأ)

    Returns:
        dict يتوافق مع schema الـ risk_engine ويحتوي على "vulnerabilities"
    """
    logger.info("بدء فحص السيرفر الخارجي | target=%s | deep=%s", target, deep)

    http_url, https_url = _normalize_target(target)
    hostname = urlparse(https_url).netloc.split(":")[0]

    result = ServerScanResult(
        target=target,
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )

    session = _build_session()

    # ══════════════════════════════════════════════════
    #  المرحلة 1: فحص المنافذ والخدمات عبر Nmap
    # ══════════════════════════════════════════════════
    try:
        import nmap  # type: ignore
        nm = nmap.PortScanner()
        nmap_args = "-sV -O --open -T4" if deep else "-sV --open -T4 --top-ports 1000"
        logger.info("netscan | target=%s | args=%s", target, nmap_args)

        nm.scan(hosts=target, arguments=nmap_args)

        _HIGH_RISK_PORTS  = {21, 23, 25, 53, 135, 137, 138, 139, 445, 3389, 4444, 5900}
        _MEDIUM_RISK_PORTS = {22, 80, 443, 3306, 5432, 6379, 27017, 8080, 8443}

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    info = nm[host][proto][port]
                    if info.get("state") != "open":
                        continue

                    service = info.get("name", "unknown")
                    product = info.get("product", "")
                    version = info.get("version", "")
                    ver_str = f"{product} {version}".strip()

                    # تقييم الخطورة
                    if port in _HIGH_RISK_PORTS or service in ("telnet", "ftp", "netbios-ssn", "msrpc"):
                        sev = Severity.HIGH
                    elif port in _MEDIUM_RISK_PORTS:
                        sev = Severity.MEDIUM
                    else:
                        sev = Severity.LOW

                    result.vulnerabilities.append(Finding(
                        check=f"open_port_{port}_{proto}",
                        severity=sev,
                        title=f"منفذ مفتوح: {port}/{proto} — {service}",
                        description=(
                            f"المنفذ {port}/{proto} مفتوح يُشغّل {service}"
                            + (f" ({ver_str})" if ver_str else "")
                        ),
                        evidence=f"Host: {host} | Port: {port}/{proto} | Service: {service} | Version: {ver_str}",
                        remediation=(
                            f"أغلق المنفذ {port} إذا لم يكن ضرورياً:\n"
                            f"  iptables -A INPUT -p {proto} --dport {port} -j DROP\n"
                            f"أو عبر firewall الخادم."
                        ),
                    ))

            # OS Detection
            if deep and "osmatch" in nm[host]:
                for osmatch in nm[host]["osmatch"][:1]:
                    result.info.append(Finding(
                        check="os_detection",
                        severity=Severity.INFO,
                        title=f"نظام التشغيل المحتمل: {osmatch.get('name', 'Unknown')}",
                        description=f"دقة الكشف: {osmatch.get('accuracy', '?')}%",
                        evidence=str(osmatch),
                    ))

    except ImportError:
        logger.warning("netscan (python-nmap) غير مثبّت — تخطّي فحص المنافذ")
        result.info.append(Finding(
            check="netscan_unavailable",
            severity=Severity.INFO,
            title="فحص المنافذ غير متاح",
            description="python-nmap غير مثبّت. شغّل: pip install python-nmap",
            evidence="ImportError: nmap module",
        ))
    except Exception as exc:
        logger.warning("netscan scan failed | target=%s | error=%s", target, exc)
        result.info.append(Finding(
            check="netscan_failed",
            severity=Severity.INFO,
            title="فشل فحص المنافذ",
            description=f"فشل ماسح netscan (nmap): {exc}. تأكد من تثبيت nmap على النظام والأذونات الكافية.",
            evidence=str(exc),
        ))

    # ══════════════════════════════════════════════════
    #  المرحلة 2: فحص HTTP-level
    # ══════════════════════════════════════════════════
    active_url    = None
    base_response = None

    for url in (https_url, http_url):
        try:
            resp = session.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                verify=False,
            )
            active_url    = url
            base_response = resp
            result.reachable = True
            logger.info("اتصال HTTP ناجح | url=%s | status=%s", url, resp.status_code)
            break
        except requests.RequestException as e:
            logger.debug("فشل الاتصال | url=%s | error=%s", url, e)

    if active_url and base_response is not None:
        header_findings, server_type, server_version = _check_headers(base_response)
        result.server_type    = server_type
        result.server_version = server_version

        version_findings = (
            _check_apache_version(server_version)
            if server_type == "apache"
            else _check_nginx_version(server_version)
            if server_type == "nginx"
            else []
        )
        http_findings = (
            header_findings
            + _check_tls(hostname)
            + _check_sensitive_paths(active_url, session)
            + _check_http_methods(active_url, session)
            + version_findings
        )

        for finding in http_findings:
            if finding.severity == Severity.INFO:
                result.info.append(finding)
            else:
                result.vulnerabilities.append(finding)
    else:
        result.info.append(Finding(
            check="http_unreachable",
            severity=Severity.INFO,
            title="HTTP/HTTPS غير متاح",
            description=f"لم ينجح الاتصال HTTP/HTTPS بـ {target}. تم إجراء فحص المنافذ فقط.",
            evidence="Connection refused or timeout",
        ))

    if not result.vulnerabilities and not result.reachable:
        result.error = f"تعذّر الاتصال بالهدف ولا توجد منافذ مكتشفة: {target}"

    logger.info(
        "اكتمل فحص السيرفر الخارجي | target=%s | netscan_findings=%d | http_findings=%d",
        target, len(result.vulnerabilities), len(result.info),
    )

    return result.to_dict()