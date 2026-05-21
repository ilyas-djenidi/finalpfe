# scanners/server_int.py
"""
Apache / Nginx Config File Scanner — White-Box Analysis
═══════════════════════════════════════════════════════
يُحلّل ملف httpd.conf / nginx.conf مباشرةً ويبحث عن ثغرات الإعداد.

الفحوصات المُطبَّقة (Apache):
────────────────────────────────
 [1]  ServerTokens               — يكشف إصدار السيرفر في HTTP Headers (CIS 2.2)
 [2]  ServerSignature            — يُظهر التوقيع في صفحات الخطأ (CIS 2.3)
 [3]  Directory Listing          — Options Indexes يعرض قائمة الملفات (CIS 3.6)
 [4]  FollowSymLinks             — رابط رمزي خارج DocumentRoot (CIS 3.7)
 [5]  SSL/TLS Protocol          — بروتوكولات قديمة SSLv2/3 - TLS 1.0/1.1 (CIS 7.x)
 [6]  SSL Cipher Suite          — خوارزميات ضعيفة RC4/DES/NULL/EXPORT (CIS 7.x)
 [7]  SSLHonorCipherOrder       — السيرفر يُفضّل cipher العميل الضعيف (CIS 7.x)
 [8]  Dangerous Modules         — mod_status/info/userdir/autoindex/cgi (CIS 4.x)
 [9]  TraceEnable               — HTTP TRACE يُمكّن Cross-Site Tracing XST (CIS 5.3)
[10]  Timeout                   — قيمة عالية تُسهّل Slowloris DoS (CIS 5.x)
[11]  Access Control            — Require all granted على root (CIS 3.x)
[12]  PHP expose_php            — يكشف إصدار PHP في X-Powered-By (CIS 5.x)
[13]  LimitRequestLine          — طول عنوان HTTP غير محدود (CIS 5.4 / L2)
[14]  LimitRequestFields        — عدد Headers غير محدود (CIS 5.5 / L2)
[15]  LimitRequestFieldSize     — حجم Header غير محدود (CIS 5.6 / L2)
[16]  LimitRequestBody          — حجم الطلب غير محدود يُسهّل DoS (CIS 5.7 / L2)
[17]  Security Headers          — X-Frame, HSTS, CSP, X-Content-Type, Referrer (OWASP/CIS)
[18]  HTTP Methods              — LimitExcept يُقيّد Methods الخطرة (OWASP)
[19]  AllowOverride             — .htaccess يُجاوز إعدادات الأمان (CIS 3.5)
[20]  KeepAliveTimeout          — Timeout طويل في Persistent connections (CIS 5.x)
[21]  ErrorLog / LogLevel       — التسجيل ضروري للكشف عن الهجمات (CIS 6.x)
[22]  mod_security (WAF)        — جدار حماية التطبيقات غير مُفعَّل (CIS L2)
[23]  FileETag                  — يُسرب inode معلومات نظام الملفات (CIS 5.2)
[24]  Options ExecCGI           — تنفيذ CGI في مجلدات غير ضرورية (CIS 3.x)
[25]  MPM Mode                  — prefork غير مناسب للإنتاج الحديث (Apache Perf)
[26]  MaxRequestWorkers         — غير مضبوط/قيمة غير متوازنة (Apache Perf)
[27]  MaxConnectionsPerChild    — صفر/غير مضبوط يراكم memory leaks (Apache Perf)
[28]  KeepAlive Requests        — KeepAlive/MaxKeepAliveRequests غير متوازن
[29]  Compression & Caching     — mod_deflate/mod_expires غير مفعّلين
[30]  Functional LogFormat      — لا يتضمن %D (زمن المعالجة)
[31]  sendfile/mmap Explicitness— عدم التصريح قد يسبب سلوك غير متوقع

الفحوصات المُطبَّقة (Nginx):
──────────────────────────────
 [N1] server_tokens             — يكشف الإصدار
 [N2] autoindex                 — Directory listing
 [N3] ssl_protocols             — TLS 1.0/1.1 قديم
 [N4] ssl_ciphers               — خوارزميات ضعيفة
 [N5] Security Headers          — X-Frame, HSTS, CSP, X-Content-Type
 [N6] client_max_body_size      — غير محدود يُسهّل DoS
 [N7] keepalive_timeout         — مرتفع يستهلك الاتصالات
 [N8] gzip                      — الضغط غير مفعّل (أداء)
 [N9] sendfile                  — غير مصرح به بوضوح
 [N10] access_log request_time  — غياب زمن المعالجة في الرصد

لا يحتاج اتصالاً بالإنترنت — تحليل نصي بالكامل.
مرجع: CIS Apache HTTP Server 2.4 Benchmark v2.3.0 L2 (2026)
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════
#  Types
# ══════════════════════════════════════════════════════

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


@dataclass
class ConfigFinding:
    check:           str
    severity:        Severity
    title:           str
    description:     str
    evidence:        str = ""      # السطر الفعلي من الملف + رقمه
    remediation:     str = ""
    line_number:     int = 0
    fixed_directive: str = ""     # السطر المُصحَّح الجاهز للاستبدال


@dataclass
class ConfigScanResult:
    config_file:     str
    apache_version:  str = ""
    scanned_at:      str = ""
    vulnerabilities: list[ConfigFinding] = field(default_factory=list)
    info:            list[ConfigFinding] = field(default_factory=list)
    error:           Optional[str] = None
    total_lines:     int = 0

    def to_dict(self) -> dict:
        return {
            "scan_type":      "server_config",
            "config_file":    self.config_file,
            "apache_version": self.apache_version,
            "scanned_at":     self.scanned_at,
            "total_lines":    self.total_lines,
            "vulnerabilities": [
                {
                    "check":           f.check,
                    "severity":        f.severity.value,
                    "title":           f.title,
                    "description":     f.description,
                    "evidence":        f.evidence,
                    "remediation":     f.remediation,
                    "recommendation":  f.remediation,   # alias used by frontend
                    "fixed_directive": f.fixed_directive,
                    "line_number":     f.line_number,
                }
                for f in self.vulnerabilities
            ],
            "info": [
                {
                    "check":       f.check,
                    "title":       f.title,
                    "description": f.description,
                    "evidence":    f.evidence,
                    "line_number": f.line_number,
                }
                for f in self.info
            ],
            "error": self.error,
        }


# ══════════════════════════════════════════════════════
#  Parser Helper
# ══════════════════════════════════════════════════════

def _parse_config(content: str) -> list[tuple[int, str, str]]:
    """
    يُحوّل محتوى الملف إلى قائمة من:
    (line_number, directive_name, directive_value)

    يتجاهل:
    - الأسطر الفارغة
    - التعليقات (#)
    - وسوم الفتح/الإغلاق <Directory> ... </Directory>
      (نحتفظ بها كـ directive خاصة)
    """
    parsed = []

    for line_num, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()

        # تجاهل الفراغات والتعليقات
        if not line or line.startswith("#"):
            continue

        # وسوم block: <Directory "/var/www"> → ("block_open", "Directory /var/www")
        block_match = re.match(r"^<(\w+)\s*(.*?)>$", line, re.IGNORECASE)
        if block_match:
            parsed.append((
                line_num,
                f"block_{block_match.group(1).lower()}",
                block_match.group(2).strip(),
            ))
            continue

        # وسوم إغلاق: </Directory>
        close_match = re.match(r"^</(\w+)>$", line, re.IGNORECASE)
        if close_match:
            parsed.append((line_num, f"block_end_{close_match.group(1).lower()}", ""))
            continue

        # Directive عادية: ServerTokens Prod
        parts = line.split(None, 1)
        directive = parts[0].lower()
        value     = parts[1].strip() if len(parts) > 1 else ""
        parsed.append((line_num, directive, value))

    return parsed


def _get_directive_value(
    parsed: list[tuple[int, str, str]],
    directive: str,
) -> Optional[tuple[int, str]]:
    """يُعيد (line_number, value) لأول تطابق للـ directive، أو None."""
    directive_lower = directive.lower()
    for line_num, name, value in parsed:
        if name == directive_lower:
            return (line_num, value)
    return None


def _get_all_directive_values(
    parsed: list[tuple[int, str, str]],
    directive: str,
) -> list[tuple[int, str]]:
    """يُعيد كل قيم directive (قد تتكرر)."""
    directive_lower = directive.lower()
    return [
        (line_num, value)
        for line_num, name, value in parsed
        if name == directive_lower
    ]


# ══════════════════════════════════════════════════════
#  Individual Checks
# ══════════════════════════════════════════════════════

def _check_server_tokens(parsed: list) -> list[ConfigFinding]:
    """
    [1] ServerTokens — CIS 2.2.

    يُحدّد مقدار المعلومات التي يُرسلها Apache في رأس Server.

    الخطر: القيمة الافتراضية Full أو OS تُرسل:
           "Apache/2.4.51 (Ubuntu) OpenSSL/1.1.1l"
           هذا يُمكِّن المهاجم من:
           - معرفة الإصدار الدقيق والبحث عن CVEs المرتبطة
           - معرفة نظام التشغيل لتحديد أدوات الاستغلال المناسبة
           - معرفة مكتبات مثبَّتة (OpenSSL, PHP) لاستهدافها
    القيمة الآمنة: Prod — تُرسل "Apache" فقط بدون أي تفاصيل.
    مرجع CIS: CIS Apache 2.4 Benchmark Section 2.2
    """
    findings = []
    result = _get_directive_value(parsed, "servertokens")

    if result is None:
        findings.append(ConfigFinding(
            check="missing_server_tokens",
            severity=Severity.MEDIUM,
            title="ServerTokens غير مُعيَّن",
            description="الإعداد الافتراضي يكشف إصدار Apache الكامل في HTTP headers.",
            evidence="Directive غير موجود في الملف",
            remediation="أضف: ServerTokens Prod",
            fixed_directive="ServerTokens Prod",
        ))
    else:
        line_num, value = result
        if value.lower() not in ("prod", "productonly"):
            findings.append(ConfigFinding(
                check="insecure_server_tokens",
                severity=Severity.MEDIUM,
                title=f"ServerTokens يكشف معلومات زائدة: {value}",
                description="القيمة الآمنة الوحيدة هي 'Prod' — تُظهر 'Apache' فقط بدون إصدار.",
                evidence=f"Line {line_num}: ServerTokens {value}",
                remediation="غيّر إلى: ServerTokens Prod",
                fixed_directive="ServerTokens Prod",
                line_number=line_num,
            ))

    return findings


def _check_server_signature(parsed: list) -> list[ConfigFinding]:
    """ServerSignature يجب أن يكون Off."""
    findings = []
    result = _get_directive_value(parsed, "serversignature")

    if result is None:
        findings.append(ConfigFinding(
            check="missing_server_signature",
            severity=Severity.LOW,
            title="ServerSignature غير مُعيَّن",
            description="الإعداد الافتراضي يُضيف توقيع Apache في صفحات الخطأ.",
            evidence="Directive غير موجود",
            remediation="أضف: ServerSignature Off",
            fixed_directive="ServerSignature Off",
        ))
    else:
        line_num, value = result
        if value.lower() != "off":
            findings.append(ConfigFinding(
                check="insecure_server_signature",
                severity=Severity.LOW,
                title="ServerSignature مُفعَّل",
                description="يُظهر إصدار Apache في صفحات الخطأ الافتراضية.",
                evidence=f"Line {line_num}: ServerSignature {value}",
                remediation="غيّر إلى: ServerSignature Off",
                fixed_directive="ServerSignature Off",
                line_number=line_num,
            ))

    return findings


def _check_directory_listing(parsed: list) -> list[ConfigFinding]:
    """
    يبحث عن Options Indexes — يُمكّن Directory Listing.
    الخطر: يعرض قائمة الملفات للزوار.
    ملاحظة مهمة: -Indexes = معطّل (آمن) | Indexes = مُفعَّل (خطير)
    """
    findings = []

    for line_num, directive, value in parsed:
        if directive != "options":
            continue

        # البحث عن "Indexes" بدون علامة - في البداية (يعني مُفعَّل)
        # -Indexes = معطّل (آمن) فلا نبلّغ عنه
        has_indexes_enabled = False
        for opt in value.split():
            opt_lower = opt.lower()
            # إذا كانت تبدأ بـ - أو + تخطّ هذا الخيار
            if opt_lower.startswith('-') or opt_lower.startswith('+'):
                continue
            if opt_lower == "indexes":
                has_indexes_enabled = True
                break

        if has_indexes_enabled:
            # بناء السطر المُصحَّح: إزالة Indexes وإضافة -Indexes
            clean_opts = [o for o in value.split() if o.lower() != "indexes"]
            fixed_opts  = " ".join(["-Indexes"] + clean_opts).strip()
            findings.append(ConfigFinding(
                check="directory_listing_enabled",
                severity=Severity.HIGH,
                title="Directory Listing مُفعَّل (Options Indexes)",
                description=(
                    "يسمح للمستخدمين برؤية قائمة الملفات في المجلدات "
                    "التي لا تحتوي على index.html — تسريب خطير للبنية الداخلية."
                ),
                evidence=f"Line {line_num}: Options {value}",
                remediation=(
                    "غيّر إلى:\n"
                    "  Options -Indexes\n"
                    "أو أزل Indexes من القائمة"
                ),
                fixed_directive=f"Options {fixed_opts}",
                line_number=line_num,
            ))

    return findings


def _check_follow_symlinks(parsed: list) -> list[ConfigFinding]:
    """FollowSymLinks بدون SymLinksIfOwnerMatch خطر.
    ملاحظة: -FollowSymLinks = معطّل (آمن) | FollowSymLinks = مُفعَّل (خطير)
    """
    findings = []

    for line_num, directive, value in parsed:
        if directive != "options":
            continue

        # التحقق من الخيارات مع الانتباه للعلامة -
        has_follow     = False
        has_owner_only = False
        
        for opt in value.split():
            opt_lower = opt.lower()
            # تخطّ الخيارات المعطَّلة (تبدأ بـ -)
            if opt_lower.startswith('-') or opt_lower.startswith('+'):
                continue
            if opt_lower == "followsymlinks":
                has_follow = True
            if opt_lower == "symlinksifownermatch":
                has_owner_only = True

        if has_follow and not has_owner_only:
            # استبدال FollowSymLinks بـ SymLinksIfOwnerMatch
            clean_opts = [o for o in value.split()
                          if o.lower() != "followsymlinks"]
            fixed_opts  = " ".join(["SymLinksIfOwnerMatch"] + clean_opts).strip()
            findings.append(ConfigFinding(
                check="unsafe_followsymlinks",
                severity=Severity.MEDIUM,
                title="FollowSymLinks بدون SymLinksIfOwnerMatch",
                description=(
                    "يسمح لأي Symlink بالعمل حتى لو المالك مختلف، "
                    "قد يُسمح بالوصول لملفات خارج DocumentRoot."
                ),
                evidence=f"Line {line_num}: Options {value}",
                remediation="استخدم: Options SymLinksIfOwnerMatch",
                fixed_directive=f"Options {fixed_opts}",
                line_number=line_num,
            ))

    return findings


def _check_ssl_settings(parsed: list) -> list[ConfigFinding]:
    """يفحص إعدادات SSL في ملف الإعدادات."""
    findings = []

    # ── SSLProtocol ──
    ssl_proto = _get_directive_value(parsed, "sslprotocol")
    if ssl_proto:
        line_num, value = ssl_proto
        value_lower = value.lower()

        weak_protocols = ["sslv2", "sslv3", "tlsv1 ", "+tlsv1 ", "tlsv1.1", "+tlsv1.1"]
        for weak in weak_protocols:
            if weak in value_lower:
                findings.append(ConfigFinding(
                    check="weak_ssl_protocol",
                    severity=Severity.HIGH,
                    title=f"بروتوكول SSL/TLS ضعيف مُفعَّل",
                    description="SSLv2/3 وTLS 1.0/1.1 عرضة لهجمات POODLE و BEAST.",
                    evidence=f"Line {line_num}: SSLProtocol {value}",
                    remediation=(
                        "استخدم:\n"
                        "  SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1"
                    ),
                    fixed_directive="SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
                    line_number=line_num,
                ))
                break
    else:
        findings.append(ConfigFinding(
            check="missing_ssl_protocol",
            severity=Severity.MEDIUM,
            title="SSLProtocol غير مُعيَّن صراحةً",
            description="الإعداد الافتراضي قد يُفعِّل بروتوكولات قديمة.",
            evidence="Directive غير موجود",
            remediation="أضف: SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
            fixed_directive="SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1",
        ))

    # ── SSLCipherSuite ──
    cipher = _get_directive_value(parsed, "sslciphersuite")
    if cipher:
        line_num, value = cipher
        # Token-based parsing avoids false positives with disabled ciphers (e.g. !aNULL, !3DES).
        value_upper = value.upper()
        tokens = [t.strip() for t in value_upper.split(":") if t.strip()]

        # Keep only enabled tokens (those not prefixed with !)
        enabled_tokens = [t for t in tokens if not t.startswith("!")]

        weak_groups = {
            "null": ("NULL", "ANULL"),
            "export": ("EXPORT", "EXP", "EXP56", "EXP40"),
            "des": ("DES", "3DES", "DES3"),
            "rc4": ("RC4", "ARC4"),
            "md5": ("MD5",),
        }

        def _token_matches(token: str, keywords: tuple[str, ...]) -> bool:
            return any(k in token for k in keywords)

        for weak_key, keywords in weak_groups.items():
            if any(_token_matches(token, keywords) for token in enabled_tokens):
                findings.append(ConfigFinding(
                    check=f"weak_cipher_{weak_key}",
                    severity=Severity.HIGH,
                    title=f"Cipher ضعيف مُفعَّل: {weak_key.upper()}",
                    description=f"الـ cipher {weak_key.upper()} ضعيف وغير آمن.",
                    evidence=f"Line {line_num}: SSLCipherSuite {value[:80]}",
                    remediation=(
                        "استخدم:\n"
                        "  SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!RC4"
                    ),
                    fixed_directive="SSLCipherSuite HIGH:!aNULL:!MD5:!3DES:!RC4",
                    line_number=line_num,
                ))

    # ── SSLHonorCipherOrder ──
    honor = _get_directive_value(parsed, "sslhonorcipherorder")
    if not honor or honor[1].lower() != "on":
        line_num = honor[0] if honor else 0
        findings.append(ConfigFinding(
            check="ssl_honor_cipher_order_off",
            severity=Severity.MEDIUM,
            title="SSLHonorCipherOrder غير مُفعَّل",
            description="السيرفر يسمح للعميل باختيار الـ cipher — العملاء الضعيفة تختار ciphers ضعيفة.",
            evidence=f"Line {line_num}: {honor[1] if honor else 'غير موجود'}",
            remediation="أضف: SSLHonorCipherOrder On",
            fixed_directive="SSLHonorCipherOrder On",
            line_number=line_num,
        ))

    return findings


def _check_dangerous_modules(parsed: list) -> list[ConfigFinding]:
    """يبحث عن LoadModule لوحدات خطرة أو غير ضرورية."""
    findings = []

    dangerous_modules = {
        "mod_status":    (Severity.HIGH,   "يكشف معلومات السيرفر والـ requests الحالية عبر /server-status"),
        "mod_info":      (Severity.HIGH,   "يكشف إعدادات Apache عبر /server-info"),
        "mod_userdir":   (Severity.MEDIUM, "يُمكّن ~username URLs — يكشف أسماء المستخدمين"),
        "mod_autoindex": (Severity.MEDIUM, "يُفعِّل Directory Listing التلقائي"),
        "mod_cgi":       (Severity.MEDIUM, "تنفيذ CGI scripts — خطر إذا لم تكن ضرورية"),
        "mod_include":   (Severity.LOW,    "Server-Side Includes — خطر XSS إذا لم تُقيَّد"),
    }

    for line_num, directive, value in parsed:
        if directive != "loadmodule":
            continue

        # LoadModule auth_basic_module modules/mod_auth_basic.so
        # نستخرج اسم الـ module من اسم الملف
        module_file = value.split()[-1] if value else ""
        module_name = Path(module_file).stem  # mod_status

        if module_name in dangerous_modules:
            severity, description = dangerous_modules[module_name]
            findings.append(ConfigFinding(
                check=f"dangerous_module_{module_name}",
                severity=severity,
                title=f"Module يحتمل خطراً محمّل: {module_name}",
                description=description,
                evidence=f"Line {line_num}: LoadModule {value}",
                remediation=(
                    f"إذا لم تحتج {module_name}:\n"
                    f"  # LoadModule (علّق السطر)\n"
                    f"أو عبر:\n"
                    f"  a2dismod {module_name.replace('mod_', '')}"
                ),
                fixed_directive=f"# LoadModule {value}  # Disabled by CyBrain",
                line_number=line_num,
            ))

    return findings


def _check_trace_method(parsed: list) -> list[ConfigFinding]:
    """TraceEnable يجب أن يكون Off."""
    findings = []
    result = _get_directive_value(parsed, "traceenable")

    if result is None:
        findings.append(ConfigFinding(
            check="missing_trace_enable",
            severity=Severity.MEDIUM,
            title="TraceEnable غير مُعيَّن",
            description="الإعداد الافتراضي يُفعِّل TRACE method — عرضة لـ XST attacks.",
            evidence="Directive غير موجود",
            remediation="أضف: TraceEnable Off",
            fixed_directive="TraceEnable Off",
        ))
    else:
        line_num, value = result
        if value.lower() != "off":
            findings.append(ConfigFinding(
                check="trace_method_enabled",
                severity=Severity.MEDIUM,
                title=f"TraceEnable مُفعَّل: {value}",
                description="TRACE HTTP method يُمكّن هجوم Cross-Site Tracing (XST).",
                evidence=f"Line {line_num}: TraceEnable {value}",
                remediation="غيّر إلى: TraceEnable Off",
                fixed_directive="TraceEnable Off",
                line_number=line_num,
            ))

    return findings


def _check_timeout_settings(parsed: list) -> list[ConfigFinding]:
    """Timeout مرتفع جداً يُسهِّل هجمات DoS."""
    findings = []
    result = _get_directive_value(parsed, "timeout")

    if result:
        line_num, value = result
        try:
            timeout_val = int(value)
            if timeout_val > 60:
                findings.append(ConfigFinding(
                    check="high_timeout",
                    severity=Severity.LOW,
                    title=f"Timeout مرتفع: {timeout_val} ثانية",
                    description=(
                        "Timeout العالي يُبقي الاتصالات مفتوحة طويلاً، "
                        "مما يُسهّل هجمات Slowloris DoS."
                    ),
                    evidence=f"Line {line_num}: Timeout {value}",
                    remediation="الموصى به: Timeout 30",
                    fixed_directive="Timeout 30",
                    line_number=line_num,
                ))
        except ValueError:
            pass

    return findings


def _check_access_control(parsed: list) -> list[ConfigFinding]:
    """يبحث عن 'Require all granted' في مجلدات حساسة."""
    findings = []
    in_root_block = False

    for line_num, directive, value in parsed:
        # نتتبع إذا كنا داخل <Directory /> أو <Directory "/">
        if directive == "block_directory":
            cleaned = value.strip('"').strip("'")
            if cleaned in ("/", "/*"):
                in_root_block = True

        elif directive.startswith("block_end_"):
            in_root_block = False

        elif in_root_block and directive == "require":
            if "all granted" in value.lower():
                findings.append(ConfigFinding(
                    check="root_directory_all_granted",
                    severity=Severity.CRITICAL,
                    title="Require all granted على الـ root directory",
                    description=(
                        "الوصول مفتوح لكل مجلدات السيرفر بدون قيود. "
                        "هذا الإعداد خطير جداً في بيئة الإنتاج."
                    ),
                    evidence=f"Line {line_num}: Require {value}",
                    remediation=(
                        "<Directory />\n"
                        "    Require all denied\n"
                        "</Directory>"
                    ),
                    fixed_directive="    Require all denied",
                    line_number=line_num,
                ))

    return findings


def _check_expose_php(parsed: list) -> list[ConfigFinding]:
    """
    [12] expose_php — تسريب إصدار PHP في X-Powered-By header.

    الخطر: معرفة إصدار PHP يُمكِّن المهاجم من استهداف CVEs محددة.
    الإصلاح: php_admin_flag expose_php off
    """
    findings = []

    for directive in ("php_admin_value", "php_value", "php_flag", "php_admin_flag"):
        for line_num, name, value in parsed:
            if name == directive and "expose_php" in value.lower():
                if "on" in value.lower().split()[-1]:
                    findings.append(ConfigFinding(
                        check="expose_php_on",
                        severity=Severity.LOW,
                        title="expose_php مُفعَّل — تسريب إصدار PHP",
                        description=(
                            "إصدار PHP سيظهر في رأس X-Powered-By في كل استجابة HTTP. "
                            "هذه المعلومة تُمكِّن المهاجم من تحديد ثغرات CVE المناسبة للإصدار."
                        ),
                        evidence=f"Line {line_num}: {directive} {value}",
                        remediation="غيّر إلى: php_admin_flag expose_php off",
                        line_number=line_num,
                    ))

    return findings


# ══════════════════════════════════════════════════════
#  CIS Level 2 — Additional Checks
# ══════════════════════════════════════════════════════

def _check_limit_request_line(parsed: list) -> list[ConfigFinding]:
    """
    [13] LimitRequestLine — CIS 5.4 / L2.

    يُحدّد الحد الأقصى لطول أول سطر في HTTP request
    (الذي يحتوي على Method + URI + Protocol).

    الخطر: طلبات طويلة جداً قد تستغل ثغرات في CGI modules أو تُسبب buffer overflow.
    القيمة الآمنة: 8190 أو أقل (الافتراضي هو 8190 في Apache لكن يُستحسن التصريح).
    مرجع CIS: "LimitRequestLine should be set to 8190 or less."
    """
    findings = []
    result = _get_directive_value(parsed, "limitrequestline")

    if result is None:
        findings.append(ConfigFinding(
            check="missing_limit_request_line",
            severity=Severity.LOW,
            title="LimitRequestLine غير مُعيَّن (CIS 5.4)",
            description=(
                "الإعداد الافتراضي (8190 bytes) يُقبل به، لكن يُنصح بالتصريح الصريح "
                "للتوافق مع متطلبات CIS L2. يحدّ هذا الإعداد من طول عنوان URI لحماية "
                "من تمرير URIs هجومية طويلة إلى تطبيقات CGI."
            ),
            evidence="LimitRequestLine غير موجود في الملف",
            remediation="أضف: LimitRequestLine 8190",
            fixed_directive="LimitRequestLine 8190",
        ))
    else:
        line_num, value = result
        try:
            val = int(value)
            if val > 8190:
                findings.append(ConfigFinding(
                    check="high_limit_request_line",
                    severity=Severity.MEDIUM,
                    title=f"LimitRequestLine مرتفع جداً: {val} (CIS 5.4)",
                    description=(
                        f"الحد الأقصى الحالي {val} bytes يتجاوز توصية CIS (8190). "
                        "قبول URIs بهذا الطول يزيد خطر الاستغلال عبر هجمات Buffer Overflow "
                        "أو تمرير أكواد خبيثة مخفية في URI."
                    ),
                    evidence=f"Line {line_num}: LimitRequestLine {value}",
                    remediation="غيّر إلى: LimitRequestLine 8190",
                    fixed_directive="LimitRequestLine 8190",
                    line_number=line_num,
                ))
            elif val == 0:
                findings.append(ConfigFinding(
                    check="zero_limit_request_line",
                    severity=Severity.HIGH,
                    title="LimitRequestLine = 0 يعني بلا حد (CIS 5.4)",
                    description=(
                        "القيمة 0 تعني إلغاء الحد تماماً مما يُعرّض السيرفر لطلبات "
                        "ضخمة جداً تستطيع تعطيل الخدمة أو استغلال تطبيقات CGI."
                    ),
                    evidence=f"Line {line_num}: LimitRequestLine {value}",
                    remediation="غيّر إلى: LimitRequestLine 8190",
                    fixed_directive="LimitRequestLine 8190",
                    line_number=line_num,
                ))
        except ValueError:
            pass

    return findings


def _check_limit_request_fields(parsed: list) -> list[ConfigFinding]:
    """
    [14] LimitRequestFields — CIS 5.5 / L2.

    يُحدّد الحد الأقصى لعدد HTTP Headers في الطلب الواحد.

    الخطر: عدد ضخم من Headers يُمكن أن يُسبب استنزاف الذاكرة
           أو يُربك تطبيقات تعالج كل header على حدة.
    القيمة الآمنة: 100 أو أقل (وليس صفراً).
    مرجع CIS: "LimitRequestFields should be set to 100 or less but not 0."
    """
    findings = []
    result = _get_directive_value(parsed, "limitrequestfields")

    if result is None:
        findings.append(ConfigFinding(
            check="missing_limit_request_fields",
            severity=Severity.LOW,
            title="LimitRequestFields غير مُعيَّن (CIS 5.5)",
            description=(
                "الافتراضي هو 100 في Apache لكن يُستحسن التصريح لتوثيق الإعداد الأمني "
                "واتباع متطلبات CIS L2. يمنع تحديد عدد Headers من هجمات استنزاف الذاكرة."
            ),
            evidence="LimitRequestFields غير موجود في الملف",
            remediation="أضف: LimitRequestFields 100",
            fixed_directive="LimitRequestFields 100",
        ))
    else:
        line_num, value = result
        try:
            val = int(value)
            if val == 0:
                findings.append(ConfigFinding(
                    check="unlimited_request_fields",
                    severity=Severity.HIGH,
                    title="LimitRequestFields = 0 يعني بلا حد (CIS 5.5)",
                    description=(
                        "إلغاء حد Headers يُعرّض السيرفر لهجمات استنزاف الذاكرة "
                        "وهجمات DoS عبر إرسال آلاف الـ Headers في طلب واحد."
                    ),
                    evidence=f"Line {line_num}: LimitRequestFields {value}",
                    remediation="غيّر إلى: LimitRequestFields 100",
                    fixed_directive="LimitRequestFields 100",
                    line_number=line_num,
                ))
            elif val > 100:
                findings.append(ConfigFinding(
                    check="high_limit_request_fields",
                    severity=Severity.MEDIUM,
                    title=f"LimitRequestFields مرتفع: {val} (CIS 5.5)",
                    description=(
                        f"قبول {val} Header في الطلب الواحد يتجاوز توصية CIS (100). "
                        "تقليل هذه القيمة يُقلل خطر هجمات HTTP Header Flooding."
                    ),
                    evidence=f"Line {line_num}: LimitRequestFields {value}",
                    remediation="غيّر إلى: LimitRequestFields 100",
                    fixed_directive="LimitRequestFields 100",
                    line_number=line_num,
                ))
        except ValueError:
            pass

    return findings


def _check_limit_request_field_size(parsed: list) -> list[ConfigFinding]:
    """
    [15] LimitRequestFieldSize — CIS 5.6 / L2.

    يُحدّد الحد الأقصى لحجم كل HTTP Header (بالبايت).

    الخطر: Header ضخم قد يستغل ثغرات في modules تعالج headers
           أو يُسبب Memory Exhaustion.
    القيمة الآمنة: 8190 bytes أو أقل.
    مرجع CIS: "LimitRequestFieldsize should be set to 8190 or less."
    """
    findings = []
    result = _get_directive_value(parsed, "limitrequestfieldsize")

    if result is None:
        findings.append(ConfigFinding(
            check="missing_limit_request_field_size",
            severity=Severity.LOW,
            title="LimitRequestFieldSize غير مُعيَّن (CIS 5.6)",
            description=(
                "الافتراضي 8190 bytes مقبول، لكن التصريح الصريح مطلوب لتوافق CIS L2. "
                "تحديد حجم Header يمنع استغلال ثغرات في معالجة Headers الضخمة."
            ),
            evidence="LimitRequestFieldSize غير موجود في الملف",
            remediation="أضف: LimitRequestFieldSize 8190",
            fixed_directive="LimitRequestFieldSize 8190",
        ))
    else:
        line_num, value = result
        try:
            val = int(value)
            if val > 8190:
                findings.append(ConfigFinding(
                    check="high_limit_request_field_size",
                    severity=Severity.MEDIUM,
                    title=f"LimitRequestFieldSize مرتفع: {val} bytes (CIS 5.6)",
                    description=(
                        f"قبول Headers بحجم {val} bytes يتجاوز توصية CIS (8190). "
                        "Header ضخم قد يستغل ثغرات في المعالجة الداخلية لبعض modules."
                    ),
                    evidence=f"Line {line_num}: LimitRequestFieldSize {value}",
                    remediation="غيّر إلى: LimitRequestFieldSize 8190",
                    fixed_directive="LimitRequestFieldSize 8190",
                    line_number=line_num,
                ))
        except ValueError:
            pass

    return findings


def _check_limit_request_body(parsed: list) -> list[ConfigFinding]:
    """
    [16] LimitRequestBody — CIS 5.7 / L2.

    يُحدّد الحد الأقصى لحجم جسم طلب HTTP (بالبايت).

    الخطر: قبول طلبات ضخمة جداً يُسهِّل هجمات DoS عبر ملء الذاكرة أو القرص.
           القيمة 0 تعني بلا حد = خطر مباشر.
    القيمة الآمنة: 102400 bytes (100KB) أو أقل حسب CIS.
    ملاحظة: قد تحتاج التطبيقات التي تستقبل ملفات قيمة أعلى — اضبطها في context خاص.
    مرجع CIS: "LimitRequestBody should be set to 102400 (100K) or less."
    """
    findings = []
    result = _get_directive_value(parsed, "limitrequestbody")

    if result is None:
        findings.append(ConfigFinding(
            check="missing_limit_request_body",
            severity=Severity.MEDIUM,
            title="LimitRequestBody غير مُعيَّن (CIS 5.7)",
            description=(
                "القيمة الافتراضية 0 (بلا حد) تُعرّض السيرفر لهجمات رفع ملفات ضخمة "
                "التي تستنزف الذاكرة والقرص وتُعطّل الخدمة (DoS). "
                "يجب تحديد حد أقصى مناسب لطبيعة التطبيق."
            ),
            evidence="LimitRequestBody غير موجود — الافتراضي: 0 (بلا حد)",
            remediation="أضف: LimitRequestBody 102400  # (100KB — اضبطه حسب احتياج تطبيقك)",
            fixed_directive="LimitRequestBody 102400",
        ))
    else:
        line_num, value = result
        try:
            val = int(value)
            if val == 0:
                findings.append(ConfigFinding(
                    check="unlimited_request_body",
                    severity=Severity.HIGH,
                    title="LimitRequestBody = 0 يعني بلا حد (CIS 5.7)",
                    description=(
                        "إلغاء الحد يُعرّض السيرفر لرفع ملفات ضخمة تُسبب DoS. "
                        "يكفي POST request واحد بجسم ضخم لاستنزاف الذاكرة المتاحة."
                    ),
                    evidence=f"Line {line_num}: LimitRequestBody {value}",
                    remediation="غيّر إلى: LimitRequestBody 10485760  # 10MB كحد أقصى معقول",
                    fixed_directive="LimitRequestBody 10485760",
                    line_number=line_num,
                ))
            elif val > 10 * 1024 * 1024:  # > 10MB
                findings.append(ConfigFinding(
                    check="high_limit_request_body",
                    severity=Severity.LOW,
                    title=f"LimitRequestBody مرتفع: {val // (1024*1024)}MB (CIS 5.7)",
                    description=(
                        f"قبول طلبات بحجم {val // (1024*1024)}MB قد يُعرّض السيرفر لهجمات DoS. "
                        "راجع ما إذا كان التطبيق يحتاج هذا الحجم فعلاً."
                    ),
                    evidence=f"Line {line_num}: LimitRequestBody {value}",
                    remediation="الموصى به: LimitRequestBody 10485760  # (10MB)",
                    fixed_directive="LimitRequestBody 10485760",
                    line_number=line_num,
                ))
        except ValueError:
            pass

    return findings


def _check_security_headers(parsed: list, raw_content: str) -> list[ConfigFinding]:
    """
    [17] Security Headers — OWASP / CIS.

    فحص وجود رؤوس HTTP الأمنية الإلزامية:

    • X-Frame-Options: SAMEORIGIN / DENY
      يمنع Clickjacking — تضمين الموقع في <iframe> على موقع خبيث.

    • X-Content-Type-Options: nosniff
      يمنع MIME Sniffing — تنفيذ ملف نصي كـ JavaScript في بعض المتصفحات.

    • Strict-Transport-Security (HSTS):
      يُجبر المتصفح على استخدام HTTPS دائماً ويمنع SSL Stripping.

    • Content-Security-Policy (CSP):
      يُحدّد مصادر JS/CSS/Images المسموح بها — يُقلّل خطر XSS بشكل كبير.

    • X-XSS-Protection: 1; mode=block
      يُفعِّل فلتر XSS في المتصفحات القديمة (دعم إضافي مع CSP).

    • Referrer-Policy: strict-origin-when-cross-origin
      يُحدّد ما يُرسل كـ Referer — يمنع تسريب URLs الداخلية.
    """
    findings = []

    # نبحث في المحتوى الخام بدل parsed لأن Header directives معقدة
    headers_to_check = [
        (
            "x-frame-options",
            "X-Frame-Options",
            Severity.HIGH,
            "missing_header_x_frame_options",
            (
                "غياب X-Frame-Options يُمكِّن هجوم Clickjacking — يستطيع المهاجم تضمين "
                "موقعك داخل iframe خفي وخداع المستخدمين للنقر على عناصر لا يرونها. "
                "هذا الهجوم خطير على صفحات المصادقة وصفحات الإجراءات الحساسة."
            ),
            'Header always set X-Frame-Options "SAMEORIGIN"',
        ),
        (
            "x-content-type-options",
            "X-Content-Type-Options",
            Severity.MEDIUM,
            "missing_header_x_content_type",
            (
                "غياب X-Content-Type-Options: nosniff يسمح للمتصفح بـ MIME Sniffing — "
                "أي تخمين نوع الملف بدل الاعتماد على Content-Type الذي يُرسله السيرفر. "
                "قد يؤدي لتنفيذ ملف نصي (txt) كـ JavaScript مما يُمكِّن هجمات XSS."
            ),
            'Header always set X-Content-Type-Options "nosniff"',
        ),
        (
            "strict-transport-security",
            "Strict-Transport-Security (HSTS)",
            Severity.HIGH,
            "missing_header_hsts",
            (
                "غياب HSTS يُعرّض المستخدمين لهجوم SSL Stripping — يستطيع Man-in-the-Middle "
                "إجبار المتصفح على استخدام HTTP بدل HTTPS وسرقة بيانات الجلسة. "
                "HSTS يُجبر المتصفح على HTTPS لمدة محددة حتى للزيارات الأولى."
            ),
            'Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"',
        ),
        (
            "content-security-policy",
            "Content-Security-Policy (CSP)",
            Severity.HIGH,
            "missing_header_csp",
            (
                "غياب CSP يُضاعف خطر هجمات XSS — يستطيع المهاجم حقن JavaScript خبيث "
                "يُنفَّذ في متصفح الضحية بدون أي قيود. CSP يُحدّد مصادر موثوقة "
                "للـ scripts/styles/images مما يمنع تحميل موارد من مصادر خارجية."
            ),
            "Header always set Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'\"",
        ),
        (
            "x-xss-protection",
            "X-XSS-Protection",
            Severity.LOW,
            "missing_header_x_xss",
            (
                "X-XSS-Protection: 1; mode=block يُفعِّل فلتر XSS في المتصفحات القديمة "
                "(IE, Chrome القديم). رغم أن CSP أهم، يُضيف هذا Header طبقة حماية إضافية "
                "للمتصفحات التي لا تدعم CSP."
            ),
            'Header always set X-XSS-Protection "1; mode=block"',
        ),
        (
            "referrer-policy",
            "Referrer-Policy",
            Severity.LOW,
            "missing_header_referrer_policy",
            (
                "غياب Referrer-Policy يُرسل المتصفح URL الصفحة الكاملة كـ Referer "
                "عند التنقل لمواقع أخرى — قد يُسرّب URLs حساسة (tokens، معرّفات جلسات). "
                "strict-origin-when-cross-origin يُرسل فقط الـ origin بدون المسار."
            ),
            'Header always set Referrer-Policy "strict-origin-when-cross-origin"',
        ),
    ]

    content_lower = raw_content.lower()

    for key, name, severity, check_id, desc, fix in headers_to_check:
        # نبحث عن "header always set X-Frame-Options" أو "header set X-Frame-Options"
        pattern = rf"header\s+(always\s+)?set\s+{re.escape(key)}"
        if not re.search(pattern, content_lower):
            findings.append(ConfigFinding(
                check=check_id,
                severity=severity,
                title=f"رأس HTTP الأمني مفقود: {name}",
                description=desc,
                evidence=f"لم يُعثر على 'Header always set {name}' في الملف",
                remediation=fix,
                fixed_directive=fix,
            ))

    return findings


def _check_http_methods(parsed: list, raw_content: str) -> list[ConfigFinding]:
    """
    [18] HTTP Methods Restriction — LimitExcept (OWASP).

    يتحقق من وجود LimitExcept لتقييد HTTP Methods المسموح بها.

    الخطر: السيرفر بدون تقييد يقبل DELETE / PUT / PATCH / CONNECT / OPTIONS
           مما قد يُمكِّن:
           - حذف ملفات عبر DELETE
           - رفع ملفات خبيثة عبر PUT
           - كشف معلومات عبر OPTIONS
    الإصلاح: LimitExcept GET POST HEAD { Require all denied }
    """
    findings = []

    if not re.search(r"limitexcept\s+", raw_content, re.IGNORECASE):
        findings.append(ConfigFinding(
            check="missing_limit_except",
            severity=Severity.MEDIUM,
            title="LimitExcept غير مُعيَّن — HTTP Methods غير مقيّدة",
            description=(
                "السيرفر يقبل جميع HTTP Methods بدون قيود. "
                "Methods مثل DELETE و PUT قد تُمكِّن تعديل أو حذف الملفات إذا كانت هناك "
                "تطبيقات تستجيب لها. OPTIONS يكشف قائمة المسارات المدعومة. "
                "يُنصح بتقييد المسموح لـ GET, POST, HEAD فقط."
            ),
            evidence="لم يُعثر على LimitExcept في الملف",
            remediation=(
                "أضف داخل كتلة <Directory>:\n"
                "  <LimitExcept GET POST HEAD>\n"
                "      Require all denied\n"
                "  </LimitExcept>"
            ),
            fixed_directive=(
                "<LimitExcept GET POST HEAD>\n"
                "    Require all denied\n"
                "</LimitExcept>"
            ),
        ))

    return findings


def _check_allow_override(parsed: list) -> list[ConfigFinding]:
    """
    [19] AllowOverride — CIS 3.5.

    يفحص إذا كان AllowOverride مُفعَّلاً (مُسمح لـ .htaccess بتجاوز الإعدادات).

    الخطر: AllowOverride All أو AllowOverride Options يسمح لملفات .htaccess
           بتجاوز إعدادات الأمان بما في ذلك:
           - تفعيل تنفيذ PHP في مجلدات مرفوعة
           - إعادة كتابة قواعد التوجيه
           - تعطيل قيود الوصول
    الإصلاح الآمن: AllowOverride None على root والمجلدات الحساسة.
    مرجع CIS: CIS 3.5
    """
    findings = []

    for line_num, directive, value in parsed:
        if directive != "allowoverride":
            continue
        if value.lower() in ("all", "options", "fileinfo", "authconfig", "indexes"):
            findings.append(ConfigFinding(
                check="allowoverride_enabled",
                severity=Severity.MEDIUM,
                title=f"AllowOverride {value} — .htaccess يُجاوز إعدادات الأمان (CIS 3.5)",
                description=(
                    f"القيمة '{value}' تسمح لملفات .htaccess بتغيير إعدادات Apache. "
                    "إذا تمكّن مهاجم من رفع .htaccess في مجلد قابل للكتابة، يستطيع "
                    "تفعيل تنفيذ PHP، تعديل قواعد التوجيه، أو تجاوز قيود المصادقة. "
                    "يُفضَّل AllowOverride None على جميع المجلدات إلا عند الحاجة الموثّقة."
                ),
                evidence=f"Line {line_num}: AllowOverride {value}",
                remediation="غيّر إلى: AllowOverride None",
                fixed_directive="AllowOverride None",
                line_number=line_num,
            ))

    return findings


def _check_keep_alive(parsed: list) -> list[ConfigFinding]:
    """
    [20] KeepAliveTimeout — CIS 5.x.

    يفحص مهلة Persistent HTTP Connections.

    الخطر: KeepAliveTimeout العالي يحتفظ بـ threads/processes مشغولة لفترة طويلة
           مما يُمكِّن هجمات Slowloris — المهاجم يُرسل طلبات بطيئة جداً لاستنزاف
           جميع slots المتاحة وتعطيل الخدمة.
    القيمة الآمنة: 15 ثانية أو أقل.
    """
    findings = []
    result = _get_directive_value(parsed, "keepalivetimeout")

    if result is None:
        findings.append(ConfigFinding(
            check="missing_keep_alive_timeout",
            severity=Severity.LOW,
            title="KeepAliveTimeout غير مُعيَّن (CIS 5.x)",
            description=(
                "القيمة الافتراضية 5 ثواني مقبولة، لكن التصريح الصريح يوثّق السياسة الأمنية "
                "ويمنع القيمة من التغيير عند تحديث Apache. "
                "KeepAlive يُحسن الأداء لكن يجب تقييد مهلته."
            ),
            evidence="KeepAliveTimeout غير موجود في الملف",
            remediation="أضف: KeepAliveTimeout 15",
            fixed_directive="KeepAliveTimeout 15",
        ))
    else:
        line_num, value = result
        try:
            val = int(value)
            if val > 15:
                findings.append(ConfigFinding(
                    check="high_keep_alive_timeout",
                    severity=Severity.LOW,
                    title=f"KeepAliveTimeout مرتفع: {val} ثانية",
                    description=(
                        f"KeepAliveTimeout = {val} يحتفظ بالاتصالات مفتوحة {val} ثانية. "
                        "هجوم Slowloris يستغل هذا بإرسال headers بطيئة— يشغل جميع workers "
                        "ويمنع الطلبات الشرعية من الوصول. الموصى به: 15 ثانية أو أقل."
                    ),
                    evidence=f"Line {line_num}: KeepAliveTimeout {value}",
                    remediation="غيّر إلى: KeepAliveTimeout 15",
                    fixed_directive="KeepAliveTimeout 15",
                    line_number=line_num,
                ))
        except ValueError:
            pass

    return findings


def _check_logging(parsed: list) -> list[ConfigFinding]:
    """
    [21] ErrorLog / LogLevel — CIS 6.x.

    يتحقق من إعداد التسجيل لاكتشاف الهجمات وتتبّعها.

    الخطر: بدون تسجيل مناسب:
           - لا يمكن اكتشاف الهجمات في الوقت المناسب
           - لا يمكن التحقيق الجنائي بعد اختراق
           - مخالفة معايير الامتثال (PCI-DSS, ISO 27001)
    المطلوب: ErrorLog مُعيَّن + LogLevel warn أو أعلى.
    مرجع CIS: CIS 6.1, 6.2, 6.3
    """
    findings = []

    # ErrorLog
    error_log = _get_directive_value(parsed, "errorlog")
    if error_log is None:
        findings.append(ConfigFinding(
            check="missing_error_log",
            severity=Severity.MEDIUM,
            title="ErrorLog غير مُعيَّن (CIS 6.1)",
            description=(
                "غياب ErrorLog يعني استخدام الافتراضي الذي قد يكون غير مناسب للبيئة. "
                "التسجيل الصريح يضمن تسجيل الأخطاء والهجمات في مكان موثّق ومُراقَب. "
                "بدون سجلات الأخطاء يستحيل اكتشاف محاولات الاختراق ومتابعتها."
            ),
            evidence="ErrorLog غير موجود في الملف",
            remediation='أضف: ErrorLog "/var/log/httpd/error_log"',
            fixed_directive='ErrorLog "/var/log/httpd/error_log"',
        ))

    # LogLevel
    log_level = _get_directive_value(parsed, "loglevel")
    if log_level is None:
        findings.append(ConfigFinding(
            check="missing_log_level",
            severity=Severity.LOW,
            title="LogLevel غير مُعيَّن (CIS 6.2)",
            description=(
                "الافتراضي warn مقبول لكن يُستحسن التصريح. "
                "debug وinfo يُسجّلان معلومات مفصّلة قد تُسرّب بيانات حساسة، "
                "بينما crit وemerg قد يُخفيان أخطاء مهمة."
            ),
            evidence="LogLevel غير موجود في الملف",
            remediation="أضف: LogLevel warn",
            fixed_directive="LogLevel warn",
        ))
    else:
        line_num, value = log_level
        verbose_levels = ["debug", "trace1", "trace2", "trace3", "trace4", "trace5", "trace6", "trace7", "trace8", "info"]
        if value.lower() in verbose_levels:
            findings.append(ConfigFinding(
                check="verbose_log_level",
                severity=Severity.MEDIUM,
                title=f"LogLevel مفصّل جداً: {value} (CIS 6.2)",
                description=(
                    f"LogLevel {value} يُسجِّل كميات ضخمة من المعلومات قد تشمل "
                    "بيانات حساسة كـ headers, cookies, query strings. "
                    "هذا يُشغل القرص ويُعقّد البحث في السجلات عند الحوادث. "
                    "للإنتاج: LogLevel warn"
                ),
                evidence=f"Line {line_num}: LogLevel {value}",
                remediation="غيّر إلى: LogLevel warn",
                fixed_directive="LogLevel warn",
                line_number=line_num,
            ))

    # CustomLog (AccessLog)
    custom_log = _get_directive_value(parsed, "customlog")
    if custom_log is None:
        findings.append(ConfigFinding(
            check="missing_custom_log",
            severity=Severity.MEDIUM,
            title="CustomLog (Access Log) غير مُعيَّن (CIS 6.3)",
            description=(
                "غياب Access Log يعني عدم تسجيل أي طلب وارد للسيرفر. "
                "Access Log ضروري لـ: تحليل حركة المرور، اكتشاف هجمات Brute Force، "
                "التحقيق الجنائي بعد الاختراق، الامتثال لمعايير PCI-DSS وISO 27001."
            ),
            evidence="CustomLog غير موجود في الملف",
            remediation='أضف: CustomLog "/var/log/httpd/access_log" combined',
            fixed_directive='CustomLog "/var/log/httpd/access_log" combined',
        ))

    return findings


def _check_mod_security(parsed: list, raw_content: str) -> list[ConfigFinding]:
    """
    [22] mod_security (WAF) — CIS L2.

    يتحقق من تحميل mod_security كـ Web Application Firewall.

    الخطر: بدون WAF، جميع الطلبات الواردة تصل للتطبيق بدون فحص مسبق.
           mod_security مع OWASP Core Rule Set (CRS) يمنع:
           - SQL Injection
           - Cross-Site Scripting (XSS)
           - Remote File Inclusion (RFI)
           - Local File Inclusion (LFI)
           - OWASP Top 10 بشكل عام
    مرجع CIS: CIS Apache L2 Requirement
    """
    findings = []

    has_modsec = (
        re.search(r"loadmodule\s+security2_module", raw_content, re.IGNORECASE)
        or re.search(r"mod_security2?\.so", raw_content, re.IGNORECASE)
        or re.search(r"modsecurityenabled\s+on", raw_content, re.IGNORECASE)
    )

    if not has_modsec:
        findings.append(ConfigFinding(
            check="missing_mod_security",
            severity=Severity.HIGH,
            title="mod_security (WAF) غير مُفعَّل (CIS L2)",
            description=(
                "mod_security مع OWASP Core Rule Set يُشكّل جدار حماية تطبيقات (WAF) "
                "يفحص كل طلب وارد ويمنع الهجمات المعروفة قبل وصولها للتطبيق. "
                "بدونه تكون جميع هجمات OWASP Top 10 مفتوحة — SQL Injection وXSS "
                "وRFI وLFI وغيرها. CIS L2 يُوجب تفعيله في بيئة الإنتاج."
            ),
            evidence="لم يُعثر على LoadModule security2_module في الملف",
            remediation=(
                "1. ثبّت mod_security:\n"
                "   yum install mod_security mod_security_crs  # RHEL/CentOS\n"
                "   apt install libapache2-mod-security2  # Debian/Ubuntu\n"
                "2. أضف في httpd.conf:\n"
                "   LoadModule security2_module modules/mod_security2.so\n"
                "   SecRuleEngine On\n"
                "   Include /etc/httpd/modsecurity.d/*.conf  # OWASP CRS"
            ),
            fixed_directive=(
                "LoadModule security2_module modules/mod_security2.so\n"
                "SecRuleEngine On"
            ),
        ))

    return findings


def _check_file_etag(parsed: list) -> list[ConfigFinding]:
    """
    [23] FileETag — CIS 5.2.

    يتحقق من إعداد FileETag لمنع تسريب معلومات نظام الملفات.

    الخطر: الإعداد الافتراضي يشمل INode في قيمة ETag.
           INode رقم يمكن استخدامه للكشف عن بنية نظام الملفات
           وقد يُسهِّل هجمات معينة.
    الإصلاح: FileETag MTime Size (بدون INode).
    مرجع CIS: CIS 5.2
    """
    findings = []
    result = _get_directive_value(parsed, "fileetag")

    if result is None:
        findings.append(ConfigFinding(
            check="missing_file_etag",
            severity=Severity.LOW,
            title="FileETag يتضمن INode بشكل افتراضي (CIS 5.2)",
            description=(
                "الافتراضي 'INode MTime Size' يُدرج رقم INode في قيمة ETag. "
                "هذا الرقم يُسرّب معلومات عن بنية نظام الملفات قد تُستخدم في "
                "هجمات مُركَّبة. استخدام MTime وSize فقط يكفي للـ caching بأمان."
            ),
            evidence="FileETag غير موجود — الافتراضي يشمل INode",
            remediation="أضف: FileETag MTime Size",
            fixed_directive="FileETag MTime Size",
        ))
    else:
        line_num, value = result
        if "inode" in value.lower() or value.lower() == "all":
            findings.append(ConfigFinding(
                check="file_etag_inode",
                severity=Severity.LOW,
                title=f"FileETag يشمل INode (CIS 5.2): {value}",
                description=(
                    "تضمين INode في ETag يُسرِّب معلومات نظام الملفات. "
                    "رغم أن الخطر منخفض بمفرده، يُشكّل جزءاً من معلومات استطلاعية "
                    "تُستخدم في هجمات أكثر تعقيداً."
                ),
                evidence=f"Line {line_num}: FileETag {value}",
                remediation="غيّر إلى: FileETag MTime Size",
                fixed_directive="FileETag MTime Size",
                line_number=line_num,
            ))

    return findings


def _check_exec_cgi(parsed: list) -> list[ConfigFinding]:
    """
    [24] Options ExecCGI — CIS 3.x.

    يتحقق من تفعيل تنفيذ CGI Scripts في مجلدات غير مخصصة.

    الخطر: ExecCGI يسمح لـ Apache بتنفيذ ملفات CGI في المجلد.
           إذا تمكّن مهاجم من رفع ملف .cgi أو تعديل .htaccess
           يستطيع تنفيذ أوامر عشوائية على السيرفر (RCE).
    الإصلاح: Options -ExecCGI في المجلدات غير CGI.
    ملاحظة: -ExecCGI = معطّل (آمن)، ExecCGI = مُفعَّل (خطير)
    """
    findings = []

    for line_num, directive, value in parsed:
        if directive != "options":
            continue
        # تحليل الخيارات مع الانتباه للعلامة -
        # -ExecCGI = معطّل (آمن)
        # ExecCGI = مُفعَّل (خطير)
        has_execcgi_enabled = False
        for opt in value.split():
            opt_lower = opt.lower()
            if opt_lower == "execcgi":  # بدون - أو + = مُفعَّل
                has_execcgi_enabled = True
                break

        if has_execcgi_enabled:
            clean_opts = [o for o in value.split() if o.lower() != "execcgi"]
            fixed_opts = " ".join(["-ExecCGI"] + clean_opts).strip()
            findings.append(ConfigFinding(
                check="options_exec_cgi",
                severity=Severity.HIGH,
                title="Options ExecCGI — تنفيذ CGI مُفعَّل (CIS 3.x)",
                description=(
                    "ExecCGI يسمح لـ Apache بتنفيذ ملفات CGI في هذا المجلد. "
                    "إذا تمكّن مهاجم من رفع ملف .cgi أو تعديل .htaccess "
                    "فسيستطيع تنفيذ أوامر Shell عشوائية مما يؤدي لاختراق كامل للسيرفر. "
                    "EnableCGI يجب أن يكون مقتصراً على مجلد cgi-bin فقط."
                ),
                evidence=f"Line {line_num}: Options {value}",
                remediation=(
                    "غيّر إلى:\n"
                    f"  Options -ExecCGI\n"
                    "أو أزل ExecCGI من القائمة"
                ),
                fixed_directive=f"Options {fixed_opts}" if fixed_opts.strip("-").strip() else "Options -ExecCGI",
                line_number=line_num,
            ))

    return findings


def _check_mpm_mode(raw_content: str) -> list[ConfigFinding]:
    """
    [25] MPM Mode — Apache Functional Performance.

    يفضَّل event MPM للإنتاج الحديث. prefork يستهلك ذاكرة أعلى لكل اتصال.
    """
    findings = []
    active_lines = []
    for ln in raw_content.splitlines():
        stripped = ln.strip()
        if not stripped or stripped.startswith("#"):
            continue
        active_lines.append(stripped)
    active_content = "\n".join(active_lines)

    has_event = re.search(r"loadmodule\s+mpm_event_module", active_content, re.IGNORECASE)
    has_worker = re.search(r"loadmodule\s+mpm_worker_module", active_content, re.IGNORECASE)
    has_prefork = re.search(r"loadmodule\s+mpm_prefork_module", active_content, re.IGNORECASE)

    prefork_line_num = 0
    prefork_line = ""
    for i, ln in enumerate(raw_content.splitlines(), start=1):
        if re.search(r"loadmodule\s+mpm_prefork_module", ln, re.IGNORECASE):
            prefork_line_num = i
            prefork_line = ln.strip()
            break

    if has_prefork:
        findings.append(ConfigFinding(
            check="mpm_prefork_in_use",
            severity=Severity.INFO,
            title="MPM prefork ملاحظة أداء",
            description=(
                "prefork يخصص عملية لكل اتصال ويستهلك ذاكرة أعلى تحت الحمل. "
                "لإنتاج حديث يُفضل event MPM لأنه يعالج KeepAlive بكفاءة أعلى."
            ),
            evidence=(
                f"Line {prefork_line_num}: {prefork_line}"
                if prefork_line_num else "LoadModule mpm_prefork_module ..."
            ),
            remediation=(
                "فعّل event MPM بدل prefork إن لم تكن هناك متطلبات توافق خاصة:\n"
                "LoadModule mpm_event_module modules/mod_mpm_event.so"
            ),
            fixed_directive="LoadModule mpm_event_module modules/mod_mpm_event.so",
            line_number=prefork_line_num,
        ))
    elif not has_event and not has_worker:
        findings.append(ConfigFinding(
            check="mpm_module_not_explicit",
            severity=Severity.LOW,
            title="MPM غير مصرح به بوضوح",
            description=(
                "عدم التصريح بنوع MPM يجعل السلوك يعتمد على افتراضات التوزيعة. "
                "للاستقرار الإنتاجي، صرّح بنوع MPM وقيم التزامن صراحةً."
            ),
            evidence="لم يُعثر على mpm_event/worker/prefork في التحميل",
            remediation="أضف: LoadModule mpm_event_module modules/mod_mpm_event.so",
            fixed_directive="LoadModule mpm_event_module modules/mod_mpm_event.so",
        ))
    elif has_worker:
        findings.append(ConfigFinding(
            check="mpm_worker_info",
            severity=Severity.INFO,
            title="MPM worker مفعّل",
            description="worker جيد، لكن event غالباً أفضل تحت اتصالات KeepAlive العالية.",
            evidence="LoadModule mpm_worker_module ...",
            remediation="اختياري: التحول إلى event MPM إذا كانت الأحمال HTTP كثيفة.",
        ))

    return findings


def _check_max_request_workers(parsed: list) -> list[ConfigFinding]:
    """
    [26] MaxRequestWorkers — Apache Performance.

    يجب ضبطها وفق RAM لتجنب swap أو 503.
    """
    findings = []
    result = _get_directive_value(parsed, "maxrequestworkers")
    if result is None:
        findings.append(ConfigFinding(
            check="missing_max_request_workers",
            severity=Severity.HIGH,
            title="MaxRequestWorkers غير مُعيَّن",
            description=(
                "غياب MaxRequestWorkers قد يسبب رفض طلبات (503) أو استهلاك ذاكرة مفرط. "
                "حسب مرجع Apache: اضبطه بناءً على RAM ولا تسمح بالوصول إلى swap."
            ),
            evidence="MaxRequestWorkers غير موجود",
            remediation=(
                "أضف قيمة محسوبة: MaxRequestWorkers = (RAM المتاحة * 0.8) / حجم عملية Apache. "
                "قيمة بداية عملية: 400"
            ),
            fixed_directive="MaxRequestWorkers 400",
        ))
        return findings

    line_num, value = result
    try:
        val = int(re.findall(r"\d+", value)[0])
    except Exception:
        return findings

    if val < 128:
        findings.append(ConfigFinding(
            check="low_max_request_workers",
            severity=Severity.MEDIUM,
            title=f"MaxRequestWorkers منخفض: {val}",
            description="القيمة المنخفضة قد تسبب اختناقاً ورفض طلبات عند الذروة.",
            evidence=f"Line {line_num}: MaxRequestWorkers {value}",
            remediation="زد القيمة تدريجياً بعد قياس الذاكرة (مثلاً 300-800).",
            fixed_directive="MaxRequestWorkers 400",
            line_number=line_num,
        ))
    elif val > 4000:
        findings.append(ConfigFinding(
            check="high_max_request_workers",
            severity=Severity.HIGH,
            title=f"MaxRequestWorkers مرتفع جداً: {val}",
            description=(
                "القيمة المرتفعة جداً قد تدفع الخادم للـ swap تحت الحمل، وهذا يسبب بطئاً حاداً."
            ),
            evidence=f"Line {line_num}: MaxRequestWorkers {value}",
            remediation="اخفض القيمة وفق الذاكرة المتاحة وحجم عمليات Apache.",
            fixed_directive="MaxRequestWorkers 1600",
            line_number=line_num,
        ))

    return findings


def _check_max_connections_per_child(parsed: list) -> list[ConfigFinding]:
    """
    [27] MaxConnectionsPerChild — Apache Performance/Resilience.
    """
    findings = []
    result = _get_directive_value(parsed, "maxconnectionsperchild")
    if result is None:
        findings.append(ConfigFinding(
            check="missing_max_connections_per_child",
            severity=Severity.MEDIUM,
            title="MaxConnectionsPerChild غير مُعيَّن",
            description=(
                "تركها غير مضبوطة/صفر لفترات طويلة يسمح بتراكم تسربات الذاكرة في العمليات طويلة العمر."
            ),
            evidence="MaxConnectionsPerChild غير موجود",
            remediation="أضف: MaxConnectionsPerChild 10000",
            fixed_directive="MaxConnectionsPerChild 10000",
        ))
        return findings

    line_num, value = result
    try:
        val = int(re.findall(r"\d+", value)[0])
    except Exception:
        return findings

    if val == 0:
        findings.append(ConfigFinding(
            check="max_connections_per_child_zero",
            severity=Severity.MEDIUM,
            title="MaxConnectionsPerChild = 0",
            description="القيمة 0 تعني عدم إعادة تدوير العمليات، ما يفاقم memory leaks بمرور الوقت.",
            evidence=f"Line {line_num}: MaxConnectionsPerChild {value}",
            remediation="غيّر إلى: MaxConnectionsPerChild 10000",
            fixed_directive="MaxConnectionsPerChild 10000",
            line_number=line_num,
        ))

    return findings


def _check_keep_alive_requests(parsed: list) -> list[ConfigFinding]:
    """
    [28] KeepAlive + MaxKeepAliveRequests.
    """
    findings = []
    keepalive = _get_directive_value(parsed, "keepalive")
    max_keepalive = _get_directive_value(parsed, "maxkeepaliverequests")

    if keepalive is None:
        findings.append(ConfigFinding(
            check="missing_keepalive",
            severity=Severity.LOW,
            title="KeepAlive غير مُصرَّح به",
            description="التصريح الصريح يثبت سياسة الاتصالات في الإنتاج.",
            evidence="KeepAlive غير موجود",
            remediation="أضف: KeepAlive On",
            fixed_directive="KeepAlive On",
        ))
    else:
        line_num, value = keepalive
        if value.strip().lower() == "off":
            findings.append(ConfigFinding(
                check="keepalive_off",
                severity=Severity.INFO,
                title="KeepAlive معطّل",
                description="قد يقلل الاستهلاك لكنه عادةً يرفع كلفة كل طلب على التطبيقات الحديثة.",
                evidence=f"Line {line_num}: KeepAlive {value}",
                remediation="قيّم تفعيل KeepAlive On مع KeepAliveTimeout منخفض.",
            ))

    if max_keepalive is None:
        findings.append(ConfigFinding(
            check="missing_max_keepalive_requests",
            severity=Severity.LOW,
            title="MaxKeepAliveRequests غير مُعيَّن",
            description="ضبط القيمة يمنع اتصالاً طويلاً غير منضبط ويثبت سلوك الخادم.",
            evidence="MaxKeepAliveRequests غير موجود",
            remediation="أضف: MaxKeepAliveRequests 100",
            fixed_directive="MaxKeepAliveRequests 100",
        ))

    return findings


def _check_compression_and_cache(raw_content: str) -> list[ConfigFinding]:
    """
    [29] Compression & Browser Caching.

    لا يندرج ضمن CIS الأمني مباشرة، لكنه أساسي للأداء الوظيفي في الإنتاج.
    """
    findings = []
    has_deflate = re.search(r"<IfModule\s+mod_deflate\.c>", raw_content, re.IGNORECASE)
    has_expires = re.search(r"<IfModule\s+mod_expires\.c>", raw_content, re.IGNORECASE)

    if not has_deflate:
        findings.append(ConfigFinding(
            check="missing_mod_deflate",
            severity=Severity.LOW,
            title="ضغط المحتوى (mod_deflate) غير مُفعَّل",
            description=(
                "غياب الضغط يزيد حجم الاستجابة 2-5x للملفات النصية (HTML/CSS/JS/JSON)."
            ),
            evidence="لم يُعثر على كتلة mod_deflate",
            remediation=(
                "أضف:\n"
                "<IfModule mod_deflate.c>\n"
                "    AddOutputFilterByType DEFLATE text/html text/plain text/css application/javascript application/json\n"
                "</IfModule>"
            ),
            fixed_directive="<IfModule mod_deflate.c>\n    AddOutputFilterByType DEFLATE text/html text/plain text/css application/javascript application/json\n</IfModule>",
        ))

    if not has_expires:
        findings.append(ConfigFinding(
            check="missing_mod_expires",
            severity=Severity.LOW,
            title="Browser caching (mod_expires) غير مُفعَّل",
            description="غياب سياسات الكاش يرفع زمن التحميل واستهلاك الشبكة.",
            evidence="لم يُعثر على كتلة mod_expires",
            remediation=(
                "أضف:\n"
                "<IfModule mod_expires.c>\n"
                "    ExpiresActive On\n"
                "    ExpiresByType text/css \"access plus 1 month\"\n"
                "    ExpiresByType application/javascript \"access plus 1 month\"\n"
                "</IfModule>"
            ),
            fixed_directive="<IfModule mod_expires.c>\n    ExpiresActive On\n    ExpiresByType text/css \"access plus 1 month\"\n    ExpiresByType application/javascript \"access plus 1 month\"\n</IfModule>",
        ))

    return findings


def _check_functional_log_format(parsed: list) -> list[ConfigFinding]:
    """
    [30] Functional LogFormat includes %D processing time.

    مقياس %D (microseconds) أساسي لبناء SLI/SLO للزمن.
    """
    findings = []
    log_formats = _get_all_directive_values(parsed, "logformat")
    if not log_formats:
        findings.append(ConfigFinding(
            check="missing_logformat_functional",
            severity=Severity.LOW,
            title="LogFormat غير مُعرَّف لقياس زمن المعالجة",
            description="لـ observability الإنتاجية، أضف LogFormat يتضمن %D.",
            evidence="لم يُعثر على LogFormat",
            remediation='أضف: LogFormat "%h %u %t \"%r\" %>s %b %D" functional',
            fixed_directive='LogFormat "%h %u %t \"%r\" %>s %b %D" functional',
        ))
        return findings

    has_latency = any("%d" in value.lower() for _, value in log_formats)
    if not has_latency:
        line_num, value = log_formats[-1]
        findings.append(ConfigFinding(
            check="logformat_missing_latency",
            severity=Severity.LOW,
            title="LogFormat لا يتضمن زمن المعالجة (%D)",
            description="غياب %D يضعف مراقبة الأداء ولا يسمح بتحديد SLI لزمن الاستجابة.",
            evidence=f"Line {line_num}: LogFormat {value}",
            remediation='استخدم صيغة: LogFormat "%h %u %t \"%r\" %>s %b %D" functional',
            fixed_directive='LogFormat "%h %u %t \"%r\" %>s %b %D" functional',
            line_number=line_num,
        ))

    return findings


def _check_sendfile_mmap(parsed: list) -> list[ConfigFinding]:
    """
    [31] Explicit sendfile/mmap policy.

    التصريح الصريح يمنع اختلاف السلوك بين البيئات ويزيد قابلية الضبط الإنتاجي.
    """
    findings = []
    sendfile = _get_directive_value(parsed, "enablesendfile")
    mmap = _get_directive_value(parsed, "enablemmap")

    if sendfile is None:
        findings.append(ConfigFinding(
            check="missing_enable_sendfile",
            severity=Severity.LOW,
            title="EnableSendfile غير مُصرَّح به",
            description=(
                "على بعض البيئات (مثل NFS) يُفضّل تعطيله لتجنب مشاكل نقل الملفات. "
                "التصريح الصريح يزيل الغموض."
            ),
            evidence="EnableSendfile غير موجود",
            remediation="أضف سياسة صريحة: EnableSendfile Off  # أو On حسب بيئتك",
            fixed_directive="EnableSendfile Off",
        ))

    if mmap is None:
        findings.append(ConfigFinding(
            check="missing_enable_mmap",
            severity=Severity.INFO,
            title="EnableMMAP غير مُصرَّح به",
            description="التصريح بـ EnableMMAP يعزز وضوح إعدادات الأداء بين البيئات.",
            evidence="EnableMMAP غير موجود",
            remediation="أضف: EnableMMAP Off  # أو On حسب اختباراتك",
            fixed_directive="EnableMMAP Off",
        ))

    return findings


def _check_mod_rewrite_security(raw_content: str) -> list[ConfigFinding]:
    """
    [32] mod_rewrite Open Redirect.

    يكتشف قواعد RewriteRule التي تعيد التوجيه إلى مضيف غير مُقيَّد.
    """
    findings = []
    lines = raw_content.splitlines()
    pattern = re.compile(
        r"RewriteRule\s+.+\s+https?://(?:\$\{?HTTP_HOST\}?|%\{HTTP_HOST\})",
        re.IGNORECASE,
    )
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if pattern.search(stripped):
            findings.append(ConfigFinding(
                check="rewrite_open_redirect",
                severity=Severity.HIGH,
                title="RewriteRule قد تسبب Open Redirect",
                description=(
                    "إعادة التوجيه باستخدام HTTP_HOST دون تحقق من نطاق موثوق قد تسمح "
                    "بإعادة المستخدم إلى نطاق خبيث."
                ),
                evidence=f"Line {i}: {stripped}",
                remediation=(
                    "قَيّد الوجهة على نطاقات موثوقة فقط (RewriteCond على HOST) "
                    "أو استخدم redirect ثابتاً داخل نفس النطاق."
                ),
                fixed_directive="# RewriteCond %{HTTP_HOST} ^(www\\.)?example\\.com$ [NC]",
                line_number=i,
            ))
    return findings


def _check_tls_session_cache(parsed: list) -> list[ConfigFinding]:
    """
    [33] SSLSessionCache / SSLSessionCacheTimeout / SSLSessionTickets.
    """
    findings = []
    cache = _get_directive_value(parsed, "sslsessioncache")
    timeout = _get_directive_value(parsed, "sslsessioncachetimeout")
    tickets = _get_directive_value(parsed, "sslsessiontickets")

    if cache is None:
        findings.append(ConfigFinding(
            check="missing_ssl_session_cache",
            severity=Severity.LOW,
            title="SSLSessionCache غير مُعيَّن",
            description="ضبط TLS session cache يحسن الأداء تحت اتصالات HTTPS المتكررة.",
            evidence="SSLSessionCache غير موجود",
            remediation="أضف: SSLSessionCache shmcb:/run/httpd/ssl_scache(512000)",
            fixed_directive="SSLSessionCache shmcb:/run/httpd/ssl_scache(512000)",
        ))

    if timeout is None:
        findings.append(ConfigFinding(
            check="missing_ssl_session_cache_timeout",
            severity=Severity.LOW,
            title="SSLSessionCacheTimeout غير مُعيَّن",
            description="غياب timeout الصريح يقلل قابلية الضبط والتوازن بين الأداء والأمان.",
            evidence="SSLSessionCacheTimeout غير موجود",
            remediation="أضف: SSLSessionCacheTimeout 300",
            fixed_directive="SSLSessionCacheTimeout 300",
        ))

    if tickets is None:
        findings.append(ConfigFinding(
            check="missing_ssl_session_tickets_policy",
            severity=Severity.INFO,
            title="SSLSessionTickets policy غير مصرح بها",
            description=(
                "في كثير من البيئات الإنتاجية يُفضّل تعطيل session tickets للحفاظ على PFS "
                "إلا عند إدارة مفاتيح التذاكر بشكل صارم."
            ),
            evidence="SSLSessionTickets غير موجود",
            remediation="أضف: SSLSessionTickets Off",
            fixed_directive="SSLSessionTickets Off",
        ))

    return findings


def _check_mpm_params(parsed: list) -> list[ConfigFinding]:
    """
    [34] MPM params coherence.

    يتحقق من توافق MaxRequestWorkers = ServerLimit × ThreadsPerChild.
    """
    findings = []
    mrw = _get_directive_value(parsed, "maxrequestworkers")
    sl = _get_directive_value(parsed, "serverlimit")
    tpc = _get_directive_value(parsed, "threadsperchild")

    if not (mrw and sl and tpc):
        return findings

    try:
        mrw_val = int(re.findall(r"\d+", mrw[1])[0])
        sl_val = int(re.findall(r"\d+", sl[1])[0])
        tpc_val = int(re.findall(r"\d+", tpc[1])[0])
    except Exception:
        return findings

    expected = sl_val * tpc_val
    if expected != mrw_val:
        findings.append(ConfigFinding(
            check="mpm_params_inconsistent",
            severity=Severity.MEDIUM,
            title="عدم اتساق إعدادات MPM",
            description=(
                f"القيمة الحالية MaxRequestWorkers={mrw_val} لا تطابق ServerLimit×ThreadsPerChild ({expected}). "
                "هذا قد يسبب سلوكاً غير متوقع تحت الحمل."
            ),
            evidence=(
                f"Line {mrw[0]}: MaxRequestWorkers {mrw[1]} | "
                f"Line {sl[0]}: ServerLimit {sl[1]} | "
                f"Line {tpc[0]}: ThreadsPerChild {tpc[1]}"
            ),
            remediation=f"اضبط MaxRequestWorkers على {expected} أو عدّل ServerLimit/ThreadsPerChild.",
            fixed_directive=f"MaxRequestWorkers {expected}",
            line_number=mrw[0],
        ))

    return findings


# ══════════════════════════════════════════════════════
#  Fixed Config Generator
# ══════════════════════════════════════════════════════

def generate_fixed_config(original_content: str, vulnerabilities: list[dict]) -> tuple[str, list[dict]]:
    """
    يُنشئ نسخة مُصحَّحة من ملف الإعدادات مع تطبيق جميع الإصلاحات.

    Returns:
        (fixed_content, change_log)
        change_log: قائمة من { line, check, title, before, after }
    """
    lines = original_content.splitlines()
    changes: list[dict] = []

    def _apply_options_fix(line_text: str, check: str) -> str:
        """Apply one options-related fix while preserving other options on the same line."""
        stripped = line_text.strip()
        if not stripped.lower().startswith("options "):
            return line_text

        rest = stripped[len("Options "):].strip()
        raw_tokens = [t for t in rest.split() if t]

        def _remove_option(tokens: list[str], option_name: str) -> list[str]:
            return [t for t in tokens if t.lstrip("+-").lower() != option_name]

        tokens = raw_tokens[:]

        if check == "directory_listing_enabled":
            tokens = _remove_option(tokens, "indexes")
            tokens = ["-Indexes"] + tokens
        elif check == "options_exec_cgi":
            tokens = _remove_option(tokens, "execcgi")
            tokens = ["-ExecCGI"] + tokens
        elif check == "unsafe_followsymlinks":
            # Remove enabled FollowSymLinks and enforce SymLinksIfOwnerMatch.
            tokens = [
                t for t in tokens
                if not (t.lower() == "followsymlinks" or t.lstrip("+-").lower() == "symlinksifownermatch")
            ]
            tokens = ["SymLinksIfOwnerMatch"] + tokens

        # De-duplicate while preserving order (case-insensitive key).
        deduped: list[str] = []
        seen: set[str] = set()
        for t in tokens:
            k = t.lower()
            if k not in seen:
                deduped.append(t)
                seen.add(k)

        return "Options " + " ".join(deduped).strip()

    # جمع الإصلاحات المرتبطة بأسطر
    line_fixes: dict[int, list[tuple[str, str, str, str]]] = {}  # line_num → [(old, new, check, title)]
    append_fixes: list[tuple[str, str, str]] = []          # (check, title, fixed_directive)

    for v in vulnerabilities:
        fixed = (v.get("fixed_directive") or "").strip()
        if not fixed:
            continue
        ln = v.get("line_number", 0)
        if ln and 1 <= ln <= len(lines):
            line_fixes.setdefault(ln, []).append(
                (lines[ln - 1].strip(), fixed, v.get("check", ""), v.get("title", ""))
            )
        else:
            append_fixes.append((v.get("check", ""), v.get("title", ""), fixed))

    # بناء المحتوى الجديد مع تعليقات
    new_lines: list[str] = []
    for i, line in enumerate(lines, start=1):
        if i in line_fixes:
            fixes = line_fixes[i]
            working_line = line.strip()
            applied_checks: list[str] = []

            # Apply options-specific checks first so multiple findings on same line are merged.
            for _, _, check, _ in fixes:
                if check in {"directory_listing_enabled", "options_exec_cgi", "unsafe_followsymlinks"}:
                    working_line = _apply_options_fix(working_line, check)
                    applied_checks.append(check)

            # Then apply other line-specific directives (if any).
            for _, new_directive, check, _ in fixes:
                if check in {"directory_listing_enabled", "options_exec_cgi", "unsafe_followsymlinks"}:
                    continue
                working_line = new_directive
                applied_checks.append(check)

            # الحفاظ على المسافات البادئة الأصلية
            indent = len(line) - len(line.lstrip())
            new_lines.append(" " * indent + working_line)
            for old_stripped, _, check, _ in fixes:
                new_lines.append(f"# CyBrain fix [{check}]: was → {old_stripped}")

            title = ", ".join([t for _, _, _, t in fixes if t])
            changes.append({
                "line":   i,
                "check":  ",".join(applied_checks),
                "title":  title,
                "before": line.strip(),
                "after":  working_line,
            })
        else:
            new_lines.append(line)

    # إلحاق الإعدادات المفقودة في نهاية الملف
    if append_fixes:
        new_lines += [
            "",
            "# ═══════════════════════════════════════════════════════",
            "# CyBrain Security Fix — Missing Security Directives",
            "# ═══════════════════════════════════════════════════════",
        ]
        for check, title, fixed in append_fixes:
            new_lines.append(f"# Fix [{check}]: {title}")
            new_lines.append(fixed)
            changes.append({
                "line":   "مُضاف",
                "check":  check,
                "title":  title,
                "before": "(غير موجود)",
                "after":  fixed,
            })

    return "\n".join(new_lines), changes


# ══════════════════════════════════════════════════════
#  Nginx Support
# ══════════════════════════════════════════════════════

def _detect_config_type(content: str) -> str:
    """يُحدّد هل الملف إعدادات Nginx أم Apache."""
    nginx_patterns = [r"\bhttp\s*\{", r"\bserver\s*\{", r"\blocation\s+/", r"\bworker_processes\b", r"\bkeepalive_timeout\b"]
    score = sum(1 for p in nginx_patterns if re.search(p, content))
    return "nginx" if score >= 2 else "apache"


def _scan_nginx_config(config_path: str, content: str, result: ConfigScanResult) -> dict:
    """يُحلّل ملف إعدادات Nginx."""
    result.apache_version = ""  # سنملأه بإصدار nginx إن وُجد
    nginx_ver = re.search(r"#.*nginx[/ ](\d+\.\d+\.\d+)", content, re.IGNORECASE)
    if nginx_ver:
        result.apache_version = "nginx/" + nginx_ver.group(1)

    vulns: list[ConfigFinding] = []

    def _line(pattern: str) -> tuple[int, str]:
        for i, ln in enumerate(content.splitlines(), 1):
            if re.search(pattern, ln, re.IGNORECASE):
                return i, ln.strip()
        return 0, ""

    # 1. server_tokens
    ln, ev = _line(r"server_tokens\s+on")
    if ln:
        vulns.append(ConfigFinding(
            check="nginx_server_tokens", severity=Severity.MEDIUM,
            title="server_tokens مُفعَّل",
            description="يُكشف إصدار Nginx في رؤوس HTTP مما يُيسّر استهداف ثغرات محددة.",
            evidence=f"L{ln}: {ev}", line_number=ln,
            remediation="أضف في كتلة http { }: server_tokens off;",
            fixed_directive="server_tokens off;",
        ))
    elif not re.search(r"server_tokens\s+off", content):
        vulns.append(ConfigFinding(
            check="nginx_server_tokens_missing", severity=Severity.LOW,
            title="server_tokens غير مُعرَّف",
            description="القيمة الافتراضية on — يجب التصريح بـ server_tokens off;",
            evidence="لم يُعثر على server_tokens في الملف",
            remediation="أضف في كتلة http { }: server_tokens off;",
            fixed_directive="server_tokens off;",
        ))

    # 2. autoindex
    ln, ev = _line(r"autoindex\s+on")
    if ln:
        vulns.append(ConfigFinding(
            check="nginx_autoindex", severity=Severity.HIGH,
            title="autoindex مُفعَّل",
            description="يعرض قائمة ملفات المجلد للزوار — تسريب بنية الموقع.",
            evidence=f"L{ln}: {ev}", line_number=ln,
            remediation="autoindex off;",
            fixed_directive="autoindex off;",
        ))

    # 3. SSL protocols
    weak_protos = re.findall(r"ssl_protocols\s+([^;]+);", content, re.IGNORECASE)
    for proto_line in weak_protos:
        if "TLSv1 " in proto_line or "TLSv1.1 " in proto_line or proto_line.strip() in ("TLSv1", "TLSv1.1"):
            ln, ev = _line(r"ssl_protocols")
            vulns.append(ConfigFinding(
                check="nginx_ssl_protocols", severity=Severity.HIGH,
                title="بروتوكول TLS قديم في ssl_protocols",
                description=f"يتضمن TLS 1.0 أو 1.1 الضعيفَين: {proto_line.strip()}",
                evidence=f"L{ln}: {ev}", line_number=ln,
                remediation="ssl_protocols TLSv1.2 TLSv1.3;",
                fixed_directive="ssl_protocols TLSv1.2 TLSv1.3;",
            ))

    # 4. ssl_ciphers
    ln, ev = _line(r"ssl_ciphers")
    if ln:
        if re.search(r"(RC4|DES|MD5|NULL|EXPORT|ADH|aNULL)", ev, re.IGNORECASE):
            vulns.append(ConfigFinding(
                check="nginx_weak_ciphers", severity=Severity.HIGH,
                title="خوارزميات تشفير SSL ضعيفة",
                description=f"يتضمن RC4/DES/MD5/NULL/EXPORT: {ev}",
                evidence=f"L{ln}: {ev}", line_number=ln,
                remediation="ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:!RC4:!DES:!MD5;",
                fixed_directive="ssl_ciphers HIGH:!aNULL:!MD5:!RC4;",
            ))
    else:
        vulns.append(ConfigFinding(
            check="nginx_ssl_ciphers_missing", severity=Severity.MEDIUM,
            title="ssl_ciphers غير مُعرَّفة",
            description="يُستخدم الافتراضي الذي قد يشمل خوارزميات ضعيفة.",
            evidence="لم يُعثر على ssl_ciphers في الملف",
            remediation="ssl_ciphers HIGH:!aNULL:!MD5:!RC4;",
            fixed_directive="ssl_ciphers HIGH:!aNULL:!MD5:!RC4;",
        ))

    # 5. add_header X-Frame-Options / X-Content-Type-Options / CSP
    for hdr, sev in [
        ("X-Frame-Options", Severity.MEDIUM),
        ("X-Content-Type-Options", Severity.MEDIUM),
        ("Content-Security-Policy", Severity.HIGH),
        ("Strict-Transport-Security", Severity.HIGH),
    ]:
        if not re.search(rf"add_header\s+{re.escape(hdr)}", content, re.IGNORECASE):
            vulns.append(ConfigFinding(
                check=f"nginx_missing_header_{hdr.lower().replace('-','_')}",
                severity=sev,
                title=f"Header {hdr} مفقود",
                description=f"أضف: add_header {hdr} \"...\";",
                evidence=f"لم يُعثر على add_header {hdr}",
                remediation=f'add_header {hdr} "SAMEORIGIN" always;  # أو القيمة المناسبة',
                fixed_directive=f'add_header {hdr} "SAMEORIGIN" always;',
            ))

    # 6. client_max_body_size
    if not re.search(r"client_max_body_size\s+\d+", content, re.IGNORECASE):
        vulns.append(ConfigFinding(
            check="nginx_client_max_body_size", severity=Severity.LOW,
            title="client_max_body_size غير مُحدَّد",
            description="يسمح بتحميلات ضخمة — خطر DoS.",
            evidence="لم يُعثر على client_max_body_size",
            remediation="client_max_body_size 10m;",
            fixed_directive="client_max_body_size 10m;",
        ))

    # 7. keepalive_timeout
    km = re.search(r"keepalive_timeout\s+(\d+)", content, re.IGNORECASE)
    if not km:
        vulns.append(ConfigFinding(
            check="nginx_keepalive_timeout_missing", severity=Severity.LOW,
            title="keepalive_timeout غير مُحدَّد",
            description="التصريح بالقيمة يثبت سلوك الاتصالات المستمرة في الإنتاج.",
            evidence="لم يُعثر على keepalive_timeout",
            remediation="keepalive_timeout 5;",
            fixed_directive="keepalive_timeout 5;",
        ))
    else:
        kv = int(km.group(1))
        if kv > 15:
            ln, ev = _line(r"keepalive_timeout")
            vulns.append(ConfigFinding(
                check="nginx_keepalive_timeout_high", severity=Severity.LOW,
                title=f"keepalive_timeout مرتفع: {kv}s",
                description="القيمة المرتفعة تستهلك الاتصالات وتزيد أثر هجمات الاتصالات البطيئة.",
                evidence=f"L{ln}: {ev}", line_number=ln,
                remediation="keepalive_timeout 5;",
                fixed_directive="keepalive_timeout 5;",
            ))

    # 8. gzip
    if not re.search(r"\bgzip\s+on\s*;", content, re.IGNORECASE):
        vulns.append(ConfigFinding(
            check="nginx_gzip_off", severity=Severity.LOW,
            title="gzip غير مفعّل",
            description="ضغط الاستجابات النصية يقلل الحجم وزمن التحميل للمستخدم النهائي.",
            evidence="لم يُعثر على gzip on;",
            remediation="gzip on;\ngzip_types text/plain text/css application/json application/javascript text/xml application/xml;",
            fixed_directive="gzip on;",
        ))

    # 9. sendfile explicit policy
    if not re.search(r"\bsendfile\s+(on|off)\s*;", content, re.IGNORECASE):
        vulns.append(ConfigFinding(
            check="nginx_sendfile_missing", severity=Severity.INFO,
            title="sendfile غير مصرح به صراحةً",
            description="التصريح الصريح يثبت سلوك نقل الملفات عبر البيئات المختلفة.",
            evidence="لم يُعثر على sendfile on/off;",
            remediation="sendfile on;  # أو off حسب بيئتك",
            fixed_directive="sendfile on;",
        ))

    # 10. Access log timing for observability
    has_request_time = re.search(r"\$request_time", content, re.IGNORECASE)
    if not has_request_time:
        vulns.append(ConfigFinding(
            check="nginx_access_log_no_request_time", severity=Severity.LOW,
            title="سجل Nginx لا يتضمن request_time",
            description="إضافة $request_time ضرورية لمراقبة SLI/SLO زمن الاستجابة.",
            evidence="لم يُعثر على $request_time في log_format",
            remediation='log_format functional "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent $request_time";\naccess_log /var/log/nginx/access.log functional;',
            fixed_directive='log_format functional "$remote_addr - $remote_user [$time_local] \"$request\" $status $body_bytes_sent $request_time";',
        ))

    # 11. SSL advanced (stapling + session tickets)
    has_stapling = re.search(r"\bssl_stapling\s+on\s*;", content, re.IGNORECASE)
    has_stapling_verify = re.search(r"\bssl_stapling_verify\s+on\s*;", content, re.IGNORECASE)
    tickets_off = re.search(r"\bssl_session_tickets\s+off\s*;", content, re.IGNORECASE)

    if not has_stapling:
        vulns.append(ConfigFinding(
            check="nginx_ssl_stapling_missing", severity=Severity.LOW,
            title="ssl_stapling غير مفعّل",
            description="OCSP stapling يحسن الأداء ويقلل زمن التحقق من الشهادات.",
            evidence="لم يُعثر على ssl_stapling on;",
            remediation="ssl_stapling on;",
            fixed_directive="ssl_stapling on;",
        ))
    if not has_stapling_verify:
        vulns.append(ConfigFinding(
            check="nginx_ssl_stapling_verify_missing", severity=Severity.LOW,
            title="ssl_stapling_verify غير مفعّل",
            description="التحقق من OCSP stapling يمنع قبول استجابات stapling غير موثوقة.",
            evidence="لم يُعثر على ssl_stapling_verify on;",
            remediation="ssl_stapling_verify on;",
            fixed_directive="ssl_stapling_verify on;",
        ))
    if not tickets_off:
        vulns.append(ConfigFinding(
            check="nginx_ssl_session_tickets_policy", severity=Severity.INFO,
            title="ssl_session_tickets policy غير صارمة",
            description="إيقاف session tickets غالباً أفضل للحفاظ على Perfect Forward Secrecy.",
            evidence="لم يُعثر على ssl_session_tickets off;",
            remediation="ssl_session_tickets off;",
            fixed_directive="ssl_session_tickets off;",
        ))

    for finding in vulns:
        if finding.severity == Severity.INFO:
            result.info.append(finding)
        else:
            result.vulnerabilities.append(finding)

    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    result.vulnerabilities.sort(key=lambda f: severity_order[f.severity])

    logger.info("اكتمل فحص Nginx | file=%s | findings=%d", config_path, len(result.vulnerabilities))
    return result.to_dict()


# ══════════════════════════════════════════════════════
#  Public Entry Point
# ══════════════════════════════════════════════════════

def run_server_config_scan(config_path: str) -> dict:
    """
    نقطة الدخول الرئيسية.

    Args:
        config_path: المسار الكامل لملف الإعدادات (httpd.conf أو nginx.conf)

    Returns:
        dict بنفس schema الـ risk_engine
    """
    logger.info("بدء فحص ملف الإعدادات | file=%s", config_path)

    result = ConfigScanResult(
        config_file=Path(config_path).name,
        scanned_at=datetime.now(timezone.utc).isoformat(),
    )

    # ── قراءة الملف ──
    try:
        content = Path(config_path).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        result.error = f"تعذّر قراءة الملف: {e}"
        logger.error(result.error)
        return result.to_dict()

    result.total_lines = content.count("\n") + 1

    # ── تحديد نوع الإعدادات: Apache أم Nginx ──────────────────────────────
    config_type = _detect_config_type(content)
    if config_type == "nginx":
        return _scan_nginx_config(config_path, content, result)

    # ── استخراج إصدار Apache إذا وُجد في تعليق ──
    version_comment = re.search(r"apache[/ ](\d+\.\d+\.\d+)", content, re.IGNORECASE)
    if version_comment:
        result.apache_version = version_comment.group(1)

    # ── تحليل المحتوى ──
    parsed = _parse_config(content)

    # ── تشغيل كل الفحوصات ──
    all_findings: list[ConfigFinding] = []
    all_findings += _check_server_tokens(parsed)
    all_findings += _check_server_signature(parsed)
    all_findings += _check_directory_listing(parsed)
    all_findings += _check_follow_symlinks(parsed)
    all_findings += _check_ssl_settings(parsed)
    all_findings += _check_dangerous_modules(parsed)
    all_findings += _check_trace_method(parsed)
    all_findings += _check_timeout_settings(parsed)
    all_findings += _check_access_control(parsed)
    all_findings += _check_expose_php(parsed)
    # ── CIS L2 Checks ──
    all_findings += _check_limit_request_line(parsed)
    all_findings += _check_limit_request_fields(parsed)
    all_findings += _check_limit_request_field_size(parsed)
    all_findings += _check_limit_request_body(parsed)
    all_findings += _check_security_headers(parsed, content)
    all_findings += _check_http_methods(parsed, content)
    all_findings += _check_allow_override(parsed)
    all_findings += _check_keep_alive(parsed)
    all_findings += _check_logging(parsed)
    all_findings += _check_mod_security(parsed, content)
    all_findings += _check_file_etag(parsed)
    all_findings += _check_exec_cgi(parsed)
    # ── Functional (Performance/Reliability) Checks ──
    all_findings += _check_mpm_mode(content)
    all_findings += _check_max_request_workers(parsed)
    all_findings += _check_max_connections_per_child(parsed)
    all_findings += _check_keep_alive_requests(parsed)
    all_findings += _check_compression_and_cache(content)
    all_findings += _check_functional_log_format(parsed)
    all_findings += _check_sendfile_mmap(parsed)
    all_findings += _check_mod_rewrite_security(content)
    all_findings += _check_tls_session_cache(parsed)
    all_findings += _check_mpm_params(parsed)

    # ── فصل النتائج ──
    for finding in all_findings:
        if finding.severity == Severity.INFO:
            result.info.append(finding)
        else:
            result.vulnerabilities.append(finding)

    # ── ترتيب حسب الخطورة ──
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.HIGH:     1,
        Severity.MEDIUM:   2,
        Severity.LOW:      3,
        Severity.INFO:     4,
    }
    result.vulnerabilities.sort(key=lambda f: severity_order[f.severity])

    logger.info(
        "اكتمل فحص الإعدادات | file=%s | findings=%d",
        config_path,
        len(result.vulnerabilities),
    )

    return result.to_dict()
