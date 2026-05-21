# scanners/dast_scanner.py
"""
DAST Scanner — Dynamic Application Security Testing
────────────────────────────────────────────────────
يفحص تطبيق ويب يعمل فعلاً باستخدام Nikto.

الأداة: Nikto (https://github.com/sullo/nikto)
  Linux:   sudo apt install nikto
  Windows: تحميل من الموقع الرسمي + Perl

تحذير: لا تستخدم هذا الفحص إلا على أهداف تملك تصريحاً قانونياً بفحصها.
"""

import csv
import io
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)

NIKTO_TIMEOUT = 360    # 6 دقائق أقصى
MAX_SCAN_TIME = "300s" # 5 دقائق لـ Nikto نفسه
ZAP_TIMEOUT = 300      # 5 دقائق لـ ZAP

# False Positives المعروفة نستبعدها
_FP_PATTERNS = [
    r"anti-clickjacking",
    r"x-frame-options header",
    r"x-content-type-options",
    r"the anti-clickjacking",
    r"retrieved via a get request",
    r"no cgi",
]


def _normalise_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        return "https://" + target
    return target


def _parse_severity(description: str) -> str:
    """يُقدّر خطورة النتيجة من وصفها."""
    desc_lower = description.lower()
    if any(w in desc_lower for w in [
        "remote code", "rce", "execute", "shell", "overflow", "critical",
        "sql injection", "command injection", "directory traversal",
    ]):
        return "critical"
    if any(w in desc_lower for w in [
        "xss", "cross-site scripting", "injection", "backdoor",
        "default credential", "password", "authentication bypass",
        "unrestricted file upload", "high",
    ]):
        return "high"
    if any(w in desc_lower for w in [
        "version", "outdated", "disclosure", "server", "medium",
        "misconfiguration", "enabled", "open",
    ]):
        return "medium"
    return "low"


def _severity_rank(severity: str) -> int:
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    return order.get(severity, 0)


def _merge_dast_findings(nikto_vulns: list[dict], zap_vulns: list[dict]) -> list[dict]:
    def key_for(v: dict) -> str:
        base = (v.get("title", "") + "|" + v.get("description", "") + "|" + v.get("evidence", "")).lower()
        return re.sub(r"\s+", " ", base).strip()[:300]

    merged: dict[str, dict] = {}
    for v in nikto_vulns:
        k = key_for(v)
        item = dict(v)
        item["source"] = "nikto"
        item["confidence"] = "medium"
        merged[k] = item

    for v in zap_vulns:
        k = key_for(v)
        if k in merged:
            existing = merged[k]
            existing["source"] = "nikto+zap"
            existing["confidence"] = "high"
            if _severity_rank(v.get("severity", "")) > _severity_rank(existing.get("severity", "")):
                existing["severity"] = v.get("severity")
        else:
            item = dict(v)
            item["source"] = "zap"
            item["confidence"] = "medium"
            merged[k] = item

    return list(merged.values())


def _run_nikto_scan(url: str) -> tuple[list[dict], str | None]:
    nikto_cmd = (
        shutil.which("nikto")
        or shutil.which("nikto.pl")
        or shutil.which("perl")
    )
    if not nikto_cmd:
        return [], "Nikto غير مثبّت أو غير موجود في PATH."

    tmp_output = tempfile.mktemp(suffix="_nikto.csv")
    vulns: list[dict] = []

    try:
        cmd = [
            nikto_cmd, "-h", url,
            "-Format", "csv",
            "-o", tmp_output,
            "-nointeractive",
            "-timeout", "10",
            "-maxtime", MAX_SCAN_TIME,
            "-C", "all",
        ]

        logger.info("DAST(Nikto) | target=%s | cmd=%s", url, " ".join(cmd[:3]))

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=NIKTO_TIMEOUT,
        )

        if os.path.exists(tmp_output):
            with open(tmp_output, encoding="utf-8", errors="replace") as f:
                content = f.read()

            reader = csv.reader(io.StringIO(content))
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue
                if len(row) < 5:
                    continue

                if len(row) >= 7:
                    uri  = row[3].strip()
                    desc = row[6].strip()
                elif len(row) >= 5:
                    uri  = row[3].strip()
                    desc = row[4].strip()
                else:
                    continue

                if not desc:
                    continue

                if any(re.search(fp, desc, re.IGNORECASE) for fp in _FP_PATTERNS):
                    continue

                sev = _parse_severity(desc)

                vulns.append({
                    "title":       f"[DAST] {desc[:120]}",
                    "severity":    sev,
                    "description": desc,
                    "evidence":    f"URI: {url.rstrip('/')}{uri}" if uri else url,
                    "remediation": "راجع توثيق OWASP للثغرة المكتشفة وطبّق الإصلاح المناسب",
                })

        elif proc.stdout:
            for line in proc.stdout.splitlines():
                if line.startswith("+") and len(line) > 10:
                    desc = line.lstrip("+ ").strip()
                    if any(re.search(fp, desc, re.IGNORECASE) for fp in _FP_PATTERNS):
                        continue
                    vulns.append({
                        "title":       f"[DAST] {desc[:120]}",
                        "severity":    _parse_severity(desc),
                        "description": desc,
                        "evidence":    url,
                        "remediation": "راجع توثيق OWASP",
                    })

        return vulns, None

    except subprocess.TimeoutExpired:
        return [], f"انتهت مهلة فحص DAST ({NIKTO_TIMEOUT}s). الهدف بطيء أو كبير جداً."
    finally:
        if os.path.exists(tmp_output):
            try:
                os.unlink(tmp_output)
            except OSError:
                pass


def _zap_request(base_url: str, path: str, api_key: str | None, params: dict | None = None) -> dict:
    params = params or {}
    if api_key:
        params["apikey"] = api_key
    resp = requests.get(f"{base_url}{path}", params=params, timeout=10)
    resp.raise_for_status()
    return resp.json()


def _run_zap_scan(url: str) -> tuple[list[dict], str | None]:
    zap_url = os.environ.get("ZAP_URL", "http://127.0.0.1:8080").rstrip("/")
    zap_key = os.environ.get("ZAP_API_KEY")
    if os.environ.get("ZAP_ENABLED", "1") in ("0", "false", "False"):
        return [], "ZAP معطّل عبر ZAP_ENABLED=0"

    try:
        _zap_request(zap_url, "/JSON/core/view/version/", zap_key)
    except Exception as exc:
        return [], f"ZAP غير متاح على {zap_url}: {exc}"

    try:
        logger.info("DAST(ZAP) | target=%s | zap=%s", url, zap_url)

        spider = _zap_request(zap_url, "/JSON/spider/action/scan/", zap_key, {"url": url})
        spider_id = spider.get("scan")
        if spider_id:
            for _ in range(120):
                status = _zap_request(zap_url, "/JSON/spider/view/status/", zap_key, {"scanId": spider_id})
                if status.get("status") == "100":
                    break
                time.sleep(1)

        ascan = _zap_request(zap_url, "/JSON/ascan/action/scan/", zap_key, {"url": url, "recurse": True})
        scan_id = ascan.get("scan")
        if scan_id:
            for _ in range(ZAP_TIMEOUT):
                status = _zap_request(zap_url, "/JSON/ascan/view/status/", zap_key, {"scanId": scan_id})
                if status.get("status") == "100":
                    break
                time.sleep(1)

        alerts = _zap_request(zap_url, "/JSON/alert/view/alerts/", zap_key, {"baseurl": url}).get("alerts", [])
        vulns: list[dict] = []
        for a in alerts:
            risk = (a.get("risk", "") or "").lower()
            severity = {
                "high": "high",
                "medium": "medium",
                "low": "low",
                "informational": "info",
            }.get(risk, "low")
            desc = a.get("desc", "") or a.get("alert", "")
            if not desc:
                continue
            vulns.append({
                "title":       f"[ZAP] {a.get('alert', '')[:120]}",
                "severity":    severity,
                "description": desc,
                "evidence":    a.get("url", url),
                "remediation": a.get("solution", "راجع توثيق OWASP لإصلاح الثغرة"),
            })

        return vulns, None

    except Exception as exc:
        return [], f"فشل ZAP: {exc}"


def run_dast_scan(target: str) -> dict:
    """
    يُشغّل Nikto على الهدف ويُعيد النتائج في الشكل المعياري.

    Args:
        target: URL أو نطاق أو IP

    Returns:
        dict بالشكل { "vulnerabilities": [...], "meta": {...} }
    """
    url   = _normalise_url(target)
    # ── التحقق من قابلية الوصول للهدف قبل إطلاق Nikto ─────────────────────
    parsed_host = urlparse(url).hostname or ""
    try:
        socket.getaddrinfo(parsed_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise RuntimeError(f"تعذّر حل اسم الهدف '{parsed_host}': {exc}") from exc

    nikto_vulns, nikto_error = _run_nikto_scan(url)
    if nikto_error:
        logger.warning("DAST(Nikto) skipped | %s", nikto_error)

    zap_vulns, zap_error = _run_zap_scan(url)
    if zap_error:
        logger.warning("DAST(ZAP) skipped | %s", zap_error)

    if not nikto_vulns and not zap_vulns:
        raise RuntimeError(
            "تعذر تنفيذ فحص DAST: لا Nikto ولا ZAP متاحين."
        )

    vulns = _merge_dast_findings(nikto_vulns, zap_vulns)
    meta = {
        "scan_time":     datetime.now(timezone.utc).isoformat(),
        "tools":         [t for t, v in (("nikto", nikto_vulns), ("zap", zap_vulns)) if v],
        "target_url":    url,
        "issues_found":  len(vulns),
        "nikto_issues":  len(nikto_vulns),
        "zap_issues":    len(zap_vulns),
        "nikto_error":   nikto_error,
        "zap_error":     zap_error,
    }

    return {
        "scan_type":       "dast",
        "target":          target,
        "vulnerabilities": vulns,
        "meta":            meta,
    }
