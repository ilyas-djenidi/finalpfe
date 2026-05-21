/**
 * form.js
 * ─────────────────────────────────────────────
 * Form submission, CSRF injection, and scan
 * progress simulation.
 * Depends on: config.js, utils.js, validator.js, ui.js
 */

'use strict';

window.Form = (function (config, utils, validator, ui) {

    const { TIMINGS, SCAN_STEPS } = config;

    /* ── DOM References ── */
    const els = {};

    function _bindElements() {
        els.form        = document.getElementById('scanForm');
        els.csrfToken   = document.getElementById('csrfToken');
        els.target      = document.getElementById('target');
        els.feedback    = document.getElementById('targetFeedback');
        els.terminal    = document.getElementById('terminalText');
        els.alertBar    = document.getElementById('alertBar');
        els.submitBtn   = document.getElementById('submitBtn');
        els.progressWrap = document.getElementById('scanProgress');
        els.progressFill = document.getElementById('progressFill');
        els.progressPct  = document.getElementById('progressPct');
    }

    const progressEls = () => ({
        fill:  els.progressFill,
        pct:   els.progressPct,
        steps: SCAN_STEPS,
    });


    /* ── CSRF ── */

    function _injectCSRF() {
        // CSRF token is generated server-side by Flask-WTF via {{ form.hidden_tag() }}.
        // Do NOT override the value here — overwriting it breaks CSRF validation.
        // This function is intentionally left as a no-op.
    }


    /* ── Validation listeners ── */

    function _bindTargetValidation() {
        if (!els.target) return;

        els.target.addEventListener('input', () => {
            const val    = els.target.value.trim();
            const result = validator.validateTarget(val);

            ui.renderTargetFeedback(els.feedback, result);
            ui.updateTerminal(els.terminal, val);
        });
    }


    /* ── Progress ── */

    let _progressTimer = null;

    /** Creep bar up to 90% while waiting for server response. */
    function _startProgress() {
        ui.setProgressVisible(els.progressWrap, true);
        let progress = 0;

        _progressTimer = setInterval(() => {
            if (progress < 90) {
                progress += utils.randomRange(
                    TIMINGS.PROGRESS_MIN_STEP,
                    TIMINGS.PROGRESS_MAX_STEP,
                );
                if (progress > 90) progress = 90;
                ui.updateProgress(progressEls(), progress);
            }
        }, TIMINGS.PROGRESS_TICK);
    }

    /** Jump bar to 100% then hide after delay. */
    function _finishProgress() {
        if (_progressTimer) { clearInterval(_progressTimer); _progressTimer = null; }
        ui.updateProgress(progressEls(), 100);
        setTimeout(() => {
            ui.setProgressVisible(els.progressWrap, false);
            ui.resetProgress(progressEls());
        }, TIMINGS.PROGRESS_COMPLETE_DELAY);
    }


    /* ── Results Renderer ── */

    function _renderResults(data) {
        const panel = document.getElementById('scanResults');
        if (!panel) return;

        const result = data.scan_result || {};
        const risk   = typeof data.risk_score === 'number' ? data.risk_score : 0;
        const vulns  = result.vulnerabilities || [];
        const token  = data.report_token || '';

        const sevAr = { critical: 'حرج', high: 'عالٍ', medium: 'متوسط', low: 'منخفض', info: 'معلومات' };
        const riskClass = risk >= 8 ? 'critical' : risk >= 6 ? 'high' : risk >= 4 ? 'medium' : 'low';

        const vulnHTML = vulns.length === 0
            ? '<div class="vuln-empty">✓ لم يتم اكتشاف ثغرات واضحة في هذا الفحص</div>'
            : vulns.map(v => {
                const rec = v.recommendation || v.remediation || '';
                const fixLine = v.fixed_directive
                    ? `<div class="vuln-fix-line"><span class="fix-label">الإصلاح المقترح:</span><code>${utils.sanitise(v.fixed_directive)}</code></div>`
                    : '';
                return `
                <div class="vuln-item sev-${v.severity || 'info'}">
                    <div class="vuln-header">
                        <span class="vuln-badge">${utils.sanitise(sevAr[v.severity] || v.severity || 'info')}</span>
                        <span class="vuln-title">${utils.sanitise(v.title || v.id || 'ثغرة غير محددة')}</span>
                        ${v.line_number ? `<span class="vuln-line">سطر ${v.line_number}</span>` : ''}
                    </div>
                    ${v.description ? `<p class="vuln-desc">${utils.sanitise(v.description)}</p>` : ''}
                    ${v.evidence     ? `<div class="vuln-evidence"><span class="ev-label">الحالة الحالية:</span><code>${utils.sanitise(v.evidence)}</code></div>` : ''}
                    ${fixLine}
                    ${rec             ? `<p class="vuln-rec">⟶ ${utils.sanitise(rec)}</p>` : ''}
                </div>`;
            }).join('');

        /* ── أزرار التحميل ── */
        const reportBtn = token
            ? `<a href="/report/${token}" target="_blank" class="result-btn btn-report">🖨️ فتح التقرير الكامل / PDF</a>`
            : '';
        const fixBtn = (token && result.scan_type === 'server_config')
            ? `<a href="/download-fixed/${token}" class="result-btn btn-fix-dl">⬇️ تحميل الملف المُصحَّح</a>`
            : '';

        panel.innerHTML = `
            <div class="results-header">
                <span class="results-title">[ تقرير الفحص الأمني ]</span>
                <span class="risk-badge ${riskClass}">RISK: ${risk.toFixed(1)} / 10</span>
            </div>
            <div class="results-meta">
                <span>الهدف: <strong>${utils.sanitise(result.target || 'local')}</strong></span>
                <span>نوع الفحص: <strong>${utils.sanitise(result.scan_type || '')}</strong></span>
                <span>الثغرات المكتشفة: <strong>${vulns.length}</strong></span>
            </div>
            <div class="vulns-list">${vulnHTML}</div>
            ${(reportBtn || fixBtn) ? `<div class="results-actions">${reportBtn}${fixBtn}</div>` : ''}
        `;
        panel.hidden = false;
        panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }


    /* ── Submit Handler ── */

    /** Scan types that don't require a target address (use file upload instead) */
    const NO_TARGET_TYPES = new Set(['server_int', 'dependencies']);

    function _getSelectedScanType() {
        const checked = document.querySelector('input[name="scan_type"]:checked');
        return checked ? checked.value : '';
    }

    function _handleSubmit(e) {
        e.preventDefault();

        const target      = (els.target ? els.target.value : '').trim();
        const scanType    = _getSelectedScanType();
        const skipTarget  = NO_TARGET_TYPES.has(scanType);

        /* Empty check — skip for file-only scan types */
        if (!skipTarget && !target) {
            ui.showAlert(els.alertBar, 'error', 'يرجى إدخال الهدف أولًا');
            if (els.target) els.target.focus();
            return;
        }

        /* Format check — skip for file-only scan types */
        if (!skipTarget && !validator.isValidTarget(target)) {
            ui.showAlert(els.alertBar, 'error', 'صيغة الهدف غير صحيحة — أدخل نطاقًا صالحًا أو عنوان IP');
            if (els.target) els.target.focus();
            return;
        }

        /* Proceed — real fetch to backend */
        ui.setSubmitLoading(els.submitBtn, true);
        ui.updateTerminal(els.terminal, `initializing_scan: ${target || 'local'}`);

        // إخفاء نتائج الفحص السابق إن وجدت
        const oldPanel = document.getElementById('scanResults');
        if (oldPanel) { oldPanel.hidden = true; oldPanel.innerHTML = ''; }

        _startProgress();

        const fd = new FormData(els.form);
        fetch(config.API.SCAN_ENDPOINT, { method: config.API.METHOD, body: fd })
            .then(res => res.json().then(body => ({ ok: res.ok, body })))
            .then(({ ok, body }) => {
                _finishProgress();
                ui.setSubmitLoading(els.submitBtn, false);
                if (!ok) {
                    ui.showAlert(els.alertBar, 'error', body.error || 'حدث خطأ أثناء تنفيذ الفحص');
                } else {
                    ui.showAlert(els.alertBar, 'success', 'اكتمل الفحص بنجاح ✓');
                    _renderResults(body);
                }
            })
            .catch(() => {
                _finishProgress();
                ui.setSubmitLoading(els.submitBtn, false);
                ui.showAlert(els.alertBar, 'error', 'فشل الاتصال بالخادم — تحقق من الشبكة');
            });
    }

    /* ── Reset Handler ── */

    function _handleReset() {
        ui.clearAlert(els.alertBar);
        ui.renderTargetFeedback(els.feedback, null);
        ui.updateTerminal(els.terminal, '');
        if (_progressTimer) { clearInterval(_progressTimer); _progressTimer = null; }
        ui.setProgressVisible(els.progressWrap, false);
        ui.resetProgress(progressEls());
        ui.setSubmitLoading(els.submitBtn, false);
        // إخفاء لوحة النتائج عند إعادة الضبط
        const panel = document.getElementById('scanResults');
        if (panel) { panel.hidden = true; panel.innerHTML = ''; }
    }


    /* ── Init ── */

    function init() {
        _bindElements();
        _injectCSRF();
        _bindTargetValidation();

        if (els.form) {
            els.form.addEventListener('submit', _handleSubmit);
            els.form.addEventListener('reset',  _handleReset);
        }
    }

    return Object.freeze({ init });

})(window.APP_CONFIG, window.Utils, window.Validator, window.UI);
