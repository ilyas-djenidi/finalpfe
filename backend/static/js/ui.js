/**
 * ui.js
 * ─────────────────────────────────────────────
 * DOM helpers and UI state management.
 * Knows about the DOM; knows nothing about business logic.
 * Depends on: config.js, utils.js
 */

'use strict';

window.UI = (function (config, utils) {

    const { TIMINGS, SCAN_STEPS } = config;

    /* ── Clock ── */

    let clockTimer = null;

    function startClock(el) {
        if (!el) return;
        const tick = () => { el.textContent = utils.utcTimeString(); };
        tick();
        clockTimer = setInterval(tick, TIMINGS.CLOCK_INTERVAL);
    }

    function stopClock() {
        if (clockTimer) clearInterval(clockTimer);
    }


    /* ── Alerts ── */

    let alertTimer = null;

    /**
     * Show a temporary alert bar.
     * @param {HTMLElement} el
     * @param {'success'|'error'|'warning'} type
     * @param {string} message
     */
    function showAlert(el, type, message) {
        if (!el) return;
        if (alertTimer) clearTimeout(alertTimer);

        const icon = type === 'success' ? '✓' : type === 'error' ? '✗' : '⚠';
        el.className = `alert-bar ${type}`;
        el.innerHTML = `<span>${icon}</span><span>${utils.sanitise(message)}</span>`;

        alertTimer = setTimeout(() => {
            el.className = 'alert-bar';
        }, TIMINGS.ALERT_HIDE);
    }

    function clearAlert(el) {
        if (!el) return;
        el.className = 'alert-bar';
        el.innerHTML = '';
    }


    /* ── Target Feedback ── */

    /**
     * Render validation feedback below the target input.
     * @param {HTMLElement} el    The feedback container
     * @param {{ type: string, message: string }} result
     */
    function renderTargetFeedback(el, result) {
        if (!el) return;
        if (!result || result.type === 'empty') {
            el.className = 'field-feedback';
            el.innerHTML = '';
            return;
        }
        el.className = `field-feedback visible ${result.type}`;
        el.innerHTML = result.message;
    }


    /* ── Terminal Line ── */

    /**
     * Update the terminal status line text.
     * @param {HTMLElement} el
     * @param {string} target  Current input value
     */
    function updateTerminal(el, target) {
        if (!el) return;
        el.textContent = target
            ? `scanning_target: ${utils.truncate(target, 40)}`
            : 'awaiting_input';
    }


    /* ── Advanced Panel Toggle ── */

    /**
     * @param {HTMLElement} panel
     * @param {HTMLElement} arrow
     * @param {HTMLElement} toggle
     * @param {boolean} open
     */
    function setAdvancedPanel(panel, arrow, toggle, open) {
        panel.classList.toggle('open', open);
        panel.setAttribute('aria-hidden', String(!open));
        toggle.setAttribute('aria-expanded', String(open));
        arrow.textContent = open ? '▼' : '▶';
        arrow.style.color = open ? 'var(--accent-cyan)' : '';
    }


    /* ── Submit Button ── */

    function setSubmitLoading(btn, loading) {
        btn.classList.toggle('loading', loading);
        btn.disabled = loading;
    }


    /* ── Animated Counter ── */

    /**
     * Animate a numeric counter from 0 to target.
     * @param {HTMLElement} el
     * @param {number} target
     * @param {number} [duration]
     */
    function animateCount(el, target, duration = TIMINGS.STATS_DURATION) {
        if (!el) return;
        let current = 0;
        const step = target / (duration / 16);

        const timer = setInterval(() => {
            current += step;
            if (current >= target) {
                current = target;
                clearInterval(timer);
            }
            el.textContent = utils.formatNumber(current);
        }, 16);
    }


    /* ── Progress Bar ── */

    /**
     * Update the progress bar UI.
     * @param {{ fill, pct, steps }} els  DOM element references
     * @param {number} progress           0–100
     */
    function updateProgress(els, progress) {
        const { fill, pct, steps } = els;
        const clamped = utils.clamp(progress, 0, 100);

        fill.style.width   = clamped + '%';
        pct.textContent    = Math.round(clamped) + '%';

        /* Update ARIA attribute on the track */
        const track = fill.parentElement;
        if (track) track.setAttribute('aria-valuenow', Math.round(clamped));

        const stepCount = steps.length;
        const stepIdx   = Math.floor((clamped / 100) * stepCount);

        steps.forEach((s, i) => {
            const el = document.getElementById(s);
            if (!el) return;
            if (i < stepIdx)        el.className = 'progress-step done';
            else if (i === stepIdx) el.className = 'progress-step active';
            else                    el.className = 'progress-step';
        });
    }

    /**
     * Show or hide the scan progress panel.
     * @param {HTMLElement} el
     * @param {boolean} visible
     */
    function setProgressVisible(el, visible) {
        if (!el) return;
        el.classList.toggle('visible', visible);
        el.setAttribute('aria-hidden', String(!visible));
    }

    /**
     * Reset the progress bar to 0.
     * @param {{ fill, pct }} els
     */
    function resetProgress(els) {
        updateProgress({ ...els, steps: SCAN_STEPS }, 0);
    }


    /* ── Public API ── */
    return Object.freeze({
        startClock,
        stopClock,
        showAlert,
        clearAlert,
        renderTargetFeedback,
        updateTerminal,
        setAdvancedPanel,
        setSubmitLoading,
        animateCount,
        updateProgress,
        setProgressVisible,
        resetProgress,
    });

})(window.APP_CONFIG, window.Utils);
