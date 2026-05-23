/**
 * main.js
 * ─────────────────────────────────────────────
 * Application entry point.
 * Bootstraps all modules after DOM is ready.
 * This file should stay thin — logic belongs in modules.
 *
 * Load order (enforced by <script> tags in index.html):
 *   1. config.js
 *   2. utils.js
 *   3. particles.js
 *   4. validator.js
 *   5. ui.js
 *   6. form.js
 *   7. main.js  ← you are here
 */

'use strict';

(function (config, ui, form, particles) {

    /* ── Advanced Panel Toggle (standalone widget) ── */
    function _initAdvancedToggle() {
        const toggle = document.getElementById('advancedToggle');
        const panel  = document.getElementById('advancedPanel');
        const arrow  = document.getElementById('advancedArrow');

        if (!toggle || !panel || !arrow) return;

        let open = false;

        toggle.addEventListener('click', () => {
            open = !open;
            ui.setAdvancedPanel(panel, arrow, toggle, open);
        });

        /* Keyboard support (Space / Enter) */
        toggle.addEventListener('keydown', (e) => {
            if (e.key === ' ' || e.key === 'Enter') {
                e.preventDefault();
                toggle.click();
            }
        });
    }

    /* ── Stats Counter Animation (fetched live from /api/stats) ── */
    function _initStats() {
        const { TIMINGS } = config;
        fetch('/api/stats')
            .then(r => r.ok ? r.json() : {})
            .catch(() => ({}))
            .then(data => {
                setTimeout(() => {
                    ui.animateCount(document.getElementById('statScans'),   data.total_scans  || 0);
                    ui.animateCount(document.getElementById('statThreats'), data.total_vulns  || 0);
                }, TIMINGS.STATS_DELAY);
            });
    }

    /* ── Bootstrap ── */
    function _boot() {
        /* Particles */
        particles.init(document.getElementById('particles'));

        /* Clock */
        ui.startClock(document.getElementById('sysTime'));

        /* Form */
        form.init();

        /* Advanced toggle */
        _initAdvancedToggle();

        /* Stats counters */
        _initStats();

        console.info('[CyBrain] Platform initialised ✓');
    }

    /* Run after DOM is ready */
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', _boot);
    } else {
        _boot(); /* already ready (deferred scripts run after parsing) */
    }

})(window.APP_CONFIG, window.UI, window.Form, window.Particles);
