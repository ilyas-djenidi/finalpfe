/**
 * config.js
 * ─────────────────────────────────────────────
 * Application-wide constants.
 * Change values here — never scatter magic numbers
 * or URLs through other modules.
 *
 * Exposed as a frozen object on window.APP_CONFIG
 * so any module can read it without importing.
 */

window.APP_CONFIG = Object.freeze({

    /* ── API ── */
    API: {
        SCAN_ENDPOINT:  '/start-scan',
        METHOD:         'POST',
    },

    /* ── Validation ── */
    VALIDATION: {
        DOMAIN_REGEX: /^(https?:\/\/)?(([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})(:\d+)?(\/.*)?$/,
        IP_REGEX:     /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/,
        PRIVATE_RANGES: [
            /^10\./,
            /^172\.(1[6-9]|2\d|3[01])\./,
            /^192\.168\./,
        ],
    },

    /* ── UI Timings (ms) ── */
    TIMINGS: {
        ALERT_HIDE:       5000,
        STATS_DELAY:       800,
        STATS_DURATION:   1500,
        PROGRESS_TICK:     150,
        PROGRESS_MIN_STEP:   2,
        PROGRESS_MAX_STEP:   8,
        PROGRESS_COMPLETE_DELAY: 2000,
        CLOCK_INTERVAL:   1000,
    },

    /* ── Particles ── */
    PARTICLES: {
        COUNT:          30,
        MIN_DURATION:    8,    /* seconds */
        MAX_DURATION:   12,
        LARGE_CHANCE:    0.7,  /* probability a particle is large */
        LARGE_SIZE:      3,    /* px */
        LARGE_COLOR:    '#00ff88',
    },

    /* ── Scan Steps ── */
    SCAN_STEPS: ['step1', 'step2', 'step3', 'step4', 'step5'],

});
