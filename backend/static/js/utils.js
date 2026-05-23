/**
 * utils.js
 * ─────────────────────────────────────────────
 * Pure utility functions — zero DOM dependencies.
 * Safe to unit-test in isolation.
 *
 * Sections:
 *   1. Security
 *   2. String / Format
 *   3. Number / Math
 *   4. Date / Time
 */

'use strict';

window.Utils = (function () {

    /* ── 1. Security ── */

    /**
     * Generate a cryptographically random CSRF token
     * using the Web Crypto API.
     * @returns {string} 64-character hex string
     */
    function generateCSRFToken() {
        const arr = new Uint8Array(32);
        crypto.getRandomValues(arr);
        return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Sanitise a string for safe insertion as text content.
     * Strips HTML tags to prevent XSS when using innerHTML.
     * Prefer textContent where possible.
     * @param {string} str
     * @returns {string}
     */
    function sanitise(str) {
        const el = document.createElement('div');
        el.textContent = str;
        return el.innerHTML;
    }


    /* ── 2. String / Format ── */

    /**
     * Truncate a string to maxLen chars, appending ellipsis.
     * @param {string} str
     * @param {number} maxLen
     * @returns {string}
     */
    function truncate(str, maxLen = 40) {
        if (!str || str.length <= maxLen) return str;
        return str.slice(0, maxLen) + '…';
    }


    /* ── 3. Number / Math ── */

    /**
     * Clamp a number between min and max.
     * @param {number} value
     * @param {number} min
     * @param {number} max
     * @returns {number}
     */
    function clamp(value, min, max) {
        return Math.min(Math.max(value, min), max);
    }

    /**
     * Format a number with locale-aware thousand separators.
     * @param {number} n
     * @returns {string}
     */
    function formatNumber(n) {
        return Math.floor(n).toLocaleString();
    }

    /**
     * Linear interpolation between a and b by t ∈ [0,1].
     * @param {number} a
     * @param {number} b
     * @param {number} t
     * @returns {number}
     */
    function lerp(a, b, t) {
        return a + (b - a) * t;
    }

    /**
     * Returns a random float in [min, max).
     * @param {number} min
     * @param {number} max
     * @returns {number}
     */
    function randomRange(min, max) {
        return min + Math.random() * (max - min);
    }


    /* ── 4. Date / Time ── */

    /**
     * Return current UTC time as HH:MM:SS string.
     * @returns {string}
     */
    function utcTimeString() {
        return new Date().toISOString().slice(11, 19);
    }


    /* ── Public API ── */
    return Object.freeze({
        generateCSRFToken,
        sanitise,
        truncate,
        clamp,
        formatNumber,
        lerp,
        randomRange,
        utcTimeString,
    });

})();
