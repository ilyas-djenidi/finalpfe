/**
 * validator.js
 * ─────────────────────────────────────────────
 * Input validation logic — pure functions.
 * Returns structured result objects; never touches the DOM.
 * Depends on: config.js
 *
 * Result shape:
 *   { valid: boolean, type: 'valid'|'warning'|'invalid', message: string }
 */

'use strict';

window.Validator = (function (config) {

    const { DOMAIN_REGEX, IP_REGEX, PRIVATE_RANGES } = config.VALIDATION;

    /* ── Helpers ── */

    function isPrivateIP(value) {
        return PRIVATE_RANGES.some(r => r.test(value));
    }

    function isDomain(value) {
        return DOMAIN_REGEX.test(value);
    }

    function isIP(value) {
        return IP_REGEX.test(value);
    }


    /* ── Public ── */

    /**
     * Validate a scan target (domain or IP).
     * @param {string} value  Raw input string
     * @returns {{ valid: boolean, type: string, message: string }}
     */
    function validateTarget(value) {
        const v = (value || '').trim();

        if (!v) {
            return { valid: false, type: 'empty', message: '' };
        }

        if (isPrivateIP(v)) {
            return {
                valid:   true,   /* technically usable, but warn */
                type:    'warning',
                message: '⚠ تحذير: عنوان IP خاص — تأكد من صلاحية الوصول',
            };
        }

        if (isDomain(v) || isIP(v)) {
            return {
                valid:   true,
                type:    'valid',
                message: '✓ هدف صالح — جاهز للفحص',
            };
        }

        return {
            valid:   false,
            type:    'invalid',
            message: '✗ صيغة غير صحيحة — أدخل نطاقًا أو عنوان IP',
        };
    }

    /**
     * Quick boolean check — used before form submit.
     * @param {string} value
     * @returns {boolean}
     */
    function isValidTarget(value) {
        const v = (value || '').trim();
        return isDomain(v) || isIP(v);
    }

    return Object.freeze({
        validateTarget,
        isValidTarget,
    });

})(window.APP_CONFIG);
