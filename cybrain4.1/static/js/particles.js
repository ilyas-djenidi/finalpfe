/**
 * particles.js
 * ─────────────────────────────────────────────
 * Background particle system.
 * Reads config from APP_CONFIG.PARTICLES.
 * Depends on: config.js, utils.js
 */

'use strict';

window.Particles = (function (config, utils) {

    const cfg = config.PARTICLES;

    /**
     * Inject all particle DOM nodes into the container.
     * @param {HTMLElement} container
     */
    function init(container) {
        if (!container) return;

        const fragment = document.createDocumentFragment();

        for (let i = 0; i < cfg.COUNT; i++) {
            const p = document.createElement('div');
            p.className = 'particle';

            /* Random horizontal start */
            p.style.left = utils.randomRange(0, 100) + '%';

            /* Random animation duration */
            const duration = utils.randomRange(cfg.MIN_DURATION, cfg.MAX_DURATION);
            p.style.animationDuration = duration + 's';

            /* Staggered start delay so they don't all appear at once */
            p.style.animationDelay = utils.randomRange(0, 10) + 's';
            p.style.opacity = String(utils.randomRange(0, 0.5));

            /* Some particles are larger and different colour */
            if (Math.random() > cfg.LARGE_CHANCE) {
                p.style.background = cfg.LARGE_COLOR;
                p.style.width  = cfg.LARGE_SIZE + 'px';
                p.style.height = cfg.LARGE_SIZE + 'px';
            }

            fragment.appendChild(p);
        }

        container.appendChild(fragment);
    }

    return Object.freeze({ init });

})(window.APP_CONFIG, window.Utils);
