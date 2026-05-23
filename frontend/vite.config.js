import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const FLASK = 'http://127.0.0.1:5000';

const proxy = (timeout = 480000) => ({
    target:       FLASK,
    changeOrigin: true,
    timeout,
    proxyTimeout: timeout,
    configure: (proxy) => {
        proxy.on('error', (err, _req, res) => {
            if (!res.headersSent) {
                res.writeHead(502, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Flask backend offline', detail: err.message }));
            }
        });
    },
});

export default defineConfig({
    plugins: [react()],
    server: {
        port: 3000,
        proxy: {
            // ── Scan Endpoints ────────────────────────────────────────────
            '/scan_url':              proxy(480000),
            '/scan_network':          proxy(480000),
            '/scan_server':           proxy(480000),
            '/scan_dast':             proxy(480000),
            '/scan_dependencies':     proxy(480000),
            '/analyze_code':          proxy(480000),
            '/analyze':               proxy(480000),
            '/fix_code':              proxy(480000),
            '/fix_config':            proxy(480000),

            // ── Download / Export ─────────────────────────────────────────
            '/download_report':       proxy(60000),
            '/download_report_csv':   proxy(60000),
            '/download_report_json':  proxy(60000),
            '/download_fixed':        proxy(60000),

            // ── API (auth, dashboard, admin, AI, stats) ───────────────────
            '/api':                   proxy(480000),

            // ── Health ────────────────────────────────────────────────────
            '/health':                proxy(10000),

            // ── Legacy Flask HTML routes (kept for compatibility) ──────────
            '/start-scan':            proxy(480000),
        }
    }
})
