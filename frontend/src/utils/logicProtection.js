// API base — set VITE_API_URL in .env for production (e.g. https://api.cybrain.io)
const BACKEND = import.meta.env.VITE_API_URL || 'http://127.0.0.1:5000';

export const API_ENDPOINTS = {
    // SAST: upload a .zip → /analyze_code
    ANALYZE_CODE:    `${BACKEND}/analyze_code`,
    // Apache config: upload .conf/.txt → /fix_config
    FIX_CONFIG:      `${BACKEND}/fix_config`,
    // URL web scan → /scan_url
    SCAN_URL:        `${BACKEND}/scan_url`,
    // Network scan → /scan_network
    SCAN_NETWORK:    `${BACKEND}/scan_network`,
    // Report download → /api/reports/:token
    REPORT_BASE:     `${BACKEND}/api/reports`,
    // AI chat
    CHAT:            `${BACKEND}/api/chat`,
    // AI findings analysis
    ANALYZE_FINDINGS:`${BACKEND}/api/analyze_findings`,
};

// Severity order — matches backend lowercase output
export const SEVERITY_ORDER = {
    critical: 0,
    high:     1,
    medium:   2,
    low:      3,
    info:     4,
};

// Severity colors — used in ResultsPanel and SeverityBadge
export const SEVERITY_STYLES = {
    critical: {
        bg:     '#000000',
        border: '#ef4444',
        text:   '#ef4444',
        badge:  'bg-red-500/20 text-red-400 border-red-500/40',
    },
    high: {
        bg:     '#000000',
        border: '#f97316',
        text:   '#f97316',
        badge:  'bg-orange-500/20 text-orange-400 border-orange-500/40',
    },
    medium: {
        bg:     '#000000',
        border: '#eab308',
        text:   '#eab308',
        badge:  'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
    },
    low: {
        bg:     '#000000',
        border: '#22c55e',
        text:   '#22c55e',
        badge:  'bg-green-500/20 text-green-400 border-green-500/40',
    },
    info: {
        bg:     '#000000',
        border: '#6b7280',
        text:   '#9ca3af',
        badge:  'bg-gray-500/20 text-gray-400 border-gray-500/40',
    },
};

// Sort findings by severity (critical first)
export const sortBySeverity = (findings) => {
    return [...findings].sort(
        (a, b) =>
            (SEVERITY_ORDER[(a.severity || '').toLowerCase()] ?? 9) -
            (SEVERITY_ORDER[(b.severity || '').toLowerCase()] ?? 9)
    );
};

// Format a finding message for display
export const formatFinding = (finding) => {
    const parts = [finding.message || ''];
    if (finding.fix)
        parts.push(`<strong>Recommendation:</strong><br>${finding.fix}`);
    if (finding.evidence)
        parts.push(`<strong>Evidence:</strong><br><code>${finding.evidence}</code>`);
    if (finding.cwe)
        parts.push(`<strong>CWE:</strong> ${finding.cwe}`);
    if (finding.owasp)
        parts.push(`<strong>OWASP:</strong> ${finding.owasp}`);
    return parts.join('\n\n');
};
