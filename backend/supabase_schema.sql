-- ════════════════════════════════════════════════════════════════════
--  CyBrain Security Platform — Supabase PostgreSQL Schema
--  Run this in: Supabase Dashboard → SQL Editor
-- ════════════════════════════════════════════════════════════════════

-- ── Users ────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL PRIMARY KEY,
    username        TEXT      UNIQUE NOT NULL,
    password_hash   TEXT      NOT NULL,
    role            TEXT      NOT NULL DEFAULT 'analyst',
    permissions     JSONB     NOT NULL DEFAULT '["run_scan","view_reports"]'::jsonb,
    is_active       BOOLEAN   NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login      TIMESTAMPTZ,
    login_count     INTEGER   NOT NULL DEFAULT 0,
    failed_attempts INTEGER   NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ,
    created_by      TEXT      NOT NULL DEFAULT 'system',
    totp_secret     TEXT      NOT NULL DEFAULT '',
    totp_enabled    BOOLEAN   NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

-- ── Scan Reports ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_reports (
    id               BIGSERIAL PRIMARY KEY,
    token            TEXT      UNIQUE NOT NULL,
    user_id          BIGINT    REFERENCES users(id) ON DELETE SET NULL,
    username         TEXT      NOT NULL,
    scan_type        TEXT      NOT NULL,
    target           TEXT      NOT NULL DEFAULT '',
    risk_score       FLOAT     NOT NULL DEFAULT 0.0,
    vuln_count       INTEGER   NOT NULL DEFAULT 0,
    critical_count   INTEGER   NOT NULL DEFAULT 0,
    high_count       INTEGER   NOT NULL DEFAULT 0,
    medium_count     INTEGER   NOT NULL DEFAULT 0,
    low_count        INTEGER   NOT NULL DEFAULT 0,
    result_json      TEXT      NOT NULL,
    original_content TEXT,
    stored_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_reports_user  ON scan_reports(user_id, stored_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_token ON scan_reports(token);
CREATE INDEX IF NOT EXISTS idx_reports_time  ON scan_reports(stored_at DESC);

-- ── Scan Vulnerabilities ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
    id          BIGSERIAL PRIMARY KEY,
    report_id   BIGINT    NOT NULL REFERENCES scan_reports(id) ON DELETE CASCADE,
    check_name  TEXT      NOT NULL,
    severity    TEXT      NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    title       TEXT      NOT NULL,
    description TEXT,
    evidence    TEXT,
    remediation TEXT,
    line_number INTEGER   NOT NULL DEFAULT 0,
    cve_ids     JSONB     NOT NULL DEFAULT '[]'::jsonb,
    is_fixed    BOOLEAN   NOT NULL DEFAULT false,
    fixed_at    TIMESTAMPTZ,
    found_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vulns_report   ON scan_vulnerabilities(report_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON scan_vulnerabilities(severity, report_id);
CREATE INDEX IF NOT EXISTS idx_vulns_check    ON scan_vulnerabilities(check_name);

-- ── Audit Log ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_log (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id     BIGINT      REFERENCES users(id) ON DELETE SET NULL,
    username    TEXT        NOT NULL DEFAULT 'system',
    action      TEXT        NOT NULL,
    category    TEXT        NOT NULL DEFAULT 'general',
    resource    TEXT,
    ip_address  TEXT,
    user_agent  TEXT,
    status      TEXT        NOT NULL DEFAULT 'success',
    details     TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_time   ON audit_log(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_user   ON audit_log(user_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);

-- ════════════════════════════════════════════════════════════════════
--  RPC Functions (called from Python via supabase.rpc())
-- ════════════════════════════════════════════════════════════════════

-- User dashboard stats
CREATE OR REPLACE FUNCTION get_dashboard_stats(p_user_id BIGINT)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE result JSON;
BEGIN
    SELECT json_build_object(
        'total_scans',    COUNT(*),
        'total_vulns',    COALESCE(SUM(vuln_count)::int, 0),
        'critical_count', COALESCE(SUM(critical_count)::int, 0),
        'high_count',     COALESCE(SUM(high_count)::int, 0),
        'avg_risk_score', ROUND(COALESCE(AVG(risk_score), 0)::numeric, 1),
        'by_type', (
            SELECT json_agg(row_to_json(t)) FROM (
                SELECT scan_type, COUNT(*) AS count
                FROM scan_reports WHERE user_id = p_user_id
                GROUP BY scan_type ORDER BY count DESC
            ) t
        ),
        'recent_scores', (
            SELECT json_agg(row_to_json(t)) FROM (
                SELECT risk_score AS score, stored_at AS at
                FROM scan_reports WHERE user_id = p_user_id
                ORDER BY stored_at DESC LIMIT 15
            ) t
        )
    ) INTO result
    FROM scan_reports WHERE user_id = p_user_id;
    RETURN COALESCE(result, '{"total_scans":0,"total_vulns":0,"critical_count":0,"high_count":0,"avg_risk_score":0,"by_type":[],"recent_scores":[]}'::json);
END;
$$;

-- Admin dashboard stats
CREATE OR REPLACE FUNCTION get_all_dashboard_stats()
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE result JSON;
BEGIN
    SELECT json_build_object(
        'total_scans',    COUNT(*),
        'total_vulns',    COALESCE(SUM(vuln_count)::int, 0),
        'critical_count', COALESCE(SUM(critical_count)::int, 0),
        'high_count',     COALESCE(SUM(high_count)::int, 0),
        'avg_risk_score', ROUND(COALESCE(AVG(risk_score), 0)::numeric, 1),
        'active_users',   COUNT(DISTINCT user_id),
        'by_type', (
            SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (
                SELECT scan_type, COUNT(*) AS count FROM scan_reports
                GROUP BY scan_type ORDER BY count DESC
            ) t
        ),
        'recent_scores', (
            SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (
                SELECT risk_score AS score, stored_at AS at
                FROM scan_reports ORDER BY stored_at DESC LIMIT 15
            ) t
        )
    ) INTO result FROM scan_reports;
    RETURN COALESCE(result, '{"total_scans":0,"total_vulns":0,"critical_count":0,"high_count":0,"avg_risk_score":0,"active_users":0,"by_type":[],"recent_scores":[]}'::json);
END;
$$;

-- System stats for admin hub
CREATE OR REPLACE FUNCTION get_system_stats()
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    RETURN json_build_object(
        'total_users',    (SELECT COUNT(*)::int FROM users),
        'active_users',   (SELECT COUNT(*)::int FROM users WHERE is_active = true),
        'total_scans',    (SELECT COUNT(*)::int FROM scan_reports),
        'today_scans',    (SELECT COUNT(*)::int FROM scan_reports WHERE stored_at >= CURRENT_DATE),
        'total_vulns',    (SELECT COALESCE(SUM(vuln_count),0)::int FROM scan_reports),
        'critical_vulns', (SELECT COALESCE(SUM(critical_count),0)::int FROM scan_reports),
        'failed_logins',  (SELECT COUNT(*)::int FROM audit_log WHERE action='login' AND status='failure'),
        'recent_events',  (
            SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (
                SELECT timestamp, username, action, category, status, ip_address, details
                FROM audit_log ORDER BY timestamp DESC LIMIT 10
            ) t
        ),
        'top_scanners', (
            SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (
                SELECT username, COUNT(*) AS cnt FROM scan_reports
                GROUP BY username ORDER BY cnt DESC LIMIT 5
            ) t
        ),
        'users_list', (
            SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (
                SELECT id, username, role, is_active, last_login, login_count
                FROM users ORDER BY id
            ) t
        )
    );
END;
$$;

-- Audit stats
CREATE OR REPLACE FUNCTION get_audit_stats()
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    RETURN json_build_object(
        'total_events',  (SELECT COUNT(*)::int FROM audit_log),
        'failed_events', (SELECT COUNT(*)::int FROM audit_log WHERE status='failure'),
        'by_category', (
            SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (
                SELECT category, COUNT(*) AS cnt FROM audit_log
                GROUP BY category ORDER BY cnt DESC
            ) t
        ),
        'recent_logins', (
            SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (
                SELECT username, ip_address, status, timestamp
                FROM audit_log WHERE category='auth' AND action='login'
                ORDER BY timestamp DESC LIMIT 10
            ) t
        )
    );
END;
$$;

-- Top vulnerabilities
CREATE OR REPLACE FUNCTION get_top_vulnerabilities(p_limit INT DEFAULT 10)
RETURNS JSON LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    RETURN (
        SELECT COALESCE(json_agg(row_to_json(t)), '[]'::json) FROM (
            SELECT check_name, severity, COUNT(*) AS count
            FROM scan_vulnerabilities
            GROUP BY check_name, severity
            ORDER BY count DESC
            LIMIT p_limit
        ) t
    );
END;
$$;

-- ════════════════════════════════════════════════════════════════════
--  Row Level Security (RLS) — enable for production
--  Uncomment when using anon key from frontend
-- ════════════════════════════════════════════════════════════════════
-- ALTER TABLE users               ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE scan_reports        ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE scan_vulnerabilities ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE audit_log           ENABLE ROW LEVEL SECURITY;
-- NOTE: Backend uses service_role key — RLS is bypassed automatically.
