-- CyBrain v4 schema migration (SQLite)
-- Adds account lockout columns and normalized vulnerabilities table

ALTER TABLE users ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until TEXT;

CREATE TABLE IF NOT EXISTS scan_vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id   INTEGER NOT NULL,
    check_name  TEXT    NOT NULL,
    severity    TEXT    NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    title       TEXT    NOT NULL,
    description TEXT,
    evidence    TEXT,
    remediation TEXT,
    line_number INTEGER NOT NULL DEFAULT 0,
    cve_ids     TEXT    NOT NULL DEFAULT '[]',
    is_fixed    INTEGER NOT NULL DEFAULT 0,
    fixed_at    TEXT,
    found_at    TEXT    NOT NULL,
    FOREIGN KEY (report_id) REFERENCES scan_reports(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_vulns_report
    ON scan_vulnerabilities(report_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity
    ON scan_vulnerabilities(severity, report_id);
CREATE INDEX IF NOT EXISTS idx_vulns_check
    ON scan_vulnerabilities(check_name);
