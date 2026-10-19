-- Projects table
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    repo_url TEXT,
    default_branch TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scans table
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    commit_sha TEXT,
    score INTEGER,
    risk_band TEXT,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id)
);

-- Findings table
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    file TEXT NOT NULL,
    line INTEGER,
    rule_id TEXT,
    category TEXT,
    severity TEXT,
    confidence REAL DEFAULT 1.0,
    exploitability INTEGER DEFAULT 5,
    exposure INTEGER DEFAULT 3,
    remediation_effort INTEGER DEFAULT 3,
    status TEXT DEFAULT 'open',
    snippet TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

-- AI analyses table
CREATE TABLE IF NOT EXISTS ai_analyses (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    is_likely_real BOOLEAN,
    confidence REAL,
    explanation TEXT,
    impact TEXT,
    recommended_fix TEXT,
    secure_code TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

-- Score history table
CREATE TABLE IF NOT EXISTS score_history (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    score INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id),
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_ai_analyses_finding ON ai_analyses(finding_id);
CREATE INDEX IF NOT EXISTS idx_score_history_project ON score_history(project_id);
